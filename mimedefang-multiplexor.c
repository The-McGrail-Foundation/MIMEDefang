/***********************************************************************
*
* mimedefang-multiplexor.c
*
* Main program which manages a pool of e-mail scanning processes.
*
* Copyright (C) 2001-2005 Roaring Penguin Software Inc.
* http://www.roaringpenguin.com
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#include "config.h"
#include "event_tcp.h"
#include "mimedefang.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#include <inttypes.h>
#define BIG_INT int64_t
#define BIG_INT_FMT PRIi64
#elif HAVE_LONG_LONG_INT
#define BIG_INT long long
#define BIG_INT_FMT "lld"
#else
#define BIG_INT long
#define BIG_INT_FMT "ld"
#endif

#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdarg.h>
#include <pwd.h>

#ifdef HAVE_SETRLIMIT
#include <sys/resource.h>
static void limit_mem_usage(unsigned long rss, unsigned long as);
#endif

static char *pidfile = NULL;
static char *lockfile = NULL;

/* Number of file descriptors to close when forking */
#define CLOSEFDS 256

/* Weird case, but hey... */
#if defined(HAVE_WAIT3) && !defined(HAVE_SETRLIMIT)
#include <sys/resource.h>
#endif

#define STR(x) STR2(x)
#define STR2(x) #x
#define MAX_CMD_LEN 4096	/* Maximum length of command from mimedefang */
#define MAX_DIR_LEN  511        /* Maximum length of working directory */
#define MAX_QID_LEN  31         /* Maximum length of a Sendmail queue-id */
#define MAX_STATUS_LEN  64      /* Maximum length of status tag */
#define MAX_UNPRIV_CONNS 20     /* Maximum number of simultaneous unprivileged connections */
#define MAX_DOMAIN_LEN 128      /* Maximum length of a domain name for tracking per-domain recipok workers */
#define DOLOG Settings.doSyslog

#define WORKERNO(s) ((int) ((s) - AllWorkers))

/* A worker can be in one of four states:
   Stopped -- Worker has no associated Perl process
   Idle    -- Worker has an associated process, but is not doing work
   Busy    -- Worker is processing a command
   Killed  -- Worker has been killed, but we're waiting for it to exit */

#define STATE_STOPPED    0
#define STATE_IDLE       1
#define STATE_BUSY       2
#define STATE_KILLED     3
#define NUM_WORKER_STATES 4
/* Structure of a worker process */
typedef struct Worker_t {
    struct Worker_t *next;	/* Link in free/busy list                    */
    EventSelector *es;		/* Event selector                            */
    pid_t pid;			/* Process ID of worker process              */
    int numRequests;		/* Number of requests handled by worker      */
    int numScans;               /* Number of messages scanned                */
    time_t idleTime;		/* Time when worker became idle              */
    time_t activationTime;      /* Time when worker was activated            */
    time_t firstReqTime;        /* Time when worker received its first job   */
    time_t lastStateChange;     /* Time when worker last changed state       */
    unsigned int activated;     /* Activation order                          */
    int workerStdin;		/* Worker's stdin descriptor                 */
    int workerStdout;		/* Worker's stdout descriptor                */
    int workerStderr;		/* Worker's stderr descriptor                */
    int workerStatusFD;		/* File descriptor for worker status reports */
    int clientFD;		/* Client file descriptor                    */
    int oom;			/* Did worker run out of memory?             */
    EventTcpState *event;	/* Pending event handler                     */
    EventHandler *errHandler;	/* Read handler for stderr                   */
    EventHandler *statusHandler; /* Read handler for status descriptor       */
    EventHandler *termHandler;  /* Timer after which we send SIGTERM         */
    char workdir[MAX_DIR_LEN+1]; /* Working directory for current scan       */
    char qid[MAX_QID_LEN+1];    /* Current Sendmail queue ID                 */
    char status_tag[MAX_STATUS_LEN]; /* Status tag                           */
    char domain[MAX_DOMAIN_LEN]; /* Current domain for recipok               */
    int generation;		/* Worker's generation                       */
    int state;			/* Worker's state                            */
    unsigned int histo;         /* Kind of double-duty as histogram value    */
    int tick_no;                /* Which tick are we handling?               */
    struct timeval start_cmd;   /* Time when current command started         */
    int cmd;                    /* Which of the 4 commands with history?     */
    int last_cmd;               /* Last command executed                     */
} Worker;

/* A queued request */
typedef struct Request_t {
    struct Request_t *next;     /* Next request in linked list               */
    EventSelector *es;		/* Event selector                            */
    EventHandler *timeoutHandler; /* Time out if we're queued too long       */
    int fd;                     /* File descriptor for client communication  */
    char *cmd;                  /* Command to send to worker                 */
} Request;

#define MAX_QUEUE_SIZE 128      /* Hard-coded limit                          */
Request RequestQueue[MAX_QUEUE_SIZE];
int NumQueuedRequests = 0;
Request *RequestHead;
Request *RequestTail;

Worker *AllWorkers;		/* Array of all workers                      */
Worker *Workers[NUM_WORKER_STATES]; /* Lists of workers in each state           */
int WorkerCount[NUM_WORKER_STATES]; /* Count of workers in each state          */
int Generation = 0;             /* Current generation                       */
int NumMsgsProcessed = 0;	/* Number of messages processed since last
				   "msgs" query */
unsigned int Activations = 0;	/* Incremented when a worker is activated    */
static int Old_NumFreeWorkers = -1;
int NumUnprivConnections = 0;

static pid_t ParentPid = (pid_t) -1;

static char **Env;

struct Settings_t {
    int minWorkers;		/* Minimum number of workers to keep running */
    int maxWorkers;		/* Maximum possible number of workers        */
    int maxRecipokPerDomain;    /* Maximum workers doing recipok for a given domain */
    int maxRequests;		/* Maximum number of requests per worker     */
    int maxLifetime;            /* Maximum lifetime of a worker in seconds.  */
    int maxIdleTime;		/* Excess workers should be killed after time */
    int busyTimeout;		/* Timeout after which we kill scanner      */
    int clientTimeout;		/* Timeout for client request/reply         */
    int slewTime;		/* Time to wait between workers' activation  */
    int waitTime;               /* Minimum time to wait between activations */
    int doSyslog;		/* If true, log various things with syslog  */
    char const *sockName;	/* Socket name for talking to mimedefang    */
    char const *progPath;	/* Program to execute for filter            */
    char const *statsFile;	/* File name for logging statistics         */
    char const *subFilter;      /* Sub-filter to pass to filter             */
    char const *unprivSockName; /* Socket for unprivileged commands         */
    char const *spoolDir;       /* Spool directory to chdir into            */
    FILE *statsFP;		/* File pointer for stats file              */
    int statsToSyslog;		/* If true, log stats using syslog          */
    int flushStats;             /* If non-zero, flush stats file after write*/
    unsigned long maxRSS;	/* Maximum RSS for workers (if supported)    */
    unsigned long maxAS;        /* Maximum address space for workers         */
    int logStatusInterval;      /* How often to log status to syslog        */
    char const *mapSock;        /* Socket for Sendmail TCP map requests     */
    int requestQueueSize;
    int requestQueueTimeout;
    int listenBacklog;		/* Listen backlog                           */
    int useEmbeddedPerl;	/* Use embedded Perl interpreter            */
    char const *notifySock;     /* Socket for notifications                 */
    int tick_interval;		/* Do "tick" request every tick_interval s  */
    int num_ticks;              /* How many tick types to cycle through     */
    char const *syslog_label;   /* Syslog label                             */
    int wantStatusReports;      /* Do we want status reports from workers?   */
    int debugWorkerScheduling;   /* Log details about worker scheduling       */
} Settings;

/* Structure for keeping statistics on number of messages processed in
   last 10 minutes */
#define NO_CMD      -2
#define OTHER_CMD   -1
#define MIN_CMD      0
#define SCAN_CMD     0
#define RELAYOK_CMD  1
#define SENDEROK_CMD 2
#define RECIPOK_CMD  3
#define MAX_CMD      3
#define NUM_CMDS     (MAX_CMD+1)

static char *CmdName[] = {
    "scan",
    "relayok",
    "senderok",
    "recipok"
};

/* Not real commands */

#define HISTORY_SECONDS (10*60)
#define HISTORY_HOURS   24
typedef struct {
    time_t first;       /* Time at which first entry was made */
    time_t last;        /* Time at which last entry was made */
    int elapsed;	/* Seconds or hours since epoch for this bucket */
    int count;		/* Number of messages processed */
    int workers;		/* TOTAL number of workers (active workers * count) */
    int ms;             /* TOTAL scan time in milliseconds */
    int activated;      /* Number of workers activated */
    int reaped;         /* Number of workers reaped */
} HistoryBucket;

static HistoryBucket history[NUM_CMDS][HISTORY_SECONDS];
static HistoryBucket hourly_history[NUM_CMDS][HISTORY_HOURS];

/* Pipe written on reception of SIGCHLD */
static int Pipe[2] = {-1, -1};

#ifndef HAVE_SIG_ATOMIC_T
#define sig_atomic_t int
#endif

static volatile sig_atomic_t ReapPending = 0;
static volatile sig_atomic_t HupPending = 0;
static volatile sig_atomic_t IntPending = 0;
static volatile sig_atomic_t CharPending = 0;

static int DebugEvents = 0;
static time_t LastWorkerActivation = (time_t) 0;
static time_t TimeOfProgramStart = (time_t) 0;

extern int drop_privs(char const *user, uid_t uid, gid_t gid);
extern int find_syslog_facility(char const *facility_name);

/* Prototypes */
#ifdef HAVE_WAIT3
static void log_worker_resource_usage(Worker *s, struct rusage *usage);
#endif

extern int make_notifier_socket(EventSelector *es, char const *name);
extern void notify_listeners(EventSelector *es, char const *msg);
extern void notify_worker_status(EventSelector *es, int workerno,
				char const *status);
extern void notify_worker_state_change(EventSelector *es,
				      int workerno,
				      char const *old_state,
				      char const *new_state);

static Worker *findFreeWorker(int cmdno);
static void shutDescriptors(Worker *s);
static void reapTerminatedWorkers(int killed);
static Worker *findWorkerByPid(pid_t pid);

static int update_worker_status(Worker *s, char const *buf);
static void set_worker_status_from_command(Worker *s, char const *buf);
static pid_t activateWorker(Worker *s, char const *reason);
static void killWorker(Worker *s, char const *reason);
static void terminateWorker(EventSelector *es, int fd, unsigned int flags,
			   void *data);
static void nukeWorker(EventSelector *es, int fd, unsigned int flags,
		      void *data);

/* List-management functions */
static void unlinkFromList(Worker *s);
static void putOnList(Worker *s, int state);

static void handleAccept(EventSelector *es, int fd);
static void handleUnprivAccept(EventSelector *es, int fd);
static void handleCommand(EventSelector *es, int fd,
			  char *buf, int len, int flag, void *data);
static void handleWorkerReceivedCommand(EventSelector *es, int fd,
				       char *buf, int len, int flag,
				       void *data);
static void handleWorkerReceivedTick(EventSelector *es, int fd,
				    char *buf, int len, int flag,
				    void *data);
static void handleWorkerReceivedAnswer(EventSelector *es, int fd,
				      char *buf, int len, int flag,
				      void *data);
static void handleWorkerReceivedAnswerFromTick(EventSelector *es, int fd,
					      char *buf, int len, int flag,
					      void *data);
static void doScan(EventSelector *es, int fd, char *cmd);
static void doWorkerInfo(EventSelector *es, int fd, char *cmd);
static void doScanAux(EventSelector *es, int fd, char *cmd, int queueable);
static void doStatus(EventSelector *es, int fd);
static void doHelp(EventSelector *es, int fd, int unpriv);
static void doWorkerReport(EventSelector *es, int fd, int only_busy);
static void doLoad(EventSelector *es, int fd, int cmd);
static void doLoad1(EventSelector *es, int fd, int back);
static void doHourlyLoad(EventSelector *es, int fd, int cmd);
static void doHistogram(EventSelector *es, int fd);

static void doWorkerCommand(EventSelector *es, int fd, char *cmd);
static void doWorkerCommandAux(EventSelector *es, int fd, char *cmd, int queueable);
static void checkWorkerForExpiry(Worker *s);
static void handlePipe(EventSelector *es,
		       int fd, unsigned int flags, void *data);
static void handleWorkerStderr(EventSelector *es,
			      int fd,
			      unsigned int flags,
			      void *data);
static void handleWorkerStatusFD(EventSelector *es,
				int fd,
				unsigned int flags,
				void *data);
static void childHandler(int sig);
static void hupHandler(int sig);
static void intHandler(int sig);
static void sigterm(int sig);
static void newGeneration(void);

static void handleIdleTimeout(EventSelector *es, int fd, unsigned int flags,
			      void *data);
static void doStatusLog(EventSelector *es, int fd, unsigned int flags,
			void *data);

static void logWorkerReaped(Worker *s, int status);
static int queue_request(EventSelector *es, int fd, char *cmd);
static int handle_queued_request(void);

static void handleRequestQueueTimeout(EventSelector *es, int fd,
				      unsigned int flags, void *data);
static void statsReopenFile(void);
static void statsLog(char const *event, int workerno, char const *fmt, ...);
static void bringWorkersUpToMin(EventSelector *es, int fd, unsigned int flags,
			       void *data);
static void scheduleBringWorkersUpToMin(EventSelector *es);
static int minScheduled = 0;
static void schedule_tick(EventSelector *es, int tick_no);

static void handleMapAccept(EventSelector *es, int fd);

static void init_history(void);
static HistoryBucket *get_history_bucket(int cmd);
static HistoryBucket *get_hourly_history_bucket(int cmd);
static int get_history_totals(int cmd, time_t now, int back, int *total, int *workers, BIG_INT *ms, int *activated, int *reaped);
static int get_hourly_history_totals(int cmd, time_t now, int hours, int *total, int *workers, BIG_INT *ms, int *secs);

#define NUM_FREE_WORKERS    (WorkerCount[STATE_IDLE] + WorkerCount[STATE_STOPPED])
#define NUM_RUNNING_WORKERS (WorkerCount[STATE_IDLE] + WorkerCount[STATE_BUSY] + WorkerCount[STATE_KILLED])
#define REPORT_FAILURE(msg) do { if (kidpipe[1] >= 0) { write(kidpipe[1], "E" msg, strlen(msg)+1); } else { fprintf(stderr, "%s\n", msg); } } while(0)

/**********************************************************************
* %FUNCTION: state_name
* %ARGUMENTS:
*  state -- a state number
* %RETURNS:
*  A string representing the name of the state
***********************************************************************/
static char const *
state_name(int state)
{
    switch(state) {
    case STATE_STOPPED: return "Stopped";
    case STATE_IDLE:    return "Idle";
    case STATE_BUSY:    return "Busy";
    case STATE_KILLED:  return "Killed";
    }
    return "Unknown";
}

/**********************************************************************
* %FUNCTION: state_name_lc
* %ARGUMENTS:
*  state -- a state number
* %RETURNS:
*  A string representing the name of the state in all lower-case
***********************************************************************/
static char const *
state_name_lc(int state)
{
    switch(state) {
    case STATE_STOPPED: return "stopped";
    case STATE_IDLE:    return "idle";
    case STATE_BUSY:    return "busy";
    case STATE_KILLED:  return "killed";
    }
    return "unknown";
}

/**********************************************************************
* %FUNCTION: reply_to_mimedefang_with_len
* %ARGUMENTS:
*  es -- event selector
*  fd -- file descriptor
*  msg -- message to send back
*  len -- length of message
* %RETURNS:
*  The event associated with the reply, or NULL.
* %DESCRIPTION:
*  Sends a final message back to mimedefang.  Closes fd after message has
*  been sent.
***********************************************************************/
static EventTcpState *
reply_to_mimedefang_with_len(EventSelector *es,
			     int fd,
			     char const *msg,
			     int len)
{
    EventTcpState *e;

    if (len == 0) {
	/* Nothing to say. */
	close(fd);
	return NULL;
    }
    e = EventTcp_WriteBuf(es, fd, msg, len, NULL,
			  Settings.clientTimeout, NULL);
    if (!e) {
	if (DOLOG) {
	    syslog(LOG_ERR, "reply_to_mimedefang: EventTcp_WriteBuf failed: %m");
	}
	close(fd);
    }
    return e;
}

/**********************************************************************
* %FUNCTION: reply_to_mimedefang
* %ARGUMENTS:
*  es -- event selector
*  fd -- file descriptor
*  msg -- message to send back
* %RETURNS:
*  The event associated with the reply, or NULL.
* %DESCRIPTION:
*  Sends a final message back to mimedefang.
***********************************************************************/
EventTcpState *
reply_to_mimedefang(EventSelector *es,
		    int fd,
		    char const *msg)
{
    return reply_to_mimedefang_with_len(es, fd, msg, strlen(msg));
}

/**********************************************************************
* %FUNCTION: findWorkerByPid
* %ARGUMENTS:
*  pid -- Process-ID we're looking for
* %RETURNS:
*  The worker with given pid, or NULL if not found
* %DESCRIPTION:
*  Searches the killed, idle and busy lists for specified worker.
***********************************************************************/
static Worker *
findWorkerByPid(pid_t pid)
{
    Worker *s;

    /* Most likely to be on killed list, so search there first */
    s = Workers[STATE_KILLED];
    while(s) {
	if (s->pid == pid) return s;
	s = s->next;
    }

    s = Workers[STATE_IDLE];
    while(s) {
	if (s->pid == pid) return s;
	s = s->next;
    }

    s = Workers[STATE_BUSY];
    while(s) {
	if (s->pid == pid) return s;
	s = s->next;
    }

    return NULL;
}

/**********************************************************************
* %FUNCTION: usage
* %ARGUMENTS:
*  None
* %RETURNS:
*  Nothing (exits)
* %DESCRIPTION:
*  Prints usage information
***********************************************************************/
static void
usage(void)
{
    fprintf(stderr, "mimedefang-multiplexor version %s\n", VERSION);
    fprintf(stderr, "Usage: mimedefang-multiplexor [options]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h                -- Print usage info and exit\n");
    fprintf(stderr, "  -v                -- Print version and exit\n");
    fprintf(stderr, "  -t filename       -- Log statistics to filename\n");
    fprintf(stderr, "  -p filename       -- Write process-ID in filename\n");
    fprintf(stderr, "  -o file           -- Use specified file as a lock file\n");
    fprintf(stderr, "  -T                -- Log statistics to syslog\n");
    fprintf(stderr, "  -u                -- Flush stats file after each write\n");
    fprintf(stderr, "  -Z                -- Accept and process status updates from busy workers\n");
    fprintf(stderr, "  -U username       -- Run as username, not root\n");
    fprintf(stderr, "  -m minWorkers      -- Minimum number of workers\n");
    fprintf(stderr, "  -x maxWorkers      -- Maximum number of workers\n");
    fprintf(stderr, "  -y recipokPerDom  -- Maximum concurrent recipoks per domain\n");
    fprintf(stderr, "  -r maxRequests    -- Maximum number of requests per worker\n");
    fprintf(stderr, "  -V maxLifetime    -- Maximum lifetime of a worker in seconds\n");
    fprintf(stderr, "  -i idleTime       -- Idle time (seconds) for killing excess workers\n");
    fprintf(stderr, "  -b busyTime       -- Busy time (seconds) for killing hung workers\n");
    fprintf(stderr, "  -c cmdTime        -- Request/reply transmission timeout (seconds)\n");
    fprintf(stderr, "  -w waitTime       -- How long to wait between worker activations (seconds)\n");
    fprintf(stderr, "  -W waitTime       -- Absolute minimum to wait between worker activations\n");
    fprintf(stderr, "  -z dir            -- Spool directory\n");
    fprintf(stderr, "  -s sock           -- UNIX-domain socket for communication\n");
    fprintf(stderr, "  -a u_sock         -- Socket for unprivileged communication\n");
    fprintf(stderr, "  -f /dir/filter    -- Specify full path of filter program\n");
    fprintf(stderr, "  -d                -- Debug events in /var/log/mdefang-event-debug.log\n");
    fprintf(stderr, "  -l                -- Log events with syslog\n");
#ifdef HAVE_SETRLIMIT
    fprintf(stderr, "  -R size           -- Limit RSS to size kB (if supported on your OS)\n");
    fprintf(stderr, "  -M size           -- Limit memory address space to size kB\n");
#endif
    fprintf(stderr, "  -L interval       -- Log worker status every interval seconds\n");
    fprintf(stderr, "  -S facility       -- Set syslog(3) facility\n");
    fprintf(stderr, "  -N sock           -- Listen for Sendmail map requests on sock\n");
    fprintf(stderr, "  -O sock           -- Listen for notification requests on sock\n");
    fprintf(stderr, "  -q size           -- Size of request queue (default 0)\n");
    fprintf(stderr, "  -Q timeout        -- Timeout for queued requests\n");
    fprintf(stderr, "  -I backlog        -- 'backlog' argument for listen on multiplexor socket\n");
    fprintf(stderr, "  -D                -- Do not become a daemon (stay in foreground)\n");
    fprintf(stderr, "  -X interval       -- Run a 'tick' request every interval seconds\n");
    fprintf(stderr, "  -P n              -- Run 'n' parallel tick requests\n");
    fprintf(stderr, "  -Y label          -- Set syslog label to 'label'\n");
    fprintf(stderr, "  -G                -- Make sockets group-writable\n");
#ifdef EMBED_PERL
    fprintf(stderr, "  -E                -- Use embedded Perl interpreter\n");
#endif
    exit(EXIT_FAILURE);
}

static int
set_sigchld_handler(void)
{
    struct sigaction act;

    /* Set signal handler for SIGCHLD */
    act.sa_handler = childHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    return sigaction(SIGCHLD, &act, NULL);
}

/**********************************************************************
* %FUNCTION: main
* %ARGUMENTS:
*  argc, argv -- usual suspects
* %RETURNS:
* Nothing -- runs in an infinite loop
* %DESCRIPTION:
*  Main program
***********************************************************************/
int
main(int argc, char *argv[], char **env)
{
    int i;
    int sock, unpriv_sock;
    int c;
    int n;
    int pidfile_fd = -1;
    int lockfile_fd = -1;
    char *user = NULL;
    char *options;
    int facility = LOG_MAIL;
    int kidpipe[2] = {-1, -1};
    char kidmsg[256];

    time_t now;

    mode_t socket_umask = 077;
    mode_t file_umask = 077;

    EventSelector *es;
    struct sigaction act;
    struct timeval t;
    struct passwd *pw = NULL;
    int nodaemon = 0;

    /* Record program start time */
    TimeOfProgramStart = time(NULL);

    Env = env;

    /* Paranoia time */
    umask(077);

    /* Paranoia time II */
    if (getuid() != geteuid()) {
	fprintf(stderr, "ERROR: %s is NOT intended to run suid! Exiting.\n",
		argv[0]);
	exit(EXIT_FAILURE);
    }

    if (getgid() != getegid()) {
	fprintf(stderr, "ERROR: %s is NOT intended to run sgid! Exiting.\n",
		argv[0]);
	exit(EXIT_FAILURE);
    }

    Settings.minWorkers     = 0;
    Settings.maxWorkers     = 2;
    Settings.maxRecipokPerDomain = 0;
    Settings.maxRequests   = 500;
    Settings.maxLifetime   = 0; /* Unlimited */
    Settings.maxIdleTime   = 300;
    Settings.busyTimeout   = 120;
    Settings.slewTime      = 3;
    Settings.waitTime      = 0;
    Settings.clientTimeout = 10;
    Settings.doSyslog      = 0;
    Settings.spoolDir      = NULL;
    Settings.sockName      = NULL;
    Settings.unprivSockName = NULL;
    Settings.progPath      = MIMEDEFANG_PL;
    Settings.subFilter     = NULL;
    Settings.statsFile     = NULL;
    Settings.statsFP       = NULL;
    Settings.flushStats    = 0;
    Settings.statsToSyslog = 0;
    Settings.maxRSS = 0;
    Settings.maxAS = 0;
    Settings.logStatusInterval = 0;
    Settings.requestQueueSize = 0;
    Settings.requestQueueTimeout = 30;
    Settings.listenBacklog = -1;
    Settings.useEmbeddedPerl = 0;
    Settings.notifySock = NULL;
    Settings.tick_interval = 0;
    Settings.num_ticks = 1;
    Settings.mapSock       = NULL;
    Settings.wantStatusReports = 0;
    Settings.debugWorkerScheduling = 0;

#ifndef HAVE_SETRLIMIT
    options = "GAa:Tt:um:x:y:r:i:b:c:s:hdlf:p:o:w:F:W:U:S:q:Q:I:DEO:X:Y:N:vZP:z:V:";
#else
    options = "GAa:Tt:um:x:y:r:i:b:c:s:hdlf:p:o:w:F:W:U:S:q:Q:L:R:M:I:DEO:X:Y:N:vZP:z:V:";
#endif
    while((c = getopt(argc, argv, options)) != -1) {
	switch(c) {
	case 'G':
	    socket_umask = 007;
	    file_umask   = 027;
	    break;

	case 'A':
	    Settings.debugWorkerScheduling = 1;
	    break;
	case 'z':
	    Settings.spoolDir = strdup(optarg);
	    if (!Settings.spoolDir) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'Z':
	    Settings.wantStatusReports = 1;
	    break;
	case 'a':
	    Settings.unprivSockName = strdup(optarg);
	    if (!Settings.unprivSockName) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'v':
	    printf("mimedefang-multiplexor version %s\n", VERSION);
	    exit(EXIT_SUCCESS);

	case 'E':
	    #ifdef EMBED_PERL
	    Settings.useEmbeddedPerl = 1;
	    #else
	    fprintf(stderr, "mimedefang-multiplexor compiled without support for embedded perl.  Ignoring -E flag.\n");
	    #endif
	    break;
	case 'D':
	    nodaemon = 1;
	    break;
	case 'P':
	    if (sscanf(optarg, "%d", &n) != 1) usage();
	    if (n < 1) {
		n = 1;
	    } else if (n > 30) {
		n = 30;
	    }
	    Settings.num_ticks = n;
	    break;
	case 'I':
	    if (sscanf(optarg, "%d", &n) != 1) usage();
	    if (n < 5) {
		n = 5;
	    } else if (n > 200) {
		n = 200;
	    }
	    Settings.listenBacklog = n;
	    break;

	case 'q':
	    if (sscanf(optarg, "%d", &n) != 1) usage();
	    if (n <= 0) {
		n = 0;
	    } else if (n > MAX_QUEUE_SIZE) {
		fprintf(stderr, "%s: Request queue size %d too big (%d max)\n",
			argv[0], n, MAX_QUEUE_SIZE);
		exit(EXIT_FAILURE);
	    }
	    Settings.requestQueueSize = n;
	    break;

	case 'X':
	    if (sscanf(optarg, "%d", &n) != 1) usage();
	    if (n < 0) {
		n = 0;
	    }
	    Settings.tick_interval = n;
	    break;

	case 'Q':
	    if (sscanf(optarg, "%d", &n) != 1) usage();
	    if (n <= 1) {
		n = 1;
	    } else if (n > 600) {
		n = 600;
	    }
	    Settings.requestQueueTimeout = n;
	    break;

	case 'S':
	    facility = find_syslog_facility(optarg);
	    if (facility < 0) {
		fprintf(stderr, "%s: Unknown syslog facility %s\n",
			argv[0], optarg);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'L':
	    if (sscanf(optarg, "%d", &n) != 1) usage();
	    if (n <= 0) {
		n = 0;
	    } else if (n < 5) {
		n = 5;
	    }
	    Settings.logStatusInterval = n;
	    break;

	case 'R':
	case 'M':
	    if (sscanf(optarg, "%d", &n) != 1) usage();
	    if (c == 'R') {
		Settings.maxRSS = (unsigned long) n;
	    } else {
		Settings.maxAS = (unsigned long) n;
	    }
	    break;

	case 'Y':
	    Settings.syslog_label = strdup(optarg);
	    if (!Settings.syslog_label) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;

	case 'O':
	    Settings.notifySock = strdup(optarg);
	    if (!Settings.notifySock) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'N':
	    Settings.mapSock = strdup(optarg);
	    if (!Settings.mapSock) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'U':
	    /* User to run as */
	    if (user) {
		free(user);
	    }
	    user = strdup(optarg);
	    if (!user) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;

	case 'F':
	    /* Sub-filter */
	    if (Settings.subFilter) {
		free((void *) Settings.subFilter);
	    }
	    Settings.subFilter = strdup(optarg);
	    if (!Settings.subFilter) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;

	case 'W':
	    /* Absolute minimum to wait between each worker's start-up */
	    if (sscanf(optarg, "%d", &Settings.waitTime) != 1) usage();
	    if (Settings.waitTime < 0) {
		Settings.waitTime = 0;
	    }
	    break;

	case 'w':
	    /* How long to wait between each worker's start-up */
	    if (sscanf(optarg, "%d", &Settings.slewTime) != 1) usage();
	    if (Settings.slewTime < 1) {
		Settings.slewTime = 1;
	    }
	    break;

	case 'p':
	    /* Write our pid to this file */
	    if (pidfile != NULL) free(pidfile);

	    pidfile = strdup(optarg);
	    if (!pidfile) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'o':
	    /* Use this as our lock file */
	    if (lockfile != NULL) free(lockfile);

	    lockfile = strdup(optarg);
	    if (!lockfile) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'f':
	    /* Filter program */
	    if (optarg[0] != '/') {
		fprintf(stderr, "%s: -f: You must supply an absolute path for filter program\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    Settings.progPath = strdup(optarg);
	    if (!Settings.progPath) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'u':
	    Settings.flushStats = 1;
	    break;
	case 't':
	    Settings.statsFile = strdup(optarg);
	    if (!Settings.statsFile) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'T':
	    Settings.statsToSyslog = 1;
	    break;
	case 'l':
	    Settings.doSyslog = 1;
	    break;
	case 'd':
	    DebugEvents = 1;
	    break;
	case 'h':
	    usage();
	    break;
	case 'm':
	    if (sscanf(optarg, "%d", &Settings.minWorkers) != 1) usage();
	    if (Settings.minWorkers < 1) Settings.minWorkers = 1;
	    break;
	case 'x':
	    if (sscanf(optarg, "%d", &Settings.maxWorkers) != 1) usage();
	    break;
	case 'y':
	    if (sscanf(optarg, "%d", &Settings.maxRecipokPerDomain) != 1) usage();
	    break;
	case 'r':
	    if (sscanf(optarg, "%d", &Settings.maxRequests) != 1) usage();
	    if (Settings.maxRequests < 1) Settings.maxRequests = 1;
	    break;
	case 'V':
	    if (sscanf(optarg, "%d", &Settings.maxLifetime) != 1) usage();
	    if (Settings.maxLifetime <= 0) {
		Settings.maxLifetime = -1;
	    }
	    break;
	case 'i':
	    if (sscanf(optarg, "%d", &Settings.maxIdleTime) != 1) usage();
	    if (Settings.maxIdleTime < 10) Settings.maxIdleTime = 10;
	    break;
	case 'b':
	    if (sscanf(optarg, "%d", &Settings.busyTimeout) != 1) usage();
	    if (Settings.busyTimeout < 10) Settings.busyTimeout = 10;
	    break;
	case 'c':
	    if (sscanf(optarg, "%d", &Settings.clientTimeout) != 1) usage();
	    if (Settings.clientTimeout < 10) Settings.clientTimeout = 10;
	    break;
	case 's':
	    Settings.sockName = strdup(optarg);
	    if (!Settings.sockName) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	default:
	    fprintf(stderr, "\n");
	    usage();
	}
    }

    /* Set spooldir, if it's not set */
    if (!Settings.spoolDir) {
	Settings.spoolDir = SPOOLDIR;
    }

    /* Set sockName, if it's not set */
    if (!Settings.sockName) {
	Settings.sockName = malloc(strlen(Settings.spoolDir) + strlen("/mimedefang-multiplexor.sock") + 1);
	    if (!Settings.sockName) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    strcpy((char *) Settings.sockName, Settings.spoolDir);
	    strcat((char *) Settings.sockName, "/mimedefang-multiplexor.sock");
    }

    /* Open the pidfile as root.  We'll write the pid later on in the grandchild */
    if (pidfile) {
	pidfile_fd = open(pidfile, O_RDWR|O_CREAT, 0666);
	if (pidfile_fd < 0) {
	    syslog(LOG_ERR, "Could not open PID file %s: %m", pidfile);
	    exit(EXIT_FAILURE);
	}
	/* It needs to be world-readable */
	fchmod(pidfile_fd, 0644);
    }

    /* Drop privileges */
    if (user) {
	pw = getpwnam(user);
	if (!pw) {
	    fprintf(stderr, "%s: Unknown user '%s'\n", argv[0], user);
	    exit(EXIT_FAILURE);
	}
	if (drop_privs(user, pw->pw_uid, pw->pw_gid) < 0) {
	    exit(EXIT_FAILURE);
	}
	free(user);
    }

    /* Warn */
    if (!getuid() || !geteuid()) {
	fprintf(stderr,
		"ERROR: You must not run mimedefang-multiplexor as root.\n"
		"Use the -U option to set a non-root user.\n");
	exit(EXIT_FAILURE);
    }

    if (chdir(Settings.spoolDir) < 0) {
	fprintf(stderr, "%s: Unable to chdir(%s): %s\n",
		argv[0], Settings.spoolDir, strerror(errno));
	exit(EXIT_FAILURE);
    }

    /* Fix obvious stupidities */
    if (Settings.maxWorkers < 1) {
	Settings.maxWorkers = 1;
    }
    if (Settings.minWorkers < 1) {
	Settings.minWorkers = 1;
    }
    if (Settings.minWorkers > Settings.maxWorkers) {
	Settings.minWorkers = Settings.maxWorkers;
    }

    /* Make sure maxRecipokPerDomain is sane */
    if (Settings.maxRecipokPerDomain < 0) {
	Settings.maxRecipokPerDomain = 0;
    } else if (Settings.maxRecipokPerDomain >= Settings.maxWorkers) {
	Settings.maxRecipokPerDomain = 0;
    }

    /* Daemonize */
    if (!nodaemon) {
	/* Set up a pipe so child can report back when it's happy */
	if (pipe(kidpipe) < 0) {
	    perror("pipe");
	    exit(EXIT_FAILURE);
	}
	i = fork();
	if (i < 0) {
	    fprintf(stderr, "%s: fork() failed\n", argv[0]);
	    exit(EXIT_FAILURE);
	} else if (i != 0) {
	    /* parent */
	    /* Wait for a message from kid */
	    close(kidpipe[1]);
	    i = read(kidpipe[0], kidmsg, sizeof(kidmsg) - 1);
	    if (i < 0) {
		fprintf(stderr, "Error reading message from child: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	    }
	    /* Zero-terminate the string */
	    kidmsg[i] = 0;
	    if (i == 1 && kidmsg[0] == 'X') {
		/* Child indicated successful startup */
		exit(EXIT_SUCCESS);
	    }
	    if (i > 1 && kidmsg[0] == 'E') {
		/* Child indicated error */
		fprintf(stderr, "Error from child: %s\n", kidmsg+1);
		exit(EXIT_FAILURE);
	    }
	    /* Unknown status from child */
	    fprintf(stderr, "Unknown reply from child: %s\n", kidmsg);
	    exit(EXIT_FAILURE);
	}
	setsid();
	signal(SIGHUP, SIG_IGN);
	i = fork();
	if (i < 0) {
	    fprintf(stderr, "%s: fork() failed\n", argv[0]);
	    exit(EXIT_FAILURE);
	} else if (i != 0) {
	    exit(EXIT_SUCCESS);
	}

    }

    /* Do the locking */
    if (pidfile || lockfile) {
	if ( (lockfile_fd = write_and_lock_pidfile(pidfile, &lockfile, pidfile_fd)) < 0) {
	    REPORT_FAILURE("Cannot lock lockfile: Is another copy running?");
	    exit(EXIT_FAILURE);
	}
	pidfile_fd = -1;
    }

    /* Initialize history buckets */
    init_history();

    /* Initialize queue */
    for (i=0; i<Settings.requestQueueSize; i++) {
	RequestQueue[i].next = NULL;
	RequestQueue[i].es   = NULL;
	RequestQueue[i].timeoutHandler = NULL;
	RequestQueue[i].fd   = -1;
	RequestQueue[i].cmd  = NULL;
    }
    NumQueuedRequests = 0;
    RequestHead = NULL;
    RequestTail = NULL;

    /* Allocate workers and place them on the free list */
    AllWorkers = calloc(Settings.maxWorkers, sizeof(Worker));

    if (!AllWorkers) {
	REPORT_FAILURE("Unable to allocate memory for workers");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    /* Make an event selector */
    es = Event_CreateSelector();
    if (!es) {
	REPORT_FAILURE("Could not create event selector");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    WorkerCount[STATE_STOPPED] = Settings.maxWorkers;
    WorkerCount[STATE_IDLE]    = 0;
    WorkerCount[STATE_BUSY]    = 0;
    WorkerCount[STATE_KILLED]  = 0;

    Workers[STATE_STOPPED] = &AllWorkers[0];
    Workers[STATE_IDLE]    = NULL;
    Workers[STATE_BUSY]    = NULL;
    Workers[STATE_KILLED]  = NULL;

    now = time(NULL);
    /* Set some fields in workers */
    for (i=0; i<Settings.maxWorkers; i++) {
	Worker *s = &AllWorkers[i];
	s->es = es;
	s->pid = (pid_t) -1;
	s->workerStdin = -1;
	s->workerStdout = -1;
	s->workerStderr = -1;
	s->workerStatusFD = -1;
	s->clientFD = -1;
	s->oom = 0;
	s->event = NULL;
	s->errHandler = NULL;
	s->statusHandler = NULL;
	s->termHandler = NULL;
	s->workdir[0] = 0;
	s->status_tag[0] = 0;
	s->domain[0] = 0;
	s->generation = Generation;
	s->state = STATE_STOPPED;
	s->activationTime = (time_t) -1;
	s->firstReqTime = (time_t) -1;
	s->lastStateChange = now;
	s->last_cmd = NO_CMD;
    }

    /* Set up the linked list */
    for (i=0; i<Settings.maxWorkers-1; i++) {
	AllWorkers[i].next = &AllWorkers[i+1];
    }
    AllWorkers[Settings.maxWorkers-1].next = NULL;

    /* Choose a sensible default for backlog if it hasn't been set */
    if (Settings.listenBacklog < 0) {
	Settings.listenBacklog = Settings.maxWorkers / 4;
	if (Settings.listenBacklog < 5) Settings.listenBacklog = 5;
	if (Settings.listenBacklog > 200) Settings.listenBacklog = 200;
    }

    umask(socket_umask);
    sock = make_listening_socket(Settings.sockName, Settings.listenBacklog, 1);
    umask(file_umask);

    if (sock < 0) {
	if (sock == -2) {
	    REPORT_FAILURE("Argument to -s option must be a UNIX-domain socket, not a TCP socket.");
	} else {
	    REPORT_FAILURE("Unable to create listening socket.");
	}
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }
    if(set_cloexec(sock) < 0) {
	REPORT_FAILURE("Could not set FD_CLOEXEC option on socket");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    /* Set up an accept loop */
    if (!EventTcp_CreateAcceptor(es, sock, handleAccept)) {
	REPORT_FAILURE("Could not make accept() handler");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    unpriv_sock = -1;
    if (Settings.unprivSockName) {
	/* Relax the umask for the unprivileged socket */
	umask(000);
	unpriv_sock = make_listening_socket(Settings.unprivSockName,
						Settings.listenBacklog, 0);
	umask(file_umask);
	if (unpriv_sock < 0) {
	    REPORT_FAILURE("Unable to create unprivileged listening socket");
	    if (pidfile) unlink(pidfile);
	    if (lockfile) unlink(lockfile);
	    exit(EXIT_FAILURE);
	}
	if(set_cloexec(unpriv_sock) < 0) {
	    REPORT_FAILURE("Could not set FD_CLOEXEC option on socket");
	    if (pidfile) unlink(pidfile);
	    if (lockfile) unlink(lockfile);
	    exit(EXIT_FAILURE);
	}
	if (!EventTcp_CreateAcceptor(es, unpriv_sock, handleUnprivAccept)) {
	    REPORT_FAILURE("Could not make accept() handler");
	    if (pidfile) unlink(pidfile);
	    if (lockfile) unlink(lockfile);
	    exit(EXIT_FAILURE);
	}
    }

    /* Ignore sigpipe */
    signal(SIGPIPE, SIG_IGN);

    /* Set up pipe for signal handler for worker termination notification*/
    if (pipe(Pipe) < 0) {
	REPORT_FAILURE("pipe() call failed");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    if((set_cloexec(Pipe[0]) < 0) || (set_cloexec(Pipe[1]) < 0)) {
        REPORT_FAILURE("Could not set FD_CLOEXEC option on pipe");
        if (pidfile) unlink(pidfile);
        if (lockfile) unlink(lockfile);
        exit(EXIT_FAILURE);
    }

    /* Create event handler for pipe */
    if (!Event_AddHandler(es, Pipe[0],
			  EVENT_FLAG_READABLE, handlePipe, NULL)) {
	REPORT_FAILURE("Could not make pipe handler");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    /* Close files */
    for (i=0; i<CLOSEFDS; i++) {
	/* Don't close stdin/stdout/stderr if we are not a daemon */
	if (nodaemon && i < 3) {
	    continue;
	}
	if (i == kidpipe[0] || i == kidpipe[1] || i == lockfile_fd || i == unpriv_sock || i == sock || i == Pipe[0] || i == Pipe[1]) continue;
	(void) close(i);
    }

    /* Direct stdin/stdout/stderr to /dev/null if we are a daemon */
    if (!nodaemon) {
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
    }

    /* Syslog if required */
    if (Settings.syslog_label) {
	openlog(Settings.syslog_label, LOG_PID|LOG_NDELAY, facility);
    } else {
	openlog("mimedefang-multiplexor", LOG_PID|LOG_NDELAY, facility);
    }

    /* Keep track of our pid */
    ParentPid = getpid();

    /* Set up SIGHUP handler */
    act.sa_handler = hupHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &act, NULL) < 0) {
	REPORT_FAILURE("sigaction failed - exiting.");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    /* Set up SIGINT handler */
    act.sa_handler = intHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &act, NULL) < 0) {
	REPORT_FAILURE("sigaction failed - exiting.");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    if (DOLOG) {
	syslog(LOG_INFO, "started; minWorkers=%d, maxWorkers=%d, maxRequests=%d, maxLifetime=%d, maxIdleTime=%d, busyTimeout=%d, clientTimeout=%d",
	       Settings.minWorkers,
	       Settings.maxWorkers,
	       Settings.maxRequests,
	       Settings.maxLifetime,
	       Settings.maxIdleTime,
	       Settings.busyTimeout,
	       Settings.clientTimeout);
    }

    /* Init Perl interpreter */
#ifdef EMBED_PERL
    if (Settings.useEmbeddedPerl) {
	init_embedded_interpreter(argc, argv, env);
	if (make_embedded_interpreter(Settings.progPath, Settings.subFilter,
				      Settings.wantStatusReports, Env) < 0) {
	    syslog(LOG_ERR, "Could not initialize embedded Perl interpreter -- falling back to old method.");
	    Settings.useEmbeddedPerl = 0;
	} else {
	    if (DOLOG) {
		syslog(LOG_INFO, "Initialized embedded Perl interpreter");
	    }
	}
    }
#endif

    /* Set signal handler for SIGCHLD */
    if (set_sigchld_handler() < 0) {
	REPORT_FAILURE("sigaction failed - exiting.");
#ifdef EMBED_PERL
	if (Settings.useEmbeddedPerl) {
            term_embedded_interpreter();
            deinit_embedded_interpreter();
        }
#endif
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    /* Open stats file */
    statsReopenFile();

    /* Kick off the starting of workers */
    bringWorkersUpToMin(es, 0, 0, NULL);

    /* Set up a timer handler to check for idle timeouts */
    t.tv_usec = 0;
    t.tv_sec = Settings.maxIdleTime;
    Event_AddTimerHandler(es, t, handleIdleTimeout, NULL);

    /* Set up a timer handler to log status, if desired */
    if (Settings.logStatusInterval) {
	t.tv_usec = 0;
	t.tv_sec = Settings.logStatusInterval;
	Event_AddTimerHandler(es, t, doStatusLog, NULL);
    }
    if (DebugEvents) {
	Event_EnableDebugging("/var/log/mdefang-event-debug.log");
    }

    /* Set signal handler for SIGTERM */
    signal(SIGTERM, sigterm);

    /* Do notify socket */
    if (Settings.notifySock) {
	umask(socket_umask);
	make_notifier_socket(es, Settings.notifySock);
	umask(file_umask);
    }

    if (Settings.mapSock) {
	umask(socket_umask);
	sock = make_listening_socket(Settings.mapSock, Settings.listenBacklog, 0);
	umask(file_umask);
	if (sock >= 0) {
	    if(set_cloexec(sock) < 0) {
		syslog(LOG_ERR, "Could not set FD_CLOEXEC option on socket");
		close(sock);
	    }
	    if (!EventTcp_CreateAcceptor(es, sock, handleMapAccept)) {
		syslog(LOG_ERR, "Could not listen for map requests: EventTcp_CreateAcceptor: %m");
		close(sock);
	    }
	}
    }

    /* Start the tick handler.  All ticks start off at the same time,
       but should soon get out of sync.
    */
    if (Settings.tick_interval > 0 && Settings.num_ticks > 0) {
	for (i=0; i<Settings.num_ticks; i++) {
	    schedule_tick(es, i);
	}
    }

    /* Tell the waiting parent that everything is fine */
    write(kidpipe[1], "X", 1);
    close(kidpipe[1]);

    /* And loop... */
    while(1) {
	if (Event_HandleEvent(es) < 0) {
	    syslog(LOG_CRIT, "Error in Event_HandleEvent: %m.  MULTIPLEXOR IS TERMINATING.");
	    sigterm(0);
	}
    }
}

/**********************************************************************
* %FUNCTION: handleWorkerStderr
* %ARGUMENTS:
*  es -- event selector
*  fd -- file descriptor ready for reading
*  flags -- flags from event-handling code
*  data -- pointer to worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a readable stderr descriptor.  Reads data; if we're logging,
*  sends it to syslog; otherwise, discards data.
***********************************************************************/
static void
handleWorkerStderr(EventSelector *es,
		  int fd,
		  unsigned int flags,
		  void *data)
{
    Worker *s = (Worker *) data;
    char buffer[64];
    int n;
    char const *qid;

    while ( (n=read(fd, buffer, sizeof(buffer)-1)) > 0) {
	buffer[n] = 0;
	if (buffer[n-1] == '\n') {
	    buffer[n-1] = 0;
	}
  if(s == NULL) {
    syslog(LOG_ERR, "no data available for current worker");
    return;
  }
	/* Heuristic... Perl spits this out, I think*/
	if (strstr(buffer, "Out of memory!")) {
	    s->oom = 1;
	}

	qid = s->qid;
	if (DOLOG) {
	    /* Split lines into separate syslog calls */
	    char *str, *nl;
	    str = buffer;
	    while ( (nl = strchr(str, '\n')) ) {
		*nl = 0;
		if (*str) {
		    if (qid && *qid) {
			syslog(LOG_INFO, "%s: Worker %d stderr: %s", qid, WORKERNO(s), str);
		    } else {
			syslog(LOG_INFO, "Worker %d stderr: %s", WORKERNO(s), str);
		    }
		}
		str = nl+1;
	    }
	    if (str && *str) {
		if (qid && *qid) {
		    syslog(LOG_INFO, "%s: Worker %d stderr: %s", qid, WORKERNO(s), str);
		} else {
		    syslog(LOG_INFO, "Worker %d stderr: %s", WORKERNO(s), str);
		}
	    }
	}
    }

    if (n == 0 || (n < 0 && errno != EAGAIN)) {
	/* EOF or error reading stderr -- close it and cancel handler */
	if (n < 0) {
	    if (DOLOG) {
	        qid = s->qid;
		if (qid && *qid) {
		    syslog(LOG_WARNING,
			   "%s: handleWorkerStderr: Error reading from worker %d's stderr: %m", s->qid, WORKERNO(s));
		} else {
		    syslog(LOG_WARNING,
			   "handleWorkerStderr: Error reading from worker %d's stderr: %m", WORKERNO(s));
		}
	    }
	}
  if(s) {
	  close(s->workerStderr);
	  Event_DelHandler(s->es, s->errHandler);
    s->errHandler = NULL;
    s->workerStderr = -1;
  }
    }
}

/**********************************************************************
* %FUNCTION: handleWorkerStatusFD
* %ARGUMENTS:
*  es -- event selector
*  fd -- file descriptor ready for reading
*  flags -- flags from event-handling code
*  data -- pointer to worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a readable status descriptor.  Reads data and sets
*  worker's "status tag"
***********************************************************************/
static void
handleWorkerStatusFD(EventSelector *es,
		    int fd,
		    unsigned int flags,
		    void *data)
{
    Worker *s = (Worker *) data;
    char buffer[64];
    int n;
    int changed = 0;
    char const *qid;

    while ( (n=read(fd, buffer, sizeof(buffer)-1)) > 0) {
	buffer[n] = 0;
	if (buffer[n-1] == '\n') {
	    buffer[n-1] = 0;
	}
	if (update_worker_status(s, buffer)) {
	    changed = 1;
	}
    }
    if (n == 0 || (n < 0 && errno != EAGAIN)) {
	/* EOF or error reading status FD -- close it and cancel handler */
	if (n < 0) {
	    if (DOLOG) {
	        qid = s->qid;
		if (qid && *qid) {
		    syslog(LOG_WARNING, "%s: handleWorkerStatusFD: Error reading from worker %d's status pipe: %m", s->qid, WORKERNO(s));
		} else {
		    syslog(LOG_WARNING, "handleWorkerStatusFD: Error reading from worker %d's status pipe: %m", WORKERNO(s));
		}
	    }
	}
	if (s != NULL) {
	  close(s->workerStatusFD);
	  Event_DelHandler(s->es, s->statusHandler);
	  s->statusHandler = NULL;
	  s->workerStatusFD = -1;
	}
  }
  if (changed) {
	if (s != NULL) {
	  notify_worker_status(s->es, WORKERNO(s), s->status_tag);
	}
  }
}

/**********************************************************************
* %FUNCTION: update_worker_status
* %ARGUMENTS:
*  s -- a worker
*  buf -- a buffer of data read from worker's status descriptor
* %RETURNS:
*  True if status was changed; false otherwise.
* %DESCRIPTION:
*  Tucks away line in worker's status area.
***********************************************************************/
static int
update_worker_status(Worker *s, char const *buf)
{
    char const *ptr = buf;
    if (!ptr || !*ptr) {
	return 0;
    }

    while(ptr && *ptr) {
	/* Only update a busy worker's status -- these updates can come in
	   AFTER worker has exited!
	*/
	if (s->state == STATE_BUSY) {
	    snprintf(s->status_tag, sizeof(s->status_tag), "%s", ptr);
	    s->status_tag[MAX_STATUS_LEN-1] = 0;
	    percent_decode(s->status_tag);
	}

	/* Scan past next newline */
	while (*ptr && *ptr != '\n') ++ptr;
	if (*ptr == '\n') {
	    ++ptr;
	} else {
	    return 1;
	}
    }
    return 1;
}

/**********************************************************************
* %FUNCTION: cmd_to_number
* %ARGUMENTS:
*  buf -- a command about to be sent to worker
* %RETURNS:
*  An integer representing the command (SCAN, RELAYOK, SENDEROK or RECIPOK)
*  or -1 if it isn't any of those commands.
***********************************************************************/
static int
cmd_to_number(char const *buf)
{
    if (!strncmp(buf, "relayok ", 8)) {
	return RELAYOK_CMD;
    } else if (!strncmp(buf, "senderok ", 9)) {
	return SENDEROK_CMD;
    } else if (!strncmp(buf, "recipok ", 8)) {
	return RECIPOK_CMD;
    } else if (!strncmp(buf, "scan ", 5)) {
	return SCAN_CMD;
    }
    return OTHER_CMD;
}

/**********************************************************************
* %FUNCTION: set_worker_status_from_command
* %ARGUMENTS:
*  s -- a worker
*  buf -- a command about to be sent to worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sets status tag to command name plus first argument, if any.
***********************************************************************/
static void
set_worker_status_from_command(Worker *s, char const *buf)
{
    char const *ptr = buf;
    char *out = s->status_tag;
    int len = 0;
    int space = 0;

    s->cmd = cmd_to_number(buf);

    while (*ptr && (*ptr != '\n') && len < MAX_STATUS_LEN - 1) {
	char c = *ptr++;
	*out++ = c;
	len++;
	if (c == ' ') {
	    space++;
	    if (space == 2) {
		*(out-1) = 0;
		break;
	    }
	}
    }

    *out = 0;

    /* If it was "recipok", set the domain appropriately
       if we have specified a limit on concurrent recipoks
       per domain */
    if ((s->cmd == RECIPOK_CMD) && (Settings.maxRecipokPerDomain > 0)) {
	int len = 0;
	s->domain[0] = 0;
	out = s->domain;
	ptr = buf;
	while(*ptr && (*ptr != '@')) ptr++;
	if (*ptr == '@') {
	    ptr++;
	    while(*ptr && *ptr != '>' && *ptr != ' ') {
		*out++ = *ptr++;
		len++;
		if (len >= MAX_DOMAIN_LEN - 1) break;
	    }
	    *out = 0;
	}
    }

    percent_decode(s->status_tag);
    /* Sanitize tag -- ASCII-centric! */
    out = s->status_tag;
    while (*out) {
	if (*out < ' ' || *out > '~') *out = ' ';
	++out;
    }
    notify_worker_status(s->es, WORKERNO(s), s->status_tag);
}

/**********************************************************************
* %FUNCTION: handleAccept
* %ARGUMENTS:
*  es -- event selector
*  fd -- accepted connection
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a connection attempt from MIMEDefang.  Sets up a command-reader.
***********************************************************************/
static void
handleAccept(EventSelector *es, int fd)
{
    if (!EventTcp_ReadBuf(es, fd, MAX_CMD_LEN, '\n', handleCommand,
			  Settings.clientTimeout, 1, NULL)) {
	if (DOLOG) {
	    syslog(LOG_ERR, "handleAccept: EventTcp_ReadBuf failed: %m");
	}
	close(fd);
    }
}

/**********************************************************************
* %FUNCTION: handleUnprivAccept
* %ARGUMENTS:
*  es -- event selector
*  fd -- accepted connection
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a connection attempt on the *unprivileged* socket.
***********************************************************************/
static void
handleUnprivAccept(EventSelector *es, int fd)
{
    if (NumUnprivConnections >= MAX_UNPRIV_CONNS) {
	close(fd);
	return;
    }

    /* Non-null arg indicates unprivileged socket! */
    if (!EventTcp_ReadBuf(es, fd, MAX_CMD_LEN, '\n', handleCommand,
			  Settings.clientTimeout, 1, &Activations)) {
	if (DOLOG) {
	    syslog(LOG_ERR, "handleAccept: EventTcp_ReadBuf failed: %m");
	}
	close(fd);
	return;
    }
    NumUnprivConnections++;
}

/**********************************************************************
* %FUNCTION: handleCommand
* %ARGUMENTS:
*  es -- event selector
*  fd -- connection to MIMEDefang
*  buf -- buffer of data read from MIMEDefang
*  len -- amount of data read from MIMEDefang
*  flag -- flag from reader
*  data -- if non-NULL, command came from unprivileged socket -- restrict
*          what we can do.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a MIMEDefang command.
***********************************************************************/
static void
handleCommand(EventSelector *es,
	      int fd,
	      char *buf,
	      int len,
	      int flag,
	      void *data)
{
    char answer[MAX_CMD_LEN];

    if (data) {
	NumUnprivConnections--;
    }
    if (flag == EVENT_TCP_FLAG_TIMEOUT || flag == EVENT_TCP_FLAG_IOERROR) {
	if (DOLOG) {
	    syslog(LOG_ERR, "handleCommand: Timeout or error: Flag = %d: %m",
		   flag);
	}
	/* Client timeout or error */
	close(fd);
	return;
    }

    /* Null-terminate buffer */
    if (len) {
	len--;
	buf[len] = 0;
    }

    /* Remove cr so we can use telnet for unpriv socket */
    if (len && (buf[len-1] == '\r')) {
	len--;
	buf[len] = 0;
    }
    if (len == 4 && !strcmp(buf, "help")) {
	if (data) {
	    doHelp(es, fd, 1);
	} else {
	    doHelp(es, fd, 0);
	}
	return;
    }

    if (len == 4 && !strcmp(buf, "free")) {
	snprintf(answer, sizeof(answer), "%d\n",
		 NUM_FREE_WORKERS);
	reply_to_mimedefang(es, fd, answer);
	return;
    }

    if (len == 7 && !strcmp(buf, "version")) {
	reply_to_mimedefang(es, fd, VERSION);
	return;
    }
    /* "tick" command must ONLY be internally-generated to guarantee
       that two tick handlers won't be running simultaneously */
    if (len == 4 && !strcmp(buf, "tick")) {
	snprintf(answer, sizeof(answer), "error: External agents may not invoke 'tick'\n");
	reply_to_mimedefang(es, fd, answer);
	return;
    }

    if (len == 6 && !strcmp(buf, "status")) {
	doStatus(es, fd);
	return;
    }

    /* We have to keep the old command for backward-compatibility */
    if (len == 6 && !strcmp(buf, "slaves")) {
	doWorkerReport(es, fd, 0);
	return;
    }

    if (len == 7 && !strcmp(buf, "workers")) {
	doWorkerReport(es, fd, 0);
	return;
    }

    /* We have to keep the old command for backward-compatibility */
    if (len == 10 && !strcmp(buf, "busyslaves")) {
	doWorkerReport(es, fd, 1);
	return;
    }
    if (len == 11 && !strcmp(buf, "busyworkers")) {
	doWorkerReport(es, fd, 1);
	return;
    }

    if (len == 4 && !strcmp(buf, "load")) {
	doLoad(es, fd, SCAN_CMD);
	return;
    }

    if (len > 6 && !strncmp(buf, "load1 ", 6)) {
	int back;
	if (sscanf(buf+6, "%d", &back) != 1 ||
	    back < 10 || back > 600) {
	    reply_to_mimedefang(es, fd, "error: Invalid 'back' amount (must be 10-600)\n");
	    return;
	}
	doLoad1(es, fd, back);
	return;
    }
    if (len == 12 && !strcmp(buf, "load-relayok")) {
	doLoad(es, fd, RELAYOK_CMD);
	return;
    }

    if (len == 13 && !strcmp(buf, "load-senderok")) {
	doLoad(es, fd, SENDEROK_CMD);
	return;
    }

    if (len == 12 && !strcmp(buf, "load-recipok")) {
	doLoad(es, fd, RECIPOK_CMD);
	return;
    }

    if (len == 5 && !strcmp(buf, "hload")) {
	doHourlyLoad(es, fd, SCAN_CMD);
	return;
    }

    if (len == 13 && !strcmp(buf, "hload-relayok")) {
	doHourlyLoad(es, fd, RELAYOK_CMD);
	return;
    }

    if (len == 14 && !strcmp(buf, "hload-senderok")) {
	doHourlyLoad(es, fd, SENDEROK_CMD);
	return;
    }

    if (len == 13 && !strcmp(buf, "hload-recipok")) {
	doHourlyLoad(es, fd, RECIPOK_CMD);
	return;
    }

    if (len == 5 && !strcmp(buf, "histo")) {
      doHistogram(es, fd);
      return;
    }

    if (len == 4 && !strcmp(buf, "msgs")) {
	snprintf(answer, sizeof(answer), "%d\n", NumMsgsProcessed);
	reply_to_mimedefang(es, fd, answer);
	return;
    }

    /* We have to keep the old command for backward-compatibility */
    if (len > 10 && !strncmp(buf, "slaveinfo ", 10)) {
	doWorkerInfo(es, fd, buf);
	return;
    }

    if (len > 11 && !strncmp(buf, "workerinfo ", 11)) {
	doWorkerInfo(es, fd, buf);
	return;
    }

    /* This is an awful hack used by watch-multiple-mimedefangs.tcl.
       We handle it here so we don't have to waste a worker */
    if (len == 19 && !strcmp(buf, "foo_no_such_command")) {
	reply_to_mimedefang(es, fd, "error: Unknown command\n");
	return;
    }

    /* Remaining commands are privileged */
    if (data) {
	reply_to_mimedefang(es, fd, "error: Attempt to use privileged command on unprivileged socket\n");
	return;
    }

    if (len == 6 && !strcmp(buf, "reread")) {
	newGeneration();
	notify_listeners(es, "R\n");
#ifndef SAFE_EMBED_PERL
	if (Settings.useEmbeddedPerl) {
	    reply_to_mimedefang(es, fd, "Cannot destroy and recreate an embedded Perl interpreter safely on this platform.  Filter rules will NOT be reread\n");
	    return;
	}
#endif
	reply_to_mimedefang(es, fd, "Forced reread of filter rules\n");
	return;
    }

    if (len > 5 && !strncmp(buf, "scan ", 5)) {
	doScan(es, fd, buf);
	return;
    }

    /* Any command other than "scan" is handled generically. */
    doWorkerCommand(es, fd, buf);
    return;
}

static int
worker_request_age(Worker *s) {
    if (s->firstReqTime == (time_t) -1) {
	return -1;
    }
    return (int) (time(NULL) - s->firstReqTime);
}

static int
worker_age(Worker *s) {
    if (s->activationTime == (time_t) -1) {
	return -1;
    }
    return (int) (time(NULL) - s->activationTime);
}

/**********************************************************************
* %FUNCTION: doWorkerInfo
* %ARGUMENTS:
*  es -- event selector
*  fd -- connection to MIMEDefang
*  cmd -- workerinfo command
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Returns detailed information about a specific worker
***********************************************************************/
static void
doWorkerInfo(EventSelector *es, int fd, char *cmd)
{
    int workerno;
    char buf[1024];
    Worker *s;

    if (sscanf(cmd+10, "%d", &workerno) != 1) {
	reply_to_mimedefang(es, fd, "error: Invalid worker number\n");
	return;
    }
    if (workerno < 0 || workerno >= Settings.maxWorkers) {
	reply_to_mimedefang(es, fd, "error: Worker number out of range\n");
	return;
    }
    s = &AllWorkers[workerno];
    snprintf(buf, sizeof(buf), "Worker %d\nState %s\nPID %d\nNumRequests %d\nNumScans %d\nAge %d\nFirstReqAge %d\nLastStateChangeAge %d\nStatusTag %s\n",
	     workerno,
	     state_name(s->state),
	     (int) s->pid,
	     s->numRequests,
	     s->numScans,
	     worker_age(s),
	     worker_request_age(s),
	     (int) (time(NULL) - s->lastStateChange),
	     s->status_tag);
    reply_to_mimedefang(es, fd, buf);
}

/**********************************************************************
* %FUNCTION: doScan
* %ARGUMENTS:
*  es -- event selector
*  fd -- connection to MIMEDefang
*  cmd -- scan command
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends the scan command to the worker and arranges for answer to be
*  sent back when scanning is complete.
***********************************************************************/
static void
doScan(EventSelector *es, int fd, char *cmd)
{
    int len;

    /* Add newline back to command */
    len = strlen(cmd);
    if (len < MAX_CMD_LEN-1) {
	cmd[len+1] = 0;
	cmd[len] = '\n';
    } else {
	char *answer = "error: Command too long\n";
	reply_to_mimedefang(es, fd, answer);
	if (DOLOG) {
	    syslog(LOG_DEBUG, "doScan: Command too long");
	}
	return;
    }

    doScanAux(es, fd, cmd, 1);
}

static void
doScanAux(EventSelector *es, int fd, char *cmd, int queueable)
{
    Worker *s;

    /* Find a free worker */
    s = findFreeWorker(SCAN_CMD);
    if (!s) {
	char *answer = "error: No free workers\n";
	if (queueable && Settings.requestQueueSize > 0) {
	    if (queue_request(es, fd, cmd)) {
		/* Successfully queued */
		return;
	    }
	}

	if (DOLOG) {
	    syslog(LOG_WARNING, "No free workers");
	}
	reply_to_mimedefang(es, fd, answer);
	return;
    }

    if (activateWorker(s, "About to perform scan") == (pid_t) -1) {
	char *answer = "error: Unable to activate worker\n";
	if (DOLOG) {
	    syslog(LOG_ERR, "Unable to activate worker %d",
		   WORKERNO(s));
	}
	reply_to_mimedefang(es, fd, answer);
	return;
    }

    /* Put the worker on the busy list */
    putOnList(s, STATE_BUSY);

    /* Set last_cmd field */
    s->last_cmd = SCAN_CMD;

    /* Update worker status */
    set_worker_status_from_command(s, cmd);

    /* Set worker's clientFD so we can reply */
    s->clientFD = fd;

    /* Set worker's queue ID and working directory */
    sscanf(cmd, "scan %" STR(MAX_QID_LEN) "s %" STR(MAX_DIR_LEN) "s", s->qid, s->workdir);
    s->workdir[MAX_DIR_LEN] = 0;
    s->qid[MAX_QID_LEN] = 0;

    /* Set worker's start-of-command time */
    gettimeofday(&(s->start_cmd), NULL);

    /* And tell the worker to go ahead... */
    s->event = EventTcp_WriteBuf(es, s->workerStdin, cmd, strlen(cmd),
				 handleWorkerReceivedCommand,
				 Settings.clientTimeout, s);
    if (!s->event) {
	if (DOLOG) syslog(LOG_ERR, "doScan: EventTcp_WriteBuf failed: %m");
	killWorker(s, "EventTcp_WriteBuf failed");
    } else {
	statsLog("StartFilter", WORKERNO(s), NULL);
    }
}

/**********************************************************************
* %FUNCTION: doWorkerCommand
* %ARGUMENTS:
*  es -- event selector
*  fd -- connection to MIMEDefang
*  cmd -- command
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends the command to the worker and arranges for answer to be
*  sent back when command finishes.
***********************************************************************/
static void
doWorkerCommand(EventSelector *es, int fd, char *cmd)
{
    int len;

    /* Add newline back to command */
    len = strlen(cmd);
    if (len < MAX_CMD_LEN-1) {
	cmd[len+1] = 0;
	cmd[len] = '\n';
    } else {
	char *answer = "error: Command too long\n";
	reply_to_mimedefang(es, fd, answer);
	if (DOLOG) {
	    syslog(LOG_DEBUG, "doWorkerCommand: Command too long");
	}
	return;
    }

    doWorkerCommandAux(es, fd, cmd, 1);
}

static int
at_recipok_limit(char *cmd)
{
    char domain_buf[MAX_DOMAIN_LEN];
    char const *ptr = cmd;
    char *out = domain_buf;
    int len = 0;
    int count = 0;
    Worker *s;

    while(*ptr && (*ptr != '@')) ptr++;

    /* No domain?  Punt! */
    if (*ptr != '@') return 0;

    ptr++;
    while(*ptr && *ptr != '>' && *ptr != ' ') {
	len++;
	*out++ = *ptr++;
	if (len >= MAX_DOMAIN_LEN - 1) break;
    }
    *out = 0;

    /* Search active workers doing recipok */
    s = Workers[STATE_BUSY];
    while(s) {
	if (s->cmd == RECIPOK_CMD &&
	    !strcasecmp(s->domain, domain_buf)) {
	    count++;
	    if (count >= Settings.maxRecipokPerDomain) {
		if (DOLOG) {
		    syslog(LOG_WARNING, "Hit per-domain recipok limit (%d) for domain %s", Settings.maxRecipokPerDomain, domain_buf);
		}
		return 1;
	    }
	}
	s = s->next;
    }
    return 0;
}

static void
doWorkerCommandAux(EventSelector *es, int fd, char *cmd, int queueable)
{
    Worker *s;
    char reason[200];
    int cmdno;

    sprintf(reason, "About to execute command '%.100s'", cmd);

    cmdno = cmd_to_number(cmd);

    /* If cmdno is RECIPOK_CMD, make
       sure we are not at per-domain limit */
    if ((cmdno == RECIPOK_CMD) && (Settings.maxRecipokPerDomain > 0)) {
	if (at_recipok_limit(cmd)) {
	    /* TODO: Should we queue?
	       Can't right now because queue-removal logic knows nothing
	       about per-domain recipok limit. */
	    reply_to_mimedefang(es, fd, "ok -1 Per-domain%20recipok%20limit%20hit;%20please%20try%20again%20later\n");
	    return;
	}
    }

    /* Find a free worker */
    s = findFreeWorker(cmdno);
    if (!s) {
	char *answer = "error: No free workers\n";
	if (queueable && Settings.requestQueueSize > 0) {
	    if (queue_request(es, fd, cmd)) {
		/* Successfully queued */
		return;
	    }
	}

	if (DOLOG) {
	    syslog(LOG_WARNING, "No free workers");
	}
	reply_to_mimedefang(es, fd, answer);
	return;
    }

    if (activateWorker(s, reason) == (pid_t) -1) {
	char *answer = "error: Unable to activate worker\n";
	if (DOLOG) {
	    syslog(LOG_ERR, "Unable to activate worker %d",
		   WORKERNO(s));
	}
	reply_to_mimedefang(es, fd, answer);
	return;
    }

    /* Put the worker on the busy list */
    putOnList(s, STATE_BUSY);

    /* Update last_cmd */
    if (cmdno >= 0) {
	s->last_cmd = cmdno;
    }

    /* Update worker's status tag */
    set_worker_status_from_command(s, cmd);

    /* Set worker's clientFD so we can reply */
    s->clientFD = fd;

    /* Null workdir signals not to log EndFilter event */
    s->workdir[0] = 0;

    /* Set the qid */
    switch(cmdno) {
    case SENDEROK_CMD:
	/* senderok sender ip name helo dir qid */
	sscanf(cmd, "senderok %*s %*s %*s %*s %*s %" STR(MAX_QID_LEN)  "s", s->qid);
	s->qid[MAX_QID_LEN] = 0;
	break;
    case RECIPOK_CMD:
	/* recipok recipient sender ip name firstrecip helo dir qid junk */
	sscanf(cmd, "recipok %*s %*s %*s %*s %*s %*s %*s %" STR(MAX_QID_LEN) "s", s->qid);
	s->qid[MAX_QID_LEN] = 0;
	break;
    default:
	s->qid[0]     = 0;
	break;
    }

    /* Set worker's start-of-command time */
    gettimeofday(&(s->start_cmd), NULL);

    /* And tell the worker to go ahead... */
    s->event = EventTcp_WriteBuf(es, s->workerStdin, cmd, strlen(cmd),
				 handleWorkerReceivedCommand,
				 Settings.clientTimeout, s);
    if (!s->event) {
	if (DOLOG) syslog(LOG_ERR, "doWorkerCommand: EventTcp_WriteBuf failed: %m");
	killWorker(s, "EventTcp_WriteBuf failed");
    }
}

/**********************************************************************
* %FUNCTION: handleWorkerReceivedCommand
* %ARGUMENTS:
*  es -- event selector
*  fd -- connection to MIMEDefang
*  buf -- buffer of data read from MIMEDefang
*  len -- amount of data read from MIMEDefang
*  flag -- flag from reader
*  data -- the worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called when command has been written to worker.  Sets up an event handler
*  to read the worker's reply
***********************************************************************/
static void
handleWorkerReceivedCommand(EventSelector *es,
			   int fd,
			   char *buf,
			   int len,
			   int flag,
			   void *data)
{
    Worker *s = (Worker *) data;

    /* Event was triggered */
    s->event = NULL;

    if (flag == EVENT_TCP_FLAG_TIMEOUT || flag == EVENT_TCP_FLAG_IOERROR) {
	/* Error writing to worker */
	char *answer = "error: Error talking to worker process\n";
	if (DOLOG) {
	    syslog(LOG_ERR, "handleWorkerReceivedCommand(%d): Timeout or error: Flag = %d: %m",
		   WORKERNO(s),
		   flag);
	}
	reply_to_mimedefang(es, s->clientFD, answer);
	/* The reply_to_mimedefang will close clientFD when it's done */
	s->clientFD = -1;

	/* Kill the worker process */
	killWorker(s, "Error talking to worker process");
	return;
    }

    /* Worker has been given the command; now wait for it to reply */
    s->event = EventTcp_ReadBuf(es, s->workerStdout, MAX_CMD_LEN, '\n',
				handleWorkerReceivedAnswer,
				Settings.busyTimeout, 1, s);
    if (!s->event) {
	if (DOLOG) syslog(LOG_ERR, "handleWorkerReceivedCommand: EventTcp_ReadBuf failed: %m");
	killWorker(s, "EventTcp_ReadBuf failed");
    }
}

/**********************************************************************
* %FUNCTION: handleWorkerReceivedAnswer
* %ARGUMENTS:
*  es -- event selector
*  fd -- connection to MIMEDefang
*  buf -- buffer of data read from MIMEDefang
*  len -- amount of data read from MIMEDefang
*  flag -- flag from reader
*  data -- the worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called when the worker's answer comes back.
***********************************************************************/
static void
handleWorkerReceivedAnswer(EventSelector *es,
			  int fd,
			  char *buf,
			  int len,
			  int flag,
			  void *data)
{
    Worker *s = (Worker *) data;
    struct timeval now;
    HistoryBucket *b;

    /* Event was triggered */
    s->event = NULL;

    /* If nothing was received from worker, send error message back */
    if (!len || (flag == EVENT_TCP_FLAG_TIMEOUT)) {
	if (flag == EVENT_TCP_FLAG_TIMEOUT) {
	    /* Heuristic... */
	    if (WorkerCount[STATE_BUSY] > 3) {
		reply_to_mimedefang(es, s->clientFD,
				    "ERR Filter timed out - system may be overloaded "
				    "(consider increasing busy timeout)\n");
		/* The reply_to_mimedefang will close clientFD when it's done */
		s->clientFD = -1;
	    } else {
		reply_to_mimedefang(es, s->clientFD,
				    "ERR Filter timed out - check filter rules or system load\n");
		/* The reply_to_mimedefang will close clientFD when it's done */
		s->clientFD = -1;
	    }
	} else {
	    if (DOLOG) {
		if (s->oom) {
		    syslog(LOG_ERR, "Worker %d ran out of memory -- possible DoS attack due to complex MIME?", WORKERNO(s));
		} else {
		    syslog(LOG_ERR, "Worker %d died prematurely -- check your filter rules", WORKERNO(s));
		}
	    } else {
		if (s->oom) {
		    syslog(LOG_ERR, "Worker %d ran out of memory -- possible DoS attack due to complex MIME?", WORKERNO(s));
		} else {
		    syslog(LOG_ERR, "Worker %d died prematurely -- check your filter rules and use the '-l' flag on mimedefang-multiplexor to see Perl error messages", WORKERNO(s));
		}
	    }
	    reply_to_mimedefang(es, s->clientFD, "ERR No response from worker\n");
	    /* The reply_to_mimedefang will close clientFD when it's done */
	    s->clientFD = -1;
	}
    } else {
	/* Write the worker's answer back to the client */
	reply_to_mimedefang_with_len(es, s->clientFD, buf, len);
	/* The reply_to_mimedefang will close clientFD when it's done */
	s->clientFD = -1;
    }

    s->numRequests++;

    if (s->cmd >= 0 && s->cmd < NUM_CMDS) {
	long sec_diff, usec_diff;
	int ms;


	/* Calculate how many milliseconds the command took */
	gettimeofday(&now, NULL);
	sec_diff = now.tv_sec - s->start_cmd.tv_sec;
	usec_diff = now.tv_usec - s->start_cmd.tv_usec;
	if (usec_diff < 0) {
	    usec_diff += 1000000;
	    sec_diff--;
	}
	ms = (int) (sec_diff * 1000 + usec_diff / 1000);
	b = get_history_bucket(s->cmd);
	b->count++;
	b->workers += WorkerCount[STATE_BUSY];
	b->ms += ms;

	b = get_hourly_history_bucket(s->cmd);
	b->count++;
	b->workers += WorkerCount[STATE_BUSY];
	b->ms += ms;

	/* Only increment NumMsgsProcessed for a "scan" command */
	if (s->cmd == SCAN_CMD) {
	    s->numScans++;
	    NumMsgsProcessed++;
	}
    }

    /* If we had a busy timeout, kill the worker */
    if (flag == EVENT_TCP_FLAG_TIMEOUT) {
	notify_listeners(es, "B\n");
	killWorker(s, "Busy timeout");
    } else {
	/* Put worker on free list */
	putOnList(s, STATE_IDLE);

	/* Nuke cmd field, just in case */
	s->cmd = -1;

	/* Record time when this worker became idle */
	s->idleTime = time(NULL);

	/* Check worker for expiry */
	checkWorkerForExpiry(s);
    }
    if (s->workdir[0]) {
	statsLog("EndFilter", WORKERNO(s), "numRequests=%d", s->numRequests);
    }
}

/**********************************************************************
* %FUNCTION: unlinkFromList
* %ARGUMENTS:
*  s -- a worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Unlinks "s" from the list it is currently on.
***********************************************************************/
static void
unlinkFromList(Worker *s)
{
    int state = s->state;
    Worker *prev = NULL;

    if (!Workers[state]) {
	/* Panic... worker not on this list */
	syslog(LOG_CRIT, "%s worker %d not found on its list!",
	       state_name(s->state), WORKERNO(s));
	return;
    }

    /* If it's the first on the list, simple */
    if (Workers[state] == s) {
	Workers[state] = s->next;
	s->next = NULL;
	return;
    }

    /* Somewhere in the middle of the list */
    prev = Workers[state];
    while (prev->next != s) {
	if (!prev->next) {
	    /* Panic... worker not on this list */
	    syslog(LOG_CRIT, "%s worker %d not found on its list!",
		   state_name(s->state), WORKERNO(s));
	    return;
	}
	prev = prev->next;
    }

    prev->next = s->next;
    s->next = NULL;
}

/**********************************************************************
* %FUNCTION: putOnList
* %ARGUMENTS:
*  s -- a worker
*  state -- state to change to.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sets s->state to state, and moves s to the Workers[state] list.
***********************************************************************/
static void
putOnList(Worker *s, int state)
{
    s->status_tag[0] = 0;
    if (s->state == state) {
	/* Already there, nothing to do */
	return;
    }

    notify_worker_state_change(s->es, WORKERNO(s),
			      state_name(s->state), state_name(state));
    /* Adjust counts */
    WorkerCount[s->state]--;
    WorkerCount[state]++;

    unlinkFromList(s);
    s->next = Workers[state];
    Workers[state] = s;
    s->state = state;
    s->lastStateChange = time(NULL);

    /* Update busy histogram if worker was made busy */
    if (state == STATE_BUSY) {
	AllWorkers[WorkerCount[STATE_BUSY]-1].histo++;
	/* Also update firstReqTime */
	if (s->firstReqTime == (time_t) -1) {
	    s->firstReqTime = s->lastStateChange;
	}
    }

    /* Notify listeners */
    if (Settings.notifySock && s->es && Old_NumFreeWorkers != NUM_FREE_WORKERS) {
	char msg[65];
	sprintf(msg, "F %d\n", NUM_FREE_WORKERS);
	notify_listeners(s->es, msg);
    }
    /* If we went to zero, notify with a Z message */
    if (NUM_FREE_WORKERS == 0) {
	notify_listeners(s->es, "Z\n");
    }
    if (Old_NumFreeWorkers == 0 && NUM_FREE_WORKERS != 0) {
	/* Went from zero to one free worker, notify with a Y message */
	notify_listeners(s->es, "Y\n");
    }

    Old_NumFreeWorkers = NUM_FREE_WORKERS;
}

/**********************************************************************
* %FUNCTION: activateWorker
* %ARGUMENTS:
*  s -- a worker
*  reason -- reason worker is being activated
* %RETURNS:
*  The process-ID of the worker
* %DESCRIPTION:
*  Activates the worker if it is not currently associated with a running
*  process.
***********************************************************************/
static pid_t
activateWorker(Worker *s, char const *reason)
{
    int pin[2], pout[2], perr[2], pstatus[2];
    char const *pname;
    int i;
    time_t now = (time_t) 0; /* Avoid compiler warning by initializing */
    sigset_t sigs;
    char *sarg;

    /* Check if it's already active */
    if (s->state == STATE_BUSY ||
	s->state == STATE_IDLE) {
	if (s->pid == (pid_t) -1) {
	    if (DOLOG) {
		syslog(LOG_ERR, "Argh!!! Worker %d in state %s has pid of -1!  Internal error!",
		       WORKERNO(s), state_name(s->state));
		putOnList(s, STATE_STOPPED);
	    }
	} else {
	    return s->pid;
	}
    }

    /* Check if enough time has elapsed */
    if (Settings.waitTime) {
	now = time(NULL);
	if (LastWorkerActivation &&
	     (((int) (now - LastWorkerActivation)) < Settings.waitTime)) {
	    if (DOLOG) {
		syslog(LOG_DEBUG, "Did not start worker %d: Not enough time elapsed since last worker activation", WORKERNO(s));
	    }
	    return -1;
	}
    }

    /* Set up pipes */
    if (pipe(pin) < 0) {
	if (DOLOG) syslog(LOG_ERR, "Could not start worker %d: pipe failed: %m",
			  WORKERNO(s));
	return -1;
    }
    if (pipe(pout) < 0) {
	if (DOLOG) syslog(LOG_ERR, "Could not start worker %d: pipe failed: %m",
			  WORKERNO(s));
	close(pin[0]);
	close(pin[1]);
	return -1;
    }

    if (pipe(perr) < 0) {
	if (DOLOG) syslog(LOG_ERR, "Could not start worker %d: pipe failed: %m",
			  WORKERNO(s));
	close(pin[0]);
	close(pin[1]);
	close(pout[0]);
	close(pout[1]);
	return -1;
    }

    pstatus[0] = -1;
    pstatus[1] = -1;
    if (Settings.wantStatusReports) {
	if (pipe(pstatus) < 0) {
	    if (DOLOG) syslog(LOG_ERR,
			      "Could not start worker %d: pipe failed: %m",
			      WORKERNO(s));
	    close(pin[0]);
	    close(pin[1]);
	    close(pout[0]);
	    close(pout[1]);
	    close(perr[0]);
	    close(perr[1]);
	    return -1;
	}
    }
    /* fork and exec */
    s->pid = fork();

    if (s->pid == (pid_t) -1) {
	if (DOLOG) syslog(LOG_ERR, "Could not start worker %d: fork failed: %m",
			  WORKERNO(s));
	close(pin[0]);
	close(pin[1]);
	close(pout[0]);
	close(pout[1]);
	close(perr[0]);
	close(perr[1]);
	if (pstatus[0] >= 0) close(pstatus[0]);
	if (pstatus[1] >= 0) close(pstatus[1]);
	return s->pid; /* Fork failed */
    }

    if (s->pid) {
	HistoryBucket *b;

	putOnList(s, STATE_IDLE);
	/* Record time when this worker became idle */
	s->idleTime = time(NULL);

	/* Record activation time (just copy instead of calling time()) */
	s->activationTime = s->idleTime;

	/* Track activations in history */
	b = get_history_bucket(SCAN_CMD);
	b->activated++;

	/* In the parent -- return */
	close(pin[0]);
	close(pout[1]);
	close(perr[1]);
	if (pstatus[1] >= 0) close(pstatus[1]);

	s->workerStdin = pin[1];
	s->workerStdout = pout[0];
	s->workerStderr = perr[0];
	s->workerStatusFD = pstatus[0];
	s->activated = Activations++;

	/* Make worker stderr non-blocking */
	if (set_nonblocking(s->workerStderr) < 0) {
	    syslog(LOG_ERR, "Could not make worker %d's stderr non-blocking: %m", WORKERNO(s));
	}
	/* Handle anything written to worker's stderr */
	s->errHandler = Event_AddHandler(s->es, s->workerStderr,
					 EVENT_FLAG_READABLE,
					 handleWorkerStderr, s);

	/* Handle anything written to status descriptor */
	if (Settings.wantStatusReports) {
	    if (set_nonblocking(s->workerStatusFD) < 0) {
		syslog(LOG_ERR, "Could not make worker %d's status descriptor non-blocking: %m", WORKERNO(s));
	    }
	    s->statusHandler = Event_AddHandler(s->es, s->workerStatusFD,
						EVENT_FLAG_READABLE,
						handleWorkerStatusFD, s);
	} else {
	    s->statusHandler = NULL;
	}

	s->clientFD = -1;
	s->numRequests = 0;
	s->numScans = 0;
	s->oom = 0;
	s->generation = Generation;
	s->last_cmd = NO_CMD;
	if (DOLOG) {
	    syslog(LOG_INFO, "Starting worker %d (pid %lu) (%d running): %s",
		   WORKERNO(s),
		   (unsigned long) s->pid, NUM_RUNNING_WORKERS, reason);
	}
	statsLog("StartWorker", WORKERNO(s), "reason=\"%s\"", reason);
	if (Settings.waitTime) {
	    LastWorkerActivation = now;
	}
	return s->pid;
    }

    /* In the child */

    /* Reset signal-handling dispositions */
    signal(SIGTERM, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    sigemptyset(&sigs);
    sigprocmask(SIG_SETMASK, &sigs, NULL);

    /* Set resource limits */
#ifdef HAVE_SETRLIMIT
    limit_mem_usage(Settings.maxRSS, Settings.maxAS);
#endif

    /* Close unneeded file descriptors */
    closelog();
    close(pin[1]);
    close(pout[0]);
    close(perr[0]);
    dup2(pin[0], STDIN_FILENO);
    dup2(pout[1], STDOUT_FILENO);
    dup2(perr[1], STDERR_FILENO);

    if (pin[0] != STDIN_FILENO) close(pin[0]);
    if (pout[1] != STDOUT_FILENO) close(pout[1]);
    if (perr[1] != STDERR_FILENO) close(perr[1]);

    if (Settings.wantStatusReports) {
	dup2(pstatus[1], STDERR_FILENO+1);
	if (pstatus[1] != STDERR_FILENO+1) close(pstatus[1]);
    }

    if (!Settings.wantStatusReports) (void) close(STDERR_FILENO+1);

    for (i=STDERR_FILENO+2; i<1024; i++) {
	(void) close(i);
    }

    pname = strrchr(Settings.progPath, '/');
    if (pname) {
	pname++;
    } else {
	pname = Settings.progPath;
    }

#ifdef EMBED_PERL
    if (Settings.useEmbeddedPerl) {
	run_embedded_filter();
	term_embedded_interpreter();
        deinit_embedded_interpreter();
	exit(EXIT_SUCCESS);
    }
#endif
    if (Settings.wantStatusReports) {
	sarg = "-serveru";
    } else {
	sarg = "-server";
    }
    if (Settings.subFilter) {
	execl(Settings.progPath, pname, "-f", Settings.subFilter, sarg, NULL);
    } else {
	execl(Settings.progPath, pname, sarg, NULL);
    }
    _exit(EXIT_FAILURE);
}

/**********************************************************************
* %FUNCTION: checkWorkerForExpiry
* %ARGUMENTS:
*  s -- a worker to check
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  If the worker has served too many requests, it is killed.
***********************************************************************/
static void
checkWorkerForExpiry(Worker *s)
{
    /* If there is a queued request, don't terminate worker just yet.  Allow
       it to go up to triple maxRequests.  Yes, this is a horrible hack. */
    if (s->numRequests < Settings.maxRequests * 3) {
	if (handle_queued_request()) {
	    return;
	}
    }
    if (s->numRequests >= Settings.maxRequests) {
	char reason[200];
	snprintf(reason, sizeof(reason), "Worker has processed %d requests",
		 s->numRequests);
	killWorker(s, reason);
    } else if (Settings.maxLifetime > 0 && worker_request_age(s) > Settings.maxLifetime) {
	char reason[200];
	snprintf(reason, sizeof(reason), "Worker has exceeded maximum lifetime of %d seconds", Settings.maxLifetime);
	killWorker(s, reason);
    } else if (s->generation < Generation) {
	killWorker(s, "New generation -- forcing reread of filter rules");
    }
}

/**********************************************************************
* %FUNCTION: killWorker
* %ARGUMENTS:
*  s -- a worker to kill
*  reason -- reason worker is being killed
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Kills a worker by closing its pipe.  The worker then has 10 seconds
*  to clean up and exit before we send SIGTERM
***********************************************************************/
static void
killWorker(Worker *s, char const *reason)
{
    struct timeval t;
    int withPrejudice = 0;

    int age = worker_age(s);
    int req_age = worker_request_age(s);
    if (s->state != STATE_KILLED) {
	if (DOLOG) syslog(LOG_INFO, "Killing %s worker %d (pid %lu) req=%d age=%d req_age=%d: %s",
			  state_name_lc(s->state),
			  WORKERNO(s),
			  (unsigned long) s->pid,
			  s->numRequests,
			  age,
			  req_age,
			  reason);
	/* In case, for some weird reason, the worker has stopped... */
	kill(s->pid, SIGCONT);

	/* If worker is busy, we kill it with prejudice */
	if (s->state == STATE_BUSY) {
	    withPrejudice = 1;
	    kill(s->pid, SIGTERM);
	}

	putOnList(s, STATE_KILLED);
	/* Close stdin so worker sees EOF */
	close(s->workerStdin);
	s->workerStdin = -1;

	/* Kill any pending event */
	if (s->event) {
	    EventTcp_CancelPending(s->event);
	    s->event = NULL;
	}

	/* Set up a timer to send SIGTERM if worker doesn't exit in
	   10 seconds */
	t.tv_sec = 10;
	t.tv_usec = 0;
	if (withPrejudice) {
	    s->termHandler = Event_AddTimerHandler(s->es, t,
						   nukeWorker, (void *) s);
	} else {
	    s->termHandler = Event_AddTimerHandler(s->es, t,
						   terminateWorker, (void *) s);
	}
	statsLog("KillWorker", WORKERNO(s), "req=%d age=%d reason=\"%s\"", s->numRequests, age, reason);
    }
}

/**********************************************************************
* %FUNCTION: terminateWorker
* %ARGUMENTS:
*  es -- Event selector
*  fd -- not used
*  flags -- ignored
*  data -- the worker to terminate
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends a SIGTERM to worker, because it's taken too long to exit.
***********************************************************************/
static void
terminateWorker(EventSelector *es,
	       int fd,
	       unsigned int flags,
	       void *data)
{
    struct timeval t;
    Worker *s = (Worker *) data;
    s->termHandler = NULL;
    if (s->pid != (pid_t) -1) {
	if (DOLOG) {
	    syslog(LOG_INFO,
		   "Worker %d (pid %lu) taking too long to exit; sending SIGTERM",
		   WORKERNO(s), (unsigned long) s->pid);
	}
	kill(s->pid, SIGCONT);
	kill(s->pid, SIGTERM);
	/* Set up a timer to send SIGKILL if worker doesn't exit in
	   10 seconds */
	t.tv_sec = 10;
	t.tv_usec = 0;
	s->termHandler = Event_AddTimerHandler(s->es, t, nukeWorker, (void *) s);
    }
}

/**********************************************************************
* %FUNCTION: nukeWorker
* %ARGUMENTS:
*  es -- Event selector
*  fd -- not used
*  flags -- ignored
*  data -- the worker to nuke
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends a SIGKILL to worker, because it's taken too long to exit, in spite
*  of getting a SIGTERM
***********************************************************************/
static void
nukeWorker(EventSelector *es,
	  int fd,
	  unsigned int flags,
	  void *data)
{
    Worker *s = (Worker *) data;
    s->termHandler = NULL;
    if (s->pid != (pid_t) -1) {
	if (DOLOG) {
	    syslog(LOG_INFO,
		   "Worker %d (pid %lu) taking way too long to exit; sending SIGKILL",
		   WORKERNO(s), (unsigned long) s->pid);
	}
	kill(s->pid, SIGCONT);
	kill(s->pid, SIGKILL);
    }
}

/**********************************************************************
*%FUNCTION: childHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGCHLD.  Writes 'C' to Pipe to wake up the select
* loop and cause reaping of dead sessions
***********************************************************************/
static void
childHandler(int sig)
{
    char byte = 'C';
    if (!ReapPending) {
	ReapPending = 1;
	if (!CharPending) {
	    int errno_save = errno;
	    write(Pipe[1], &byte, 1);
	    errno = errno_save;
	    CharPending = 1;;
	}
    }
}

/**********************************************************************
*%FUNCTION: hupHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGHUP.  Writes 'H' to Pipe to wake up the select
* loop and cause closing and reopening of stats descriptor
***********************************************************************/
static void
hupHandler(int sig)
{
    char byte = 'H';
    if (!HupPending) {
	HupPending = 1;
	if (!CharPending) {
	    int errno_save = errno;
	    write(Pipe[1], &byte, 1);
	    errno = errno_save;
	    CharPending = 1;;
	}
    }
}

/**********************************************************************
*%FUNCTION: intHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGINT.  Writes 'I' to Pipe to wake up the select
* loop and cause closing and reopening of stats descriptor
***********************************************************************/
static void
intHandler(int sig)
{
    char byte = 'I';
    if (!IntPending) {
	IntPending = 1;
	if (!CharPending) {
	    int errno_save = errno;
	    write(Pipe[1], &byte, 1);
	    errno = errno_save;
	    CharPending = 1;;
	}
    }
}

/**********************************************************************
* %FUNCTION: handlePipe
* %ARGUMENTS:
*  es -- event selector (ignored)
*  fd -- file descriptor which is readable
*  flags -- ignored
*  data -- ignored
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Simply reads from the pipe; then reaps and/or closes and reopens
*  stats file.
***********************************************************************/
static void
handlePipe(EventSelector *es,
	    int fd,
	    unsigned int flags,
	    void *data)
{
    char buf[64];
    sigset_t sigs, osigs;
    int n;
    int doreap, dohup, doint;

    /* The read and the reset of CharPending must be atomic with respect
       to signal handlers. */
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGCHLD);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGHUP);

    n = sigprocmask(SIG_BLOCK, &sigs, &osigs);
    if (n < 0) {
	syslog(LOG_ERR, "sigprocmask failed: %m");
    }

    /* Begin atomic portion */
    read(fd, buf, 64);
    doreap = ReapPending;
    doint  = IntPending;
    dohup  = HupPending;
    CharPending = 0;
    ReapPending = 0;
    IntPending  = 0;
    HupPending  = 0;
    /* End atomic portion */

    /* Reset signal mask */
    if (n >= 0) {
	sigprocmask(SIG_SETMASK, &osigs, NULL);
    }

    if (doreap) {
	reapTerminatedWorkers(0);

	/* Activate new workers if we've fallen below minimum */
	if (NUM_RUNNING_WORKERS < Settings.minWorkers) {
	    scheduleBringWorkersUpToMin(es);
	}
    }
    if (dohup) {
	statsReopenFile();
    }
    if (doint) {
	newGeneration();
	notify_listeners(es, "R\n");
    }
}

/**********************************************************************
* %FUNCTION: reapTerminatedWorkers
* %ARGUMENTS:
*  killed -- If true, multiplexor was killed and has killed all workers
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Reaps all terminated workers
***********************************************************************/
static void
reapTerminatedWorkers(int killed)
{
    pid_t pid;
    int status;
    Worker *s;
    int oldstate;
    HistoryBucket *b;

#ifdef HAVE_WAIT3
    struct rusage resource;

    while ((pid = wait3(&status, WNOHANG, &resource)) > 0) {
#else
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
#endif
	s = findWorkerByPid(pid);
	if (!s) continue;

	oldstate = s->state;
	if (killed) {
	    s->state = STATE_KILLED;
	}
	logWorkerReaped(s, status);
	if (killed) {
	    s->state = oldstate;
	}

#ifdef HAVE_WAIT3
	log_worker_resource_usage(s, &resource);
#endif
	s->pid = (pid_t) -1;
	s->activationTime = (time_t) -1;
	s->firstReqTime = (time_t) -1;
	shutDescriptors(s);
	putOnList(s, STATE_STOPPED);
	statsLog("ReapWorker", WORKERNO(s), NULL);
	b = get_history_bucket(SCAN_CMD);
	b->reaped++;
    }
}

/**********************************************************************
* %FUNCTION: shutDescriptors
* %ARGUMENTS:
*  s -- a worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Closes worker's descriptors if necessary
***********************************************************************/
static void
shutDescriptors(Worker *s)
{
    char buffer[64];
    int n;

    if (s->workerStdin >= 0) {
	close(s->workerStdin);
	s->workerStdin = -1;
    }
    if (s->workerStdout >= 0) {
	close(s->workerStdout);
	s->workerStdout = -1;
    }
    if (s->workerStderr >= 0) {
	Event_DelHandler(s->es, s->errHandler);
	s->errHandler = NULL;
	/* Consume and log any error messages */
	while( (n=read(s->workerStderr, buffer, sizeof(buffer)-1)) > 0) {
	    buffer[n] = 0;
	    if (buffer[n-1] == '\n') {
		buffer[n-1] = 0;
	    }
	    if (DOLOG) {
		syslog(LOG_INFO, "Worker %d stderr: %s", WORKERNO(s), buffer);
	    }
	}
	close(s->workerStderr);
	s->workerStderr = -1;
    }
    if (s->workerStatusFD >= 0) {
	close(s->workerStatusFD);
	Event_DelHandler(s->es, s->statusHandler);
	s->statusHandler = NULL;
	s->workerStatusFD = -1;
    }

    if (s->termHandler) {
	Event_DelHandler(s->es, s->termHandler);
	s->termHandler = NULL;
    }

    if (s->event) {
	EventTcp_CancelPending(s->event);
	s->event = NULL;
    }

    if (s->clientFD >= 0) {
	close(s->clientFD);
	s->clientFD = -1;
    }
}

/**********************************************************************
* %FUNCTION: handleIdleTimeout
* %ARGUMENTS:
*  es -- event selector
*  fd, flags, data -- ignored
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called periodically to check for idle workers that can be killed
***********************************************************************/
static void
handleIdleTimeout(EventSelector *es,
		  int fd,
		  unsigned int flags,
		  void *data)
{
    time_t now = time(NULL);
    struct timeval t;

    /* Kill idle workers which have been idle for maxIdleTime
       or alive for more than maxLifetime*/
    Worker *s = Workers[STATE_IDLE];
    Worker *next;
    int numAlive = NUM_RUNNING_WORKERS;

    /* First pass: Kill workers that have exceeded their
     * lifetimes */
    while(s) {
	next = s->next;
	if (Settings.maxLifetime > 0 && worker_request_age(s) > Settings.maxLifetime) {
	    char reason[200];
	    snprintf(reason, sizeof(reason), "Worker has exceeded maximum lifetime of %d seconds", Settings.maxLifetime);
	    numAlive--;
	    killWorker(s, reason);
	}
	s = next;
    }

    /* Next pass: Kill workers that have been idle for too long */
    s = Workers[STATE_IDLE];
    while(s && numAlive > Settings.minWorkers) {
	next = s->next;
	if ((unsigned long) now - (unsigned long) s->idleTime >= Settings.maxIdleTime) {
	    numAlive--;
	    killWorker(s, "Idle timeout");
	}
	s = next;
    }

    /* If there are fewer running workers than Settings.minWorkers,
       then start some more. */
    if (numAlive < Settings.minWorkers) {
	scheduleBringWorkersUpToMin(es);
    }

    /* Reschedule timer */
    t.tv_usec = 0;
    t.tv_sec = Settings.maxIdleTime;
    Event_AddTimerHandler(es, t, handleIdleTimeout, NULL);
}

/**********************************************************************
* %FUNCTION: doStatusLog
* %ARGUMENTS:
*  es -- event selector
*  fd, flags, data -- ignored
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called periodically to log worker status (numRunning, etc.)
***********************************************************************/
static void
doStatusLog(EventSelector *es,
	    int fd,
	    unsigned int flags,
	    void *data)
{
    struct timeval t;

    syslog(LOG_INFO,
	   "Worker status: Stopped=%d Idle=%d Busy=%d Killed=%d Queued=%d Msgs=%d Activations=%u",
	   WorkerCount[STATE_STOPPED],
	   WorkerCount[STATE_IDLE],
	   WorkerCount[STATE_BUSY],
	   WorkerCount[STATE_KILLED],
	   NumQueuedRequests,
	   NumMsgsProcessed,
	   Activations);

    /* Reschedule timer */
    t.tv_usec = 0;
    t.tv_sec = Settings.logStatusInterval;
    Event_AddTimerHandler(es, t, doStatusLog, NULL);
}

/**********************************************************************
* %FUNCTION: logWorkerReaped
* %ARGUMENTS:
*  s -- worker
*  status -- termination status
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Logs to syslog
***********************************************************************/
static void
logWorkerReaped(Worker *s, int status)
{
    int level;
    char *extra;

    if (s->state == STATE_KILLED) {
	level = LOG_DEBUG;
	extra = "";
    } else {
	level = LOG_ERR;
	extra = " (WORKER DIED UNEXPECTEDLY)";
	if (s->es) {
	    notify_listeners(s->es, "U\n");
	}
    }
    if (!DOLOG) {
	return;
    }

    if (WIFEXITED(status)) {
	syslog(level, "Reap: worker %d (pid %lu) exited normally with status %d%s",
	       WORKERNO(s), (unsigned long) s->pid, WEXITSTATUS(status),
	       extra);
	return;
    }
    if (WIFSIGNALED(status)) {
	if (s->state == STATE_KILLED && (WTERMSIG(status) == SIGTERM ||
			  WTERMSIG(status) == SIGKILL)) {
	    syslog(level, "Reap: worker %d (pid %lu) exited due to SIGTERM/SIGKILL as expected.",
		   WORKERNO(s), (unsigned long) s->pid);
	} else {
	    syslog(level, "Reap: worker %d (pid %lu) exited due to signal %d%s",
		   WORKERNO(s), (unsigned long) s->pid, WTERMSIG(status),
		   extra);
	}
	return;
    }
    syslog(level, "Reap: worker %d (pid %lu) exited for unknown reason%s",
	   WORKERNO(s), (unsigned long) s->pid, extra);
}

/**********************************************************************
* %FUNCTION: sigterm
* %ARGUMENTS:
*  sig -- signal number
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called when SIGTERM received -- kills workers and exits
***********************************************************************/
static void
sigterm(int sig)
{
    int i, j, oneleft;

    /* Only the parent process should handle SIGTERM */
    if (ParentPid != getpid()) {
	syslog(LOG_WARNING, "Child process received SIGTERM before signal disposition could be reset!  Exiting!");
	exit(EXIT_FAILURE);
    }

    if (pidfile) {
	unlink(pidfile);
    }
    if (lockfile) {
	unlink(lockfile);
    }
    if (DOLOG) {
	if (sig) {
	    syslog(LOG_INFO, "Received SIGTERM: Stopping workers and terminating");
	}
    }

    /* Remove our socket so we don't get any more requests */
    if (Settings.sockName) {
	(void) remove(Settings.sockName);
    }

    /* Hack...*/
    if (Settings.unprivSockName && (Settings.unprivSockName[0] == '/')) {
	(void) remove(Settings.unprivSockName);
    }

    /* First, close descriptors to force EOF on STDIN; then wait up to 10
       seconds before sending SIGTERM */
    for (i=0; i<Settings.maxWorkers; i++) {
	if (AllWorkers[i].pid != (pid_t) -1) {
	    kill(AllWorkers[i].pid, SIGCONT);
	    close(AllWorkers[i].workerStdin);
	    AllWorkers[i].workerStdin = -1;
	}
    }

    /* Wait up to 10 seconds for workers to exit; then kill with SIGTERM */
    for (j=0; j<10; j++) {
	reapTerminatedWorkers(1);
	oneleft = 0;
	for (i=0; i<Settings.maxWorkers; i++) {
	    if (AllWorkers[i].pid != (pid_t) -1) {
		oneleft = 1;
		break;
	    }
	}
	if (!oneleft) {
#ifdef EMBED_PERL
  if (Settings.useEmbeddedPerl) {
    term_embedded_interpreter();
    deinit_embedded_interpreter();
  }
#endif
	    exit(EXIT_SUCCESS);
	}
	if (j != 9) {
	    sleep(1);
	}
    }

    syslog(LOG_INFO, "Still some workers alive: Sending SIGTERM");
    /* Still some workers.  SIGTERM them */
    for (i=0; i<Settings.maxWorkers; i++) {
	if (AllWorkers[i].pid != (pid_t) -1) {
	    kill(AllWorkers[i].pid, SIGCONT);
	    kill(AllWorkers[i].pid, SIGTERM);
	}
    }

    /* Wait up to 10 seconds for workers to exit; then kill with SIGKILL */
    for (j=0; j<10; j++) {
	reapTerminatedWorkers(1);
	oneleft = 0;
	for (i=0; i<Settings.maxWorkers; i++) {
	    if (AllWorkers[i].pid != (pid_t) -1) {
		oneleft = 1;
		break;
	    }
	}
	if (!oneleft) {
#ifdef EMBED_PERL
	    if (Settings.useEmbeddedPerl) {
                term_embedded_interpreter();
                deinit_embedded_interpreter();
            }
#endif
	    exit(EXIT_SUCCESS);
	}
	if (j != 9) {
	    sleep(1);
	}
    }

    syslog(LOG_INFO, "Still some workers alive: Sending SIGKILL");
    /* Kill with SIGKILL */
    for (i=0; i<Settings.maxWorkers; i++) {
	if (AllWorkers[i].pid != (pid_t) -1) {
	    kill(AllWorkers[i].pid, SIGCONT);
	    kill(AllWorkers[i].pid, SIGKILL);
	}
    }
#ifdef EMBED_PERL
    if (Settings.useEmbeddedPerl) {
        term_embedded_interpreter();
        deinit_embedded_interpreter();
    }
#endif
    exit(EXIT_SUCCESS);
}

/**********************************************************************
* %FUNCTION: statsReopenFile
* %ARGUMENTS:
*  None
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Opens or re-opens statistics file.
***********************************************************************/
static void
statsReopenFile(void)
{
    if (!Settings.statsFile) return;
    if (Settings.statsFP) {
	if (fclose(Settings.statsFP) == EOF) {
	    syslog(LOG_ERR, "Failed to close stats file: %m");
	}
	Settings.statsFP = NULL;
    }

    Settings.statsFP = fopen(Settings.statsFile, "a");
    if (!Settings.statsFP) {
	syslog(LOG_ERR, "Could not open stats file %s: %m",
	       Settings.statsFile);
    } else {
	if(set_cloexec(fileno(Settings.statsFP)) < 0) {
	    syslog(LOG_ERR, "Could not set FD_CLOEXEC option on socket");
	}
    }
}

/**********************************************************************
* %FUNCTION: statsLog
* %ARGUMENTS:
*  event -- name of event to put in log
*  workerno -- worker involved in this event, or -1 if not worker-specific
*  fmt   -- "printf" format string with extra args to add to line
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Logs an event to the stats file
***********************************************************************/
static void
statsLog(char const *event, int workerno, char const *fmt, ...)
{
    struct timeval now;
    time_t tnow;
    struct tm *t;
    char tbuf[64];
    char statbuf[1024];
    va_list ap;
    int ms;

    if (!Settings.statsFP && !Settings.statsToSyslog) return;

    gettimeofday(&now, NULL);
    tnow = (time_t) now.tv_sec;
    t = localtime(&tnow);
    ms = now.tv_usec / 1000;

    strftime(tbuf, sizeof(tbuf), "%d/%m/%Y:%H:%M:%S", t);
    snprintf(statbuf, sizeof(statbuf),
	     "%s %lu.%03d %s worker=%d nworkers=%d nbusy=%d",
	     tbuf, (unsigned long) tnow, ms, event, workerno,
	     NUM_RUNNING_WORKERS, WorkerCount[STATE_BUSY]);

    statbuf[sizeof(statbuf)-1] = 0;

    if (fmt) {
	int len = strlen(statbuf);
	statbuf[len] = ' ';
	va_start(ap, fmt);
	vsnprintf(statbuf+len+1, sizeof(statbuf)-len-1, fmt, ap);
	va_end(ap);
	statbuf[sizeof(statbuf)-1] = 0;
    }

    if (Settings.statsFP) {
	fprintf(Settings.statsFP, "%s\n", statbuf);
	if (Settings.flushStats) fflush(Settings.statsFP);
    }
    if (Settings.statsToSyslog) {
	/* Chop off the date, because it's redundant.  The date is
	   always "dd/mm/YYYY:hh:mm:ss " = 20 characters long. */
	syslog(LOG_INFO, "stats %s", statbuf + 20);
    }
}

/**********************************************************************
* %FUNCTION: newGeneration
* %ARGUMENTS:
*  None
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Kills all running-but-idle workers and increments Generation.  This
*  causes running-but-busy workers to terminate at the earliest opportunity.
*  Use this if you change the filter file and want to restart the workers.
***********************************************************************/
static void
newGeneration(void)
{
    Generation++;
#ifdef EMBED_PERL
    if (Settings.useEmbeddedPerl) {
	if (make_embedded_interpreter(Settings.progPath,
				      Settings.subFilter,
				      Settings.wantStatusReports, Env) < 0) {
	    syslog(LOG_ERR, "Error creating embedded Perl interpreter: Reverting to non-embedded interpreter!");
	    Settings.useEmbeddedPerl = 0;
	} else {
	    if (DOLOG) {
		syslog(LOG_INFO, "Re-initialized embedded Perl interpreter");
	    }
	}
    }
#endif

    /* Reset SIGCHLD handler in case some Perl code has monkeyed with it */
    set_sigchld_handler();

    while(Workers[STATE_IDLE]) {
	killWorker(Workers[STATE_IDLE],
		  "Forcing reread of filter rules");
    }
}

/**********************************************************************
* %FUNCTION: bringWorkersUpToMin
* %ARGUMENTS:
*  es -- event selector
*  fd, flags, data -- ignored
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  If there are fewer than minWorkers running, start one.  If still fewer,
*  schedule self to re-run in slewTime seconds.
***********************************************************************/
void
bringWorkersUpToMin(EventSelector *es,
		   int fd,
		   unsigned int flags,
		   void *data)
{
    Worker *s;
    char reason[200];

    minScheduled = 0;

    if (NUM_RUNNING_WORKERS >= Settings.minWorkers) {
	/* Enough workers, so do nothing */
	return;
    }

    /* Start a worker */
    s = Workers[STATE_STOPPED];
    if (s) {
	snprintf(reason, sizeof(reason),
		 "Bringing workers up to minWorkers (%d)", Settings.minWorkers);
	if (activateWorker(s, reason) >= 0) {
	    /* Check for and handle queued requests, if there are any */
	    /* FOR THE FUTURE
	    handle_queued_request();
	    */
	}
    }


    /* Reschedule if necessary */
    if (NUM_RUNNING_WORKERS < Settings.minWorkers) {
	scheduleBringWorkersUpToMin(es);
    }
}

/**********************************************************************
* %FUNCTION: scheduleBringWorkersUpToMin
* %ARGUMENTS:
*  es -- event selector
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Schedules a call to bringWorkersUpToMin in slewTime seconds from now.
***********************************************************************/
static void
scheduleBringWorkersUpToMin(EventSelector *es)
{
    struct timeval t;

    /* Do nothing if already scheduled */
    if (minScheduled) return;

    minScheduled = 1;
    t.tv_usec = 0;
    t.tv_sec = Settings.slewTime;
    Event_AddTimerHandler(es, t, bringWorkersUpToMin, NULL);
}

#ifdef HAVE_SETRLIMIT
/**********************************************************************
* %FUNCTION: limit_mem_usage
* %ARGUMENTS:
*  rss -- maximum resident-set size in kB
*  as  -- maximum total address space in kB
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Calls setrlimit to limit resource usage
***********************************************************************/
static void
limit_mem_usage(unsigned long rss,
		unsigned long as)
{
    int n;
    struct rlimit lim;

#ifdef RLIMIT_RSS
    if (rss) {
	/* Convert kb to bytes */
	rss *= 1024;
	lim.rlim_cur = rss;
	lim.rlim_max = rss;
	n = setrlimit(RLIMIT_RSS, &lim);
	if (n < 0) {
	    syslog(LOG_WARNING, "setrlimit(RLIMIT_RSS, %lu) failed: %m",
		   rss);
	}
    }
#endif
    if (as) {
	/* Convert kb to bytes */
	as *= 1024;
	lim.rlim_cur = as;
	lim.rlim_max = as;
#ifdef RLIMIT_AS
	n = setrlimit(RLIMIT_AS, &lim);
	if (n < 0) {
	    syslog(LOG_WARNING, "setrlimit(RLIMIT_AS, %lu) failed: %m",
		   as);
	}
#endif

#ifdef RLIMIT_DATA
	n = setrlimit(RLIMIT_DATA, &lim);
	if (n < 0) {
	    syslog(LOG_WARNING, "setrlimit(RLIMIT_DATA, %lu) failed: %m",
		   as);
	}
#endif

    }
}
#endif /* HAVE_SETRLIMIT */

/**********************************************************************
* %FUNCTION: doWorkerReport
* %ARGUMENTS:
*  es -- event selector
*  fd -- socket
*  only_busy -- if true, only report on busy workers
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Prints a list of workers, statuses and pids
***********************************************************************/
static void
doWorkerReport(EventSelector *es, int fd, int only_busy)
{
    int len = Settings.maxWorkers * (33 + MAX_STATUS_LEN + 2 + 32) + 1;
    char *ans = malloc(len);
    char *ptr = ans;
    char status = '?';
    int i, j;
    time_t now;
    int secs;
    if (!ans) {
	reply_to_mimedefang(es, fd, "error: Out of memory\n");
	return;
    }
    *ans = 0;
    now = time(NULL);

    for (i=0; i<Settings.maxWorkers; i++) {
	Worker *s = &AllWorkers[i];
	if (only_busy && (s->state != STATE_BUSY)) {
	    continue;
	}
	switch (s->state) {
	case STATE_STOPPED: status = 'S'; break;
	case STATE_IDLE:    status = 'I'; break;
	case STATE_BUSY:    status = 'B'; break;
	case STATE_KILLED:  status = 'K'; break;
	}
	j = snprintf(ptr, len, "%d %c", i, status);
	len -= j;
	ptr += j;
	if (s->state != STATE_STOPPED) {
	    j = snprintf(ptr, len, " %lu", (unsigned long) s->pid);
	    len -= j;
	    ptr += j;
	}
	if (s->state == STATE_BUSY && s->cmd >= 0 && s->cmd < NUM_CMDS) {
	    j = snprintf(ptr, len, " %s", CmdName[s->cmd]);
	    len -= j;
	    ptr += j;
	}

	if (s->last_cmd >= 0 && s->last_cmd < NUM_CMDS) {
	    j = snprintf(ptr, len, " last=%s", CmdName[s->last_cmd]);
	    len -= j;
	    ptr += j;
	}

	secs = (int) (now - s->lastStateChange);
	j = snprintf(ptr, len, " ago=%d", secs);
	len -= j;
	ptr += j;
	if (s->status_tag[0]) {
	    j = snprintf(ptr, len, " (%s)", s->status_tag);
	    len -= j;
	    ptr += j;
	}
	j = snprintf(ptr, len, "\n");
	len -= j;
	ptr += j;
    }
    reply_to_mimedefang(es, fd, ans);
    free(ans);
}

/**********************************************************************
* %FUNCTION: doStatus
* %ARGUMENTS:
*  es -- event selector
*  fd -- socket
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Prints a status string back.  Each char corresponds to a worker;
*  the chars are:
*  S -- worker is stopped
*  I -- worker is idle
*  B -- worker is busy
*  K -- worker is killed but not yet reaped.
***********************************************************************/
static void
doStatus(EventSelector *es, int fd)
{
    char *ans = malloc(Settings.maxWorkers + 2 + 300);
    int i;

    if (!ans) {
	reply_to_mimedefang(es, fd, "error: Out of memory\n");
	return;
    }

    for (i=0; i < Settings.maxWorkers; i++) {
	Worker *s = &AllWorkers[i];
	switch (s->state) {
	case STATE_STOPPED: ans[i] = 'S'; break;
	case STATE_IDLE:    ans[i] = 'I'; break;
	case STATE_BUSY:    ans[i] = 'B'; break;
	case STATE_KILLED:  ans[i] = 'K'; break;
	default:            ans[i] = '?';
	}
    }
    sprintf(ans + Settings.maxWorkers, " %d %d %d %d %d\n", NumMsgsProcessed, Activations, Settings.requestQueueSize, NumQueuedRequests, (int) (time(NULL) - TimeOfProgramStart));
    reply_to_mimedefang(es, fd, ans);
    free(ans);
}

/**********************************************************************
* %FUNCTION: doHelp
* %ARGUMENTS:
*  es -- event selector
*  fd -- socket
*  unpriv -- true on unprivileged socket; print raw help
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Prints a help string listing commands the multiplexor accepts.
***********************************************************************/
static void
doHelp(EventSelector *es, int fd, int unpriv)
{
    if (unpriv) {
	reply_to_mimedefang(es, fd,
	"help             -- List available multiplexor commands\n"
	"free             -- Display number of free workers\n"
	"load             -- Display worker load (scans)\n"
	"rawload          -- Display worker load in computer-readable format\n"
	"load1 secs       -- Display worker load in alternate format\n"
	"jsonload1 secs   -- Display worker load in JSON format\n"
	"rawload1 secs    -- Display worker load in computer-readable alternate format\n"
	"load-relayok     -- Display load (relayok requests)\n"
	"rawload-relayok  -- Computer-readable load (relayok requests)\n"
	"load-senderok    -- Display load (senderok requests)\n"
	"rawload-senderok -- Computer-readable load (senderok requests)\n"
	"load-recipok     -- Display load (recipok requests)\n"
	"rawload-recipok  -- Computer-readable load (recipok requests)\n"
	"status           -- Display worker status\n"
	"jsonstatus       -- Display worker status in JSON format\n"
	"histo            -- Display histogram of busy workers\n"
	"msgs             -- Display number of messages processed since startup\n"
	"workers           -- Display workers with process-IDs\n"
	"busyworkers       -- Display busy workers with process-IDs\n"
        "workerinfo n      -- Display information about a particular worker\n"
	"(Analogous hload commands provide hourly information)\n");
    } else {
	reply_to_mimedefang(es, fd,
	"help             -- List available multiplexor commands\n"
	"status           -- Display worker status\n"
	"rawstatus        -- Display worker status in computer-readable format\n"
	"barstatus        -- Display worker status as bar graph\n"
	"free             -- Display number of free workers\n"
	"load             -- Display worker load (scans)\n"
	"rawload          -- Display worker load in computer-readable format\n"
	"load1 secs       -- Display worker load in alternate format\n"
	"jsonload1 secs   -- Display worker load in JSON format\n"
	"rawload1 secs    -- Display worker load in alternate format\n"
	"load-relayok     -- Display load (relayok requests)\n"
	"rawload-relayok  -- Computer-readable load (relayok requests)\n"
	"load-senderok    -- Display load (senderok requests)\n"
	"rawload-senderok -- Computer-readable load (senderok requests)\n"
	"load-recipok     -- Display load (recipok requests)\n"
	"rawload-recipok  -- Computer-readable load (recipok requests)\n"
	"histo            -- Display histogram of busy workers\n"
	"msgs             -- Display number of messages processed since startup\n"
	"reread           -- Force a re-read of filter rules\n"
	"workers           -- Display workers with process-IDs\n"
	"busyworkers       -- Display busy workers with process-IDs\n"
	"workerinfo n      -- Display information about a particular worker\n"
	"scan /path       -- Run a scan (do not invoke using md-mx-ctrl)\n"
	"(Analogous hload commands provide hourly information)\n");
    }
}

static void
doLoad1(EventSelector *es, int fd, int back)
{
    char ans[1024];
    int msgs[NUM_CMDS], workers[NUM_CMDS], activated, reaped;
    BIG_INT ms[NUM_CMDS];
    double avg[NUM_CMDS], ams[NUM_CMDS];
    int counts[NUM_CMDS];
    int cmd;
    time_t now = time(NULL);
    Worker *s;

    for (cmd=MIN_CMD; cmd <= MAX_CMD; cmd++) {
	get_history_totals(cmd, now, back, &msgs[cmd], &workers[cmd], &ms[cmd], &activated, &reaped);
	if (msgs[cmd]) {
	    avg[cmd] = (double) workers[cmd] / (double) msgs[cmd];
	    ams[cmd] = (double) ms[cmd]     / (double) msgs[cmd];
	} else {
	    avg[cmd] = 0.0;
	    ams[cmd] = 0.0;
	}
    }
    memset(counts, 0, sizeof(counts));
    s = Workers[STATE_BUSY];
    while(s) {
	if (s->cmd >= MIN_CMD && s->cmd <= MAX_CMD) {
	    counts[s->cmd]++;
	}
	s = s->next;
    }

    snprintf(ans, sizeof(ans), "%d %f %f %d %f %f %d %f %f %d %f %f %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
	     msgs[SCAN_CMD],     avg[SCAN_CMD],     ams[SCAN_CMD],
	     msgs[RELAYOK_CMD],  avg[RELAYOK_CMD],  ams[RELAYOK_CMD],
	     msgs[SENDEROK_CMD], avg[SENDEROK_CMD], ams[SENDEROK_CMD],
	     msgs[RECIPOK_CMD],  avg[RECIPOK_CMD],  ams[RECIPOK_CMD],
	     WorkerCount[STATE_BUSY], WorkerCount[STATE_IDLE],
	     WorkerCount[STATE_STOPPED], WorkerCount[STATE_KILLED],
	     NumMsgsProcessed, Activations,
	     Settings.requestQueueSize, NumQueuedRequests,
	     (int)(now - TimeOfProgramStart), back,
	     counts[SCAN_CMD], counts[RELAYOK_CMD], counts[SENDEROK_CMD], counts[RECIPOK_CMD]);
    reply_to_mimedefang(es, fd, ans);
}

/**********************************************************************
* %FUNCTION: doLoad
* %ARGUMENTS:
*  es -- event selector
*  fd -- socket
*  cmd -- which command's history we want
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Prints a load string back.  This string is a list of numbers:
*
*    msgs_0 msgs_1 msgs_5 msgs_10
*    avg_0 avg_1 avg_5 avg_10
*    ams_0 ams_1 ams_5 ams_10
*    a0 a1 a5 a10
*    r0 r1 r5 r10
*    busy idle stopped killed
*    msgs_processed total_activations
*    request_queue_size num_queued_requests seconds_since_program_start
*
*    Note for below:  If N=0, then time frame is last 10 seconds.
*    msgs_N -- Number of messages processed in last N minutes.
*    avg_N  -- Average number of busy workers when msg processed
*    ams_N  -- Average scan time in milliseconds
*    aN     -- Number of workers activated in last N minutes
*    rN     -- Number of workers reaped in last N minutes
*    busy idle stopped killed -- Snapshot of # workers in each status
*    msgs_processed -- Total msgs processed since startup
*    total_activations -- Total worker activations since startup
*    request_queue_size -- size of queue
*    num_queued_requests -- number of requests on queue
*    seconds_since_program_start -- just what it says!
*
* NOTE: Activations and reaps (aN, rN) are only valid if cmd == SCAN_CMD
***********************************************************************/
static void
doLoad(EventSelector *es, int fd, int cmd)
{
    char ans[1024];
    time_t now = time(NULL);
    int msgs_0, msgs_1, msgs_5, msgs_10, worker_0, worker_1, worker_5, worker_10;
    BIG_INT ms_0, ms_1, ms_5, ms_10;
    int a0, a1, a5, a10; /* Activations */
    int r0, r1, r5, r10; /* Reaps */
    double ams_0, ams_1, ams_5, ams_10;
    double avg_0, avg_1, avg_5, avg_10;

    /* Tricky... get slices of history so as not to overlap */

    /*                       start     go_back_by  results....                 */
    get_history_totals(cmd, now,      10,         &msgs_0,  &worker_0,  &ms_0,  &a0,  &r0);
    get_history_totals(cmd, now-10,   1*60-10,    &msgs_1,  &worker_1,  &ms_1,  &a1,  &r1);
    get_history_totals(cmd, now-1*60, 5*60-1*60,  &msgs_5,  &worker_5,  &ms_5,  &a5,  &r5);
    get_history_totals(cmd, now-5*60, 10*60-5*60, &msgs_10, &worker_10, &ms_10, &a10, &r10);

    /* Accumulate partial sums */
    msgs_1 += msgs_0;
    worker_1 += worker_0;
    ms_1 += ms_0;
    a1 += a0;
    r1 += r0;

    msgs_5 += msgs_1;
    worker_5 += worker_1;
    ms_5 += ms_1;
    a5 += a1;
    r5 += r1;

    msgs_10 += msgs_5;
    worker_10 += worker_5;
    ms_10 += ms_5;
    a10 += a5;
    r10 += r5;

    if (!msgs_0) avg_0 = 1.0;
    else avg_0 = (double) worker_0 / (double) msgs_0;

    if (!msgs_1) avg_1 = 1.0;
    else avg_1 = (double) worker_1 / (double) msgs_1;

    if (!msgs_5) avg_5 = 1.0;
    else avg_5 = (double) worker_5 / (double) msgs_5;

    if (!msgs_10) avg_10 = 1.0;
    else avg_10 = (double) worker_10 / (double) msgs_10;

    if (!msgs_0) ams_0 = 0.0;
    else ams_0 = (double) ms_0 / (double) msgs_0;

    if (!msgs_1) ams_1 = 0.0;
    else ams_1 = (double) ms_1 / (double) msgs_1;

    if (!msgs_5) ams_5 = 0.0;
    else ams_5 = (double) ms_5 / (double) msgs_5;

    if (!msgs_10) ams_10 = 0.0;
    else ams_10 = (double) ms_10 / (double) msgs_10;

    snprintf(ans, sizeof(ans), "%d %d %d %d %f %f %f %f %f %f %f %f %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
	     msgs_0, msgs_1, msgs_5, msgs_10, avg_0, avg_1, avg_5, avg_10,
	     ams_0, ams_1, ams_5, ams_10, a0, a1, a5, a10, r0, r1, r5, r10,
	     WorkerCount[STATE_BUSY],
	     WorkerCount[STATE_IDLE],
	     WorkerCount[STATE_STOPPED],
	     WorkerCount[STATE_KILLED],
	     NumMsgsProcessed, Activations,
	     Settings.requestQueueSize, NumQueuedRequests,
	     (int)(now - TimeOfProgramStart));
    reply_to_mimedefang(es, fd, ans);
}

/**********************************************************************
* %FUNCTION: doHourlyLoad
* %ARGUMENTS:
*  es -- event selector
*  fd -- socket
*  cmd -- which command's history we want
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Prints a load string back.  This string is a list of numbers:
*
*    msgs_1 msgs_4 msgs_12 msgs_24  - #msgs in last N hours
*    avg_1 avg_4 avg_12 avg_24      - Avg workers/cmd last N hours
*    ams_1 ams_4 ams_12 ams_24      - Avg ms/cmd last N hours
*    secs_1 secs_4 secs_12 secs_24  - Total elapsed seconds in output
***********************************************************************/
static void
doHourlyLoad(EventSelector *es, int fd, int cmd)
{
    int msgs_1, msgs_4, msgs_12, msgs_24;
    double ams_1, ams_4, ams_12, ams_24;
    double avg_1, avg_4, avg_12, avg_24;
    int secs_1, secs_4, secs_12, secs_24;
    int workers;
    BIG_INT ms;

    char ans[1024];
    time_t now = time(NULL);

    get_hourly_history_totals(cmd, now, 1, &msgs_1, &workers, &ms, &secs_1);
    if (msgs_1) {
	avg_1 = ((double) workers) / ((double) msgs_1);
	ams_1 = ((double) ms) / ((double) msgs_1);
    } else {
	avg_1 = 0.0;
	ams_1 = 0.0;
    }

    get_hourly_history_totals(cmd, now, 4, &msgs_4, &workers, &ms, &secs_4);
    if (msgs_4) {
	avg_4 = ((double) workers) / ((double) msgs_4);
	ams_4 = ((double) ms) / ((double) msgs_4);
    } else {
	avg_4 = 0.0;
	ams_4 = 0.0;
    }

    get_hourly_history_totals(cmd, now, 12, &msgs_12, &workers, &ms, &secs_12);
    if (msgs_12) {
	avg_12 = ((double) workers) / ((double) msgs_12);
	ams_12 = ((double) ms) / ((double) msgs_12);
    } else {
	avg_12 = 0.0;
	ams_12 = 0.0;
    }

    get_hourly_history_totals(cmd, now, 24, &msgs_24, &workers, &ms, &secs_24);
    if (msgs_24) {
	avg_24 = ((double) workers) / ((double) msgs_24);
	ams_24 = ((double) ms) / ((double) msgs_24);
    } else {
	avg_24 = 0.0;
	ams_24 = 0.0;
    }
    snprintf(ans, sizeof(ans), "%d %d %d %d %f %f %f %f %f %f %f %f %d %d %d %d\n",
	     msgs_1, msgs_4, msgs_12, msgs_24,
	     avg_1, avg_4, avg_12, avg_24,
	     ams_1, ams_4, ams_12, ams_24,
	     secs_1, secs_4, secs_12, secs_24);
    reply_to_mimedefang(es, fd, ans);
}

/**********************************************************************
* %FUNCTION: doHistogram
* %ARGUMENTS:
*  es -- event selector
*  fd -- socket
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Prints the histogram like this:
*  1 num1
*  2 num2
*  .......
*  N numN
*
* Each "numI" is the number of times "I" workers were busy.
***********************************************************************/
static void
doHistogram(EventSelector *es, int fd)
{
  /* Allow 20 bytes/entry - two 9-digit numbers, a space and a carriage-return
   */
  int i;
  size_t roomleft = (size_t) (Settings.maxWorkers * 20);
  char *ans = malloc(roomleft + 1);
  char *pos = ans;

  if (!ans) {
    reply_to_mimedefang(es, fd, "error: Out of memory\n");
    return;
  }


  for (i=0; i<Settings.maxWorkers; i++) {
    int count = snprintf(pos, roomleft, "%4d %u\n", i+1,
			 AllWorkers[i].histo);
    if (count < 0 || count >= roomleft) {
      free(ans);
      reply_to_mimedefang(es, fd, "error: String too long\n");
      return;
    }
    pos += count;
    roomleft -= count;
  }
  reply_to_mimedefang(es, fd, ans);
  free(ans);
}


/**********************************************************************
* %FUNCTION: findFreeWorker
* %ARGUMENTS:
*  cmdno -- the command number.  One of: OTHER_CMD, SCAN_CMD,
*           RELAYOK_CMD, SENDEROK_CMD, or RECIPOK_CMD
* %RETURNS:
*  A pointer to a free worker, or NULL if none found.  Prefers to
*  return a running worker rather than one which needs activation.  Also,
*  prefers to return the worker which has been running the longest since
*  activation.  Also prefers to pick a worker that last ran the same
*  command as cmdno
* %DESCRIPTION:
*  Finds a free (preferably running) worker.
***********************************************************************/
static Worker *
findFreeWorker(int cmdno)
{
    Worker *s = Workers[STATE_IDLE];
    Worker *best = s;
    Worker *best_same_cmd = NULL;
    while(s) {
	if (s->activated < best->activated) {
	    best = s;
	}
	if (s->last_cmd == cmdno || s->last_cmd == NO_CMD) {
	    if (!best_same_cmd) {
		best_same_cmd = s;
	    } else if (best_same_cmd->last_cmd != cmdno ||
		       s->activated < best_same_cmd->activated) {
		best_same_cmd = s;

	    }
	}
	s = s->next;
    }

    if (best_same_cmd) {
	best = best_same_cmd;
    }

    if (!best) {
	/* No running workers - just pick the first stopped worker */
	best = Workers[STATE_STOPPED];
    }
    if (best) {
	best->status_tag[0] = 0;
	best->cmd = -1;
    }

    if (Settings.debugWorkerScheduling && best) {
	syslog(LOG_INFO, "Scheduling %s worker %d for cmdno %d (activated=%d, last=%d)",
	       state_name(best->state), WORKERNO(best), cmdno, best->activated, best->last_cmd);
    }
    return best;
}

/**********************************************************************
* %FUNCTION: log_worker_resource_usage
* %ARGUMENTS:
*  s -- worker
*  usage -- struct rusage with worker's resource usage.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Logs worker's resource usage.
***********************************************************************/
#ifdef HAVE_WAIT3
static void
log_worker_resource_usage(Worker *s,
			 struct rusage *usage)
{
    if (!DOLOG) return;
    syslog(LOG_INFO,
	   "Worker %d resource usage: req=%d, scans=%d, user=%d.%03d, "
	   "sys=%d.%03d, nswap=%ld, majflt=%ld, minflt=%ld, "
	   "maxrss=%ld, bi=%ld, bo=%ld",
	   WORKERNO(s),
	   s->numRequests,
	   s->numScans,
	   (int) usage->ru_utime.tv_sec,
	   (int) usage->ru_utime.tv_usec / 1000,
	   (int) usage->ru_stime.tv_sec,
	   (int) usage->ru_stime.tv_usec / 1000,
	   usage->ru_nswap,
	   usage->ru_majflt,
	   usage->ru_minflt,
	   usage->ru_maxrss,
	   usage->ru_inblock,
	   usage->ru_oublock);
}
#endif

static void handleMapAccept(EventSelector *es, int fd);
static void got_map_request(EventSelector *es, int fd,
			    char *buf, int len, int flag, void *data);

static void
handle_worker_received_map_command(EventSelector *es,
				  int fd,
				  char *buf,
				  int len,
				  int flag,
				  void *data);

static void
receive_worker_map_answer(EventSelector *es,
			 int fd,
			 char *buf,
			 int len,
			 int flag,
			 void *data);

static void
sent_map_reply(EventSelector *es,
	       int fd,
	       char *buf,
	       int len,
	       int flag,
	       void *data)
{
    if (!EventTcp_ReadNetstring(es, fd, got_map_request, 0, NULL)) {
	syslog(LOG_ERR, "sent_map_reply: EventTcp_ReadNetstring failed: %m");
	close(fd);
    }
}
/**********************************************************************
* %FUNCTION: reply_to_map_with_len
* %ARGUMENTS:
*  es -- event selector
*  fd -- file descriptor
*  msg -- message to send back
*  len -- length of message
* %RETURNS:
*  The event associated with the reply, or NULL.
* %DESCRIPTION:
*  Sends a final message back to map.
***********************************************************************/
static EventTcpState *
reply_to_map_with_len(EventSelector *es,
			     int fd,
			     char const *msg,
			     int len)
{
    EventTcpState *e;
    e = EventTcp_WriteNetstring(es, fd, msg, len, sent_map_reply,
				Settings.clientTimeout, NULL);
    if (!e) {
	if (DOLOG) {
	    syslog(LOG_ERR, "reply_to_map: EventTcp_WriteBuf failed: %m");
	}
	close(fd);
    }
    return e;
}

/**********************************************************************
* %FUNCTION: reply_to_map
* %ARGUMENTS:
*  es -- event selector
*  fd -- file descriptor
*  msg -- message to send back
* %RETURNS:
*  The event associated with the reply, or NULL.
* %DESCRIPTION:
*  Sends a final message back to map.
***********************************************************************/
static EventTcpState *
reply_to_map(EventSelector *es,
		    int fd,
		    char const *msg)
{
    return reply_to_map_with_len(es, fd, msg, strlen(msg));
}

/**********************************************************************
* %FUNCTION: handleMapAccept
* %ARGUMENTS:
*  es -- event selector
*  fd -- accepted connection
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a connection attempt for TCP map.  Sets up to read requests.
***********************************************************************/
static void
handleMapAccept(EventSelector *es,
		int fd)
{
    if (!EventTcp_ReadNetstring(es, fd, got_map_request, 0, NULL)) {
	syslog(LOG_ERR, "handleMapAccept: EventTcp_ReadNetstring failed: %m");
	close(fd);
    }
}

/**********************************************************************
* %FUNCTION: got_request
* %ARGUMENTS:
*  es -- event selector
*  fd -- connection from Sendmail map reader
*  buf -- map request
*  len -- length of map request
*  flag -- flag from reader
*  data -- ignored
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a received map command.
***********************************************************************/
static void
got_map_request(EventSelector *es,
	    int fd,
	    char *buf,
	    int len,
	    int flag,
	    void *data)
{
    Worker *s;
    char *cmd, *oldcmd;
    char *t;

    if (flag == EVENT_TCP_FLAG_TIMEOUT ||
	flag == EVENT_TCP_FLAG_IOERROR ||
	flag == EVENT_TCP_FLAG_EOF) {
	close(fd);
	return;
    }

    /* Chop off comma */
    if (len && buf[len-1] == ',') {
	buf[len-1] = 0;
	len--;
    } else {
	reply_to_map(es, fd, "PERM Netstring missing terminating comma");
	return;
    }

    /* Convert the command to something we can use */
    cmd = malloc(len*3+1 + 4 + 3);

    if (!cmd) {
	reply_to_map(es, fd, "TEMP Out of memory");
	return;
    }

    t = buf;
    while(*t && (*t != ' ')) t++;
    if (*t != ' ') {
	free(cmd);
	reply_to_map(es, fd, "PERM Invalid request format");
	return;
    }

    *t = 0;
    oldcmd = cmd;
    strcpy(cmd, "map ");
    cmd += 4;
    cmd += percent_encode(buf, cmd, len*3+1);
    *cmd++ = ' ';
    cmd += percent_encode(t+1, cmd, len*3+1+4 - (cmd - oldcmd));
    *cmd++ = '\n';
    *cmd = 0;
    cmd = oldcmd;

    /* Send the request to a worker */
    s = findFreeWorker(OTHER_CMD);
    if (!s) {
	free(cmd);
	reply_to_map(es, fd, "TEMP No free workers");
	return;
    }
    if (activateWorker(s, "About to handle map request") == (pid_t) -1) {
	free(cmd);
	syslog(LOG_WARNING, "map command failed: No free workers");
	reply_to_map(es, fd, "TEMP Unable to activate worker");
	return;
    }
    putOnList(s, STATE_BUSY);
    s->clientFD = fd;
    s->workdir[0] = 0;
    set_worker_status_from_command(s, cmd);
    s->event = EventTcp_WriteBuf(es, s->workerStdin, cmd, strlen(cmd),
				 handle_worker_received_map_command,
				 Settings.clientTimeout, s);
    free(cmd);
    if (!s->event) {
	if (DOLOG) syslog(LOG_ERR, "got_map_request: EventTcp_WriteBuf failed: %m");
	s->clientFD = -1; /* Do not close FD */
	killWorker(s, "EventTcp_WriteBuf failed");
	reply_to_map(es, fd, "TEMP Could not send command to worker");
    }
}

static void
handle_worker_received_map_command(EventSelector *es,
				  int fd,
				  char *buf,
				  int len,
				  int flag,
				  void *data)
{
    Worker *s = (Worker *) data;

    /* Event was triggered */
    s->event = NULL;

    if (flag == EVENT_TCP_FLAG_TIMEOUT || flag == EVENT_TCP_FLAG_IOERROR) {
	reply_to_map(es, s->clientFD, "TEMP Error talking to worker process");

	s->clientFD = -1;
	/* Kill the worker process */
	killWorker(s, "Error talking to worker process");
	return;
    }

    /* Worker has been given the command; now wait for it to reply */
    s->event = EventTcp_ReadBuf(es, s->workerStdout, MAX_CMD_LEN, '\n',
				receive_worker_map_answer,
				Settings.busyTimeout, 1, s);
    if (!s->event) {
	if (DOLOG) syslog(LOG_ERR, "handleWorkerReceivedCommand: EventTcp_ReadBuf failed: %m");
	reply_to_map(es, s->clientFD, "TEMP Error talking to worker process");
	s->clientFD = -1;

	killWorker(s, "EventTcp_ReadBuf failed");
    }
}

static void
receive_worker_map_answer(EventSelector *es,
			 int fd,
			 char *buf,
			 int len,
			 int flag,
			 void *data)
{
    Worker *s = (Worker *) data;
    s->event = NULL;

    if (!len || (flag == EVENT_TCP_FLAG_TIMEOUT)) {
	reply_to_map(es, s->clientFD, "TEMP Busy timeout on worker");
	s->clientFD = -1;
	killWorker(s, "Busy timeout");
	return;
    }

    /* Remove newline at end */
    if (buf[len-1] == '\n') {
	buf[len-1] = 0;
    }

    /* Send the answer back */
    percent_decode(buf);
    reply_to_map(es, s->clientFD, buf);

    s->clientFD = -1;
    s->numRequests++;
    putOnList(s, STATE_IDLE);
    s->idleTime = time(NULL);
    checkWorkerForExpiry(s);
}


static void
enqueue_request(Request *slot)
{
    NumQueuedRequests++;
    slot->next = NULL;
    if (!RequestHead) {
	RequestHead = slot;
	RequestTail = slot;
    } else {
	/* Assert that RequestTail != NULL */
	RequestTail->next = slot;
	RequestTail = slot;
    }
}

static void
dequeue_request(Request *slot)
{
    Request *prev;

    NumQueuedRequests--;
    if (slot == RequestHead) {
	RequestHead = RequestHead->next;
	if (!RequestHead) {
	    RequestTail = NULL;
	}
	/* Safety... */
	slot->next = NULL;
	return;
    }
    prev = RequestHead;
    while (prev->next && prev->next != slot) {
	prev = prev->next;
    }
    if (prev->next == slot) {
	prev->next = slot->next;
	if (slot == RequestTail) {
	    RequestTail = prev;
	}
    }
    /* Safety... */
    slot->next = NULL;
}

/**********************************************************************
* %FUNCTION: queue_request
* %ARGUMENTS:
*  es -- event selector
*  fd -- client file descriptor
*  cmd -- command to queue
* %RETURNS:
*  1 if request is successfully queued; 0 if not.
* %DESCRIPTION:
*  Queues a request if all workers are temporarily busy.  Queue is
*  handled in FIFO order as workers become free.
***********************************************************************/
int
queue_request(EventSelector *es, int fd, char *cmd)
{
    Request *slot = NULL;
    int i;
    struct timeval t;

    if (NumQueuedRequests >= Settings.requestQueueSize) {
	if (DOLOG) {
	    syslog(LOG_INFO, "Cannot queue request: request queue is full");
	}
	return 0;
    }

    /* Find a free request slot */
    for (i=0; i<Settings.requestQueueSize; i++) {
	if (RequestQueue[i].fd == -1) {
	    slot = &RequestQueue[i];
	    break;
	}
    }

    if (!slot) {
	if (DOLOG) {
	    syslog(LOG_ERR, "Cannot queue request: Unable to find free slot!");
	}
	return 0;
    }

    slot->cmd = strdup(cmd);
    if (!slot->cmd) {
	if (DOLOG) {
	    syslog(LOG_ERR, "Cannot queue request: Out of memory!");
	}
	return 0;
    }

    t.tv_usec = 0;
    t.tv_sec = Settings.requestQueueTimeout;
    slot->timeoutHandler = Event_AddTimerHandler(es, t,
						 handleRequestQueueTimeout,
						 slot);
    if (!slot->timeoutHandler) {
	free(slot->cmd);
	if (DOLOG) {
	    syslog(LOG_ERR, "Cannot queue request: Out of memory!");
	}
	return 0;
    }
    slot->fd = fd;
    slot->es = es;
    enqueue_request(slot);
    if (DOLOG) {
	syslog(LOG_INFO, "All workers are busy: Queueing request (%d queued)",
	       NumQueuedRequests);
    }
    return 1;
}

/**********************************************************************
* %FUNCTION: handleRequestQueueTimeout
* %ARGUMENTS:
*  es -- event selector
*  fd -- ignored
*  flags -- ignored
*  data -- the queued request that timed out
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a queue timeout -- sends error back to client
***********************************************************************/
static void
handleRequestQueueTimeout(EventSelector *es,
			  int fd,
			  unsigned int flags,
			  void *data)
{
    Request *slot = (Request *) data;
    fd = slot->fd;

    free(slot->cmd);
    slot->cmd = NULL;
    slot->fd = -1;
    slot->timeoutHandler = NULL;
    dequeue_request(slot);
    reply_to_mimedefang(es, fd, "error: Queued request timed out\n");
}

/**********************************************************************
* %FUNCTION: handle_queued_request
* %ARGUMENTS:
*  None
* %RETURNS:
*  1 if a queued request is waiting and was passed off to a worker; 0
*  otherwise.
* %DESCRIPTION:
*  Checks the queue for pending requests.
***********************************************************************/
static int
handle_queued_request(void)
{
    Request *slot = RequestHead;
    int len;

    if (!slot) return 0;
    dequeue_request(slot);
    Event_DelHandler(slot->es, slot->timeoutHandler);
    slot->timeoutHandler = NULL;
    len = strlen(slot->cmd);
    if (len > 5 && !strncmp(slot->cmd, "scan ", 5)) {
	doScanAux(slot->es, slot->fd, slot->cmd, 0);
    } else {
	doWorkerCommandAux(slot->es, slot->fd, slot->cmd, 0);
    }
    slot->es = NULL;
    slot->fd = -1;
    free(slot->cmd);
    slot->cmd = NULL;
    return 1;
}

/**********************************************************************
* %FUNCTION: do_tick
* %ARGUMENTS:
*  es -- event selector
*  fd, flags -- ignored
*  data -- really the tick number in disguise
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called periodically to run a "tick" request.
***********************************************************************/
static void
do_tick(EventSelector *es,
	int fd,
	unsigned int flags,
	void *data)
{
    Worker *s;
    char buffer[128];

    /* Ugly */
    int tick_no = (int) ((long) data);

    s = findFreeWorker(OTHER_CMD);
    if (!s) {
	if (DOLOG) {
	    syslog(LOG_WARNING, "Tick %d skipped -- no free workers", tick_no);
	}
	schedule_tick(es, tick_no);
	return;
    }
    if (activateWorker(s, "About to run tick") == (pid_t) -1) {
	if (DOLOG) {
	    syslog(LOG_WARNING, "Tick %d skipped -- unable to activate worker %d",
		   tick_no,
		   WORKERNO(s));
	}
	schedule_tick(es, tick_no);
	return;
    }

    putOnList(s, STATE_BUSY);
    s->clientFD = -1;
    s->tick_no = tick_no;
    sprintf(buffer, "tick %d", tick_no);
    strncpy(s->status_tag, buffer, MAX_STATUS_LEN);
    s->status_tag[MAX_STATUS_LEN-1] = 0;
    sprintf(buffer, "tick %d\n", tick_no);
    s->event = EventTcp_WriteBuf(es, s->workerStdin, buffer, strlen(buffer),
				 handleWorkerReceivedTick,
				 Settings.clientTimeout, s);
    if (!s->event) {
	if (DOLOG) {
	    syslog(LOG_WARNING, "Tick %d skipped -- EventTcp_WriteBuf failed: %m", tick_no);
	}
	killWorker(s, "EventTcp_WriteBuf failed");
	schedule_tick(es, tick_no);
    }
}

/**********************************************************************
* %FUNCTION: handleWorkerReceivedTick
* %ARGUMENTS:
*  es -- event selector
*  fd -- not used
*  buf -- buffer of data read from multiplexor
*  len -- amount of data read from multiplexor
*  flag -- flag from reader
*  data -- the worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called when "tick\n" has been written to worker.  Sets up an event handler
*  to read the worker's reply
***********************************************************************/
static void
handleWorkerReceivedTick(EventSelector *es,
			   int fd,
			   char *buf,
			   int len,
			   int flag,
			   void *data)
{
    Worker *s = (Worker *) data;

    /* Event was triggered */
    s->event = NULL;

    if (flag == EVENT_TCP_FLAG_TIMEOUT || flag == EVENT_TCP_FLAG_IOERROR) {
	if (DOLOG) {
	    syslog(LOG_ERR, "handleWorkerReceivedTick(%d): Timeout or error: Flag = %d: %m",
		   WORKERNO(s),
		   flag);
	}
	/* Kill the worker process */
	killWorker(s, "Error talking to worker process");
	schedule_tick(es, s->tick_no);
	return;
    }

    /* Worker has been given the command; now wait for it to reply */
    s->event = EventTcp_ReadBuf(es, s->workerStdout, MAX_CMD_LEN, '\n',
				handleWorkerReceivedAnswerFromTick,
				Settings.busyTimeout, 1, s);
    if (!s->event) {
	if (DOLOG) syslog(LOG_ERR, "handleWorkerReceivedTick: EventTcp_ReadBuf failed: %m");
	killWorker(s, "EventTcp_ReadBuf failed");
	schedule_tick(es, s->tick_no);
    }
}

/**********************************************************************
* %FUNCTION: handleWorkerReceivedAnswerFromTick
* %ARGUMENTS:
*  es -- event selector
*  fd -- not used
*  buf -- buffer of data read
*  len -- amount of data read
*  flag -- flag from reader
*  data -- the worker
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called when the worker's answer comes back from the "tick" request
***********************************************************************/
static void
handleWorkerReceivedAnswerFromTick(EventSelector *es,
				  int fd,
				  char *buf,
				  int len,
				  int flag,
				  void *data)
{
    Worker *s = (Worker *) data;

    /* Event was triggered */
    s->event = NULL;

    /* We don't care how the worker replied. */

    s->numRequests++;

    /* If we had a busy timeout, kill the worker */
    if (flag == EVENT_TCP_FLAG_TIMEOUT) {
	killWorker(s, "Busy timeout");
    } else {
	/* Put worker on free list */
	putOnList(s, STATE_IDLE);

	/* Record time when this worker became idle */
	s->idleTime = time(NULL);

	/* Check worker for expiry */
	checkWorkerForExpiry(s);
    }

    /* And reschedule another tick request */
    schedule_tick(es, s->tick_no);
}

/**********************************************************************
* %FUNCTION: schedule_tick
* %ARGUMENTS:
*  es -- event selector
*  tick_no -- tick number
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Schedules a "tick" command for tick_interval seconds in the future,
*  if tick_interval is non-zero
***********************************************************************/
static void
schedule_tick(EventSelector *es,
	      int tick_no)
{
    struct timeval t;

    if (Settings.tick_interval <= 0) {
	return;
    }

    t.tv_usec = 0;
    t.tv_sec = Settings.tick_interval;
    if (!Event_AddTimerHandler(es, t, do_tick, (void *) ((long) tick_no))) {
	syslog(LOG_CRIT, "Unable to schedule tick handler!  Event_AddTimerHandler failed!");
    }
}

/**********************************************************************
* %FUNCTION: init_history
* %ARGUMENTS:
*  None
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Resets all history bucket entries to zero
***********************************************************************/
static void
init_history(void)
{
    memset(history, 0, sizeof(history));
    memset(hourly_history, 0, sizeof(hourly_history));
}

/**********************************************************************
* %FUNCTION: get_history_bucket
* %ARGUMENTS:
*  cmd -- which command's buckets we want
* %RETURNS:
*  A pointer to an initialized history bucket ready for incrementing counters
* %DESCRIPTION:
*  Determines current bucket and initializes it if required.
***********************************************************************/
static HistoryBucket *
get_history_bucket(int cmd)
{
    time_t now = time(NULL);
    int bucket = ((int) now) % HISTORY_SECONDS;
    HistoryBucket *b = &(history[cmd][bucket]);
    if (b->elapsed != now) {
	b->elapsed = now;
	b->count = 0;
	b->workers = 0;
	b->ms = 0;
	b->activated = 0;
	b->reaped = 0;
    }
    return b;
}

/**********************************************************************
* %FUNCTION: get_hourly_history_bucket
* %ARGUMENTS:
*  cmd -- which command's buckets we want
* %RETURNS:
*  A pointer to an initialized history bucket ready for incrementing counters
* %DESCRIPTION:
*  Determines current bucket and initializes it if required.
***********************************************************************/
static HistoryBucket *
get_hourly_history_bucket(int cmd)
{
    time_t now = time(NULL);
    int hour = ((int) now) / 3600;
    int bucket = hour % HISTORY_HOURS;
    HistoryBucket *b = &(hourly_history[cmd][bucket]);
    if (b->elapsed != hour) {
	b->first = now;
	b->elapsed = hour;
	b->count = 0;
	b->workers = 0;
	b->ms = 0;
	b->activated = 0;
	b->reaped = 0;
    }
    b->last = now;
    return b;
}

/**********************************************************************
* %FUNCTION: get_history_totals
* %ARGUMENTS:
*  cmd -- which command's buckets we want
*  now -- current time
*  back -- how many seconds to go back from current time
*  total -- set to total count of messages
*  workers -- set to total worker count.  Average number of busy workers/msg
*            is given by workers / total.
*  ms -- set to total scan time in milliseconds
*  activated -- set to number of workers activated
*  reaped -- set to number of workers reaped
* %RETURNS:
*  0 if all is OK, -1 otherwise.
***********************************************************************/
static int
get_history_totals(int cmd,
		   time_t now, int back, int *total, int *workers, BIG_INT *ms,
		   int *activated, int *reaped)
{
    int start = ((int) now) - back + 1;
    int end = (int) now;
    int i, bucket;

    *total = 0;
    *workers = 0;
    *ms = 0;
    *activated = 0;
    *reaped = 0;

    if (back <= 0) return 0;
    if (back > HISTORY_SECONDS) return -1;

    for (i = start; i <= end; i++) {
	bucket = i % HISTORY_SECONDS;
	if (history[cmd][bucket].elapsed == i) {
	    (*total)  += history[cmd][bucket].count;
	    (*workers) += history[cmd][bucket].workers;
	    (*ms)     += history[cmd][bucket].ms;
	    (*activated) += history[cmd][bucket].activated;
	    (*reaped) += history[cmd][bucket].reaped;
	}
    }
    return 0;
}

/**********************************************************************
* %FUNCTION: get_hourly_history_totals
* %ARGUMENTS:
*  cmd -- which command's buckets we want
*  now -- current time
*  hours -- how many hours to go back (1-24)
*  total -- set to total count of messages
*  workers -- set to total worker count.  Average number of busy workers/msg
*            is given by workers / total.
*  ms -- set to total scan time in milliseconds
*  secs -- set to actual number of elapsed seconds between first and last
*          entries
* %RETURNS:
*  0 if all is OK, -1 otherwise.
***********************************************************************/
static int
get_hourly_history_totals(int cmd, time_t now, int hours,
			  int *total, int *workers, BIG_INT *ms,
			  int *secs)
{
    int end = ((int) now) / 3600;
    int start;

    int max_sec = -1;
    int min_sec = -1;

    int i, bucket;

    *total = 0;
    *workers = 0;
    *ms = 0;
    *secs = 0;

    if (hours <= 0) {
	return 0;
    }
    if (hours > 24) {
	return -1;
    }

    start = end - hours + 1;

    for (i = start; i <= end; i++) {
	HistoryBucket *b;
	bucket = i % HISTORY_HOURS;
	b = &(hourly_history[cmd][bucket]);
	if (b->elapsed == i) {
	    if (min_sec == -1 || b->first < min_sec) min_sec = b->first;
	    if (b->last > max_sec) max_sec = b->last;
	    (*total)  += b->count;
	    (*workers) += b->workers;
	    (*ms)     += b->ms;
	}
    }
    if (min_sec > -1) {
	*secs = (max_sec - min_sec);
    }
    return 0;
}
