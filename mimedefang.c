/***********************************************************************
*
* mimedefang.c
*
* C interface to the attachment-filter program for stripping or altering
* MIME attachments in incoming Sendmail connections.
*
* Copyright (C) 2000-2005 Roaring Penguin Software Inc.
* http://www.roaringpenguin.com
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2, or (at your option) any later version.
*
* This program was derived from the sample mail filter included in
* libmilter/README in the Sendmail 8.11 distribution.
***********************************************************************/

#define _DEFAULT_SOURCE 1

#define MAX_ML_LINES 31

#ifdef HAVE_SOCKLEN_T
typedef socklen_t md_socklen_t;
#else
typedef int md_socklen_t;
#endif

#include "config.h"
#include "mimedefang.h"
#include "dynbuf.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <pwd.h>
#include <stdio.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libmilter/mfapi.h"
#include "milter_cap.h"

#include <sys/socket.h>
#include <sys/un.h>

/* Solaris does not define AF_LOCAL */
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

#ifdef ENABLE_DEBUGGING
#include <signal.h>
#define DEBUG(x) x
extern void *malloc_debug(void *, size_t, char const *fname, int);
extern char *strdup_debug(void *, char const *, char const *, int);
extern void free_debug(void *, void *, char const *, int);
#undef malloc
#undef strdup
#undef free
#define malloc_with_log(x) malloc_debug(ctx, x, __FILE__, __LINE__)
#define strdup_with_log(x) strdup_debug(ctx, x, __FILE__, __LINE__)
#define malloc(x) malloc_debug(ctx, x, __FILE__, __LINE__)
#define strdup(x) strdup_debug(ctx, x, __FILE__, __LINE__)
#define free(x) free_debug(ctx, x, __FILE__, __LINE__)
#else
#define DEBUG(x) (void) 0
#endif

/* If we don't have inet_ntop, we need to protect inet_ntoa with a mutex */
#ifndef HAVE_INET_NTOP
static pthread_mutex_t ntoa_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
extern int find_syslog_facility(char const *facility_name);

#define DEBUG_ENTER(func) DEBUG(syslog(LOG_DEBUG, "%p: %s(%d): ENTER %s", ctx, __FILE__, __LINE__, func))
#define DEBUG_EXIT(func, ret) DEBUG(syslog(LOG_DEBUG, "%p: %s(%d): EXIT %s: %s", ctx, __FILE__, __LINE__, func, ret))

#define SCAN_BODY "MIMEDefang " VERSION

/* Call a Milter smfi_xxxx function, but syslog if it doesn't return
 * MI_SUCCESS */
#define MD_SMFI_TRY(func, args) do { if (func args != MI_SUCCESS) syslog(LOG_WARNING, "%s: %s returned MI_FAILURE", data->qid, #func); } while (0)

char *scan_body = NULL;
static char *pidfile = NULL;
static char *lockfile = NULL;

#define KEY_FILE CONFDIR "/mimedefang-ip-key"

/* In debug mode, we do not delete working directories. */
int DebugMode = 0;

/* Conserve file descriptors by reopening files in each callback */
int ConserveDescriptors = 0;

/* Log "eom" run-times */
int LogTimes = 0;

/* Show me rejected recipients?
   (Sendmail 8.14.0 and higher only */
int SeeRejectedRecipients = 1;

/* Default Backlog for "listen" */
static int Backlog = -1;

/* Strip out bare CR characters? */
static int StripBareCR = 0;

/* Allow new connections to queue? */
static int AllowNewConnectionsToQueue = 0;

/* Is it OK to call smfi_setsymlist? */
static int setsymlist_ok = 0;

/* Run as this user */
static char *user = NULL;
extern int drop_privs(char const *user, uid_t uid, gid_t gid);

/* NOQUEUE */
static char *NOQUEUE = "NOQUEUE";

/* My IP address */
static char *MyIPAddress = NULL;

/* "Equivalent-to-loopback" address */
static char *EquivToLoopback = NULL;

/* Header name for validating IP addresses */
static char ValidateHeader[256];

/* Additional Sendmail macros to pass along */
/* Note that libmilter has a hard limit of 50
   and we include 20 in StandardSendmailMacros */
#define MAX_ADDITIONAL_SENDMAIL_MACROS 30

/* Standard Sendmail macros */
/* We can't make it char const * because libmilter
   is not const-correct. */
static char *StandardSendmailMacros[] = {
    "_", "auth_authen", "auth_author", "auth_ssf", "auth_type",
    "cert_issuer", "cert_subject", "cipher", "cipher_bits", "daemon_name",
    "daemon_port",
    "i", "if_addr", "if_name", "j", "mail_addr", "mail_host", "mail_mailer",
    "tls_version", "verify", "rcpt_addr", "rcpt_host", "rcpt_mailer",
    /* End of macros MUST be marked with NULL! */
    NULL
};

static char *AdditionalMacros[MAX_ADDITIONAL_SENDMAIL_MACROS];
static int NumAdditionalMacros = 0;

/* Keep track of private data -- file name and fp for writing e-mail body */
struct privdata {
    char *hostname;		/* Name of connecting host */
    char *hostip;		/* IP address of connecting host */
    unsigned int hostport;      /* Port of connecting host */
    char *myip;                 /* My IP address, from Sendmail macro */
    unsigned int daemon_port;   /* Daemon port from Sendmail macro */
    char *sender;		/* Envelope sender */
    char *firstRecip;		/* Address of first recipient */
    char *dir;			/* Work directory */
    char *heloArg;		/* HELO argument */
    char *qid;                  /* Queue ID */
    unsigned char qid_written;  /* Have we written qid to COMMANDS? */
    int fd;			/* File for message body */
    int headerFD;		/* File for message headers */
    int cmdFD;			/* File for commands */
    int numContentTypeHeaders;  /* How many Content-Type headers have we seen? */
    int seenMimeVersionHeader;  /* True if there was a MIME-Version header */
    unsigned char validatePresent; /* Saw a relay-address validation header */
    unsigned char suspiciousBody; /* Suspicious characters in message body? */
    unsigned char lastWasCR;	/* Last char of body chunk was CR? */
    unsigned char filterFailed; /* Filter failed */
};

static int set_queueid(SMFICTX *ctx);

static void append_macro_value(dynamic_buffer *dbuf,
			       SMFICTX *ctx,
			       char *macro);

static void append_mx_command(dynamic_buffer *dbuf,
			      char cmd,
			      char const *buf);

static int write_dbuf(dynamic_buffer *dbuf,
		      int fd,
		      struct privdata *data,
		      char const *filename);

static void append_percent_encoded(dynamic_buffer *dbuf,
				   char const *buf);
static int safe_append_header(dynamic_buffer *dbuf,
			      char *str);

static sfsistat cleanup(SMFICTX *ctx);
static sfsistat mfclose(SMFICTX *ctx);
static int do_sm_quarantine(SMFICTX *ctx, char const *reason);
static void remove_working_directory(SMFICTX *ctx, struct privdata *data);

static char const *SpoolDir = NULL;
static char const *NoDeleteDir = NULL;
static char const *MultiplexorSocketName = NULL;

static int set_reply(SMFICTX *ctx, char const *first, char const *code, char const *dsn, char const *reply);

#define DATA ((struct privdata *) smfi_getpriv(ctx))

/* Size of chunk when replacing body */
#define CHUNK 4096

/* Number of file descriptors to close when forking */
#define CLOSEFDS 256

/* Do relay check? */
static int doRelayCheck = 0;

/* Do HELO check? */
static int doHeloCheck = 0;

/* Do sender check? */
static int doSenderCheck = 0;

/* Do recipient check? */
static int doRecipientCheck = 0;

/* Keep directories around if multiplexor fails? */
static int keepFailedDirectories = 0;

/* Number of scanning workers reserved for connection from loopback */
static int workersReservedForLoopback = -1;

static void set_dsn(SMFICTX *ctx, char *buf2, int code);

#define NO_DELETE_NAME "/DO-NOT-DELETE-WORK-DIRS"

#ifdef ENABLE_DEBUGGING
/**********************************************************************
*%FUNCTION: handle_sig
*%ARGUMENTS:
* s -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Handler for SIGSEGV and SIGBUS -- logs a message and returns -- hopefully,
* we'll get a nice core dump the second time around
***********************************************************************/
static void
handle_sig(int s)
{
    syslog(LOG_ERR, "WHOA, NELLY!  Caught signal %d -- this is bad news.  Core dump at 11.", s);

    /* Default is terminate and core. */
    signal(s, SIG_DFL);

    /* Return and probably cause core dump */
}
#endif

/**********************************************************************
* %FUNCTION: get_fd
* %ARGUMENTS:
*  data -- our struct privdata
*  fname -- filename to open for writing.  Relative to work directory
*  sample_fd -- the "sample" fd from "data", if we're not conserving.
* %RETURNS:
*  A file descriptor open for writing, or -1 on failure
* %DESCRIPTION:
*  If we are NOT conserving file descriptors, simply returns sample_fd.
*  If we ARE conserving file descriptors, opens fname for writing.
***********************************************************************/
static int
get_fd(struct privdata *data,
       char const *fname,
       int sample_fd)
{
    char buf[SMALLBUF];
    if (sample_fd >= 0 && !ConserveDescriptors) return sample_fd;

    snprintf(buf, SMALLBUF, "%s/%s", data->dir, fname);
    sample_fd = open(buf, O_CREAT|O_APPEND|O_RDWR, 0640);
    if (sample_fd < 0) {
	syslog(LOG_WARNING, "%s: Could not open %s/%s: %m",
	       data->qid, data->dir, fname);
    }
    return sample_fd;
}

/**********************************************************************
* %FUNCTION: put_fd
* %ARGUMENTS:
*  fd -- file descriptor to close
* %RETURNS:
*  -1 if descriptor was closed; fd otherwise.
* %DESCRIPTION:
*  If we are NOT conserving file descriptors, simply returns fd.
*  If we ARE conserving file descriptors, closes fd and returns -1.
***********************************************************************/
static int
put_fd(int fd)
{
    if (!ConserveDescriptors) return fd;

    closefd(fd);
    return -1;
}

/**********************************************************************
* %FUNCTION: do_reply
* %ARGUMENTS:
*  ctx -- filter context
*  code -- SMTP three-digit code
*  dsn -- SMTP DSN status notification code
*  reply -- text message (MAY BE MODIFIED!)
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Called if we KNOW reply contains carriage-returns.
*  Sets the SMTP reply code and message.  If smfi_setmlreply is available,
*  call it.  Otherwise, call smfi_setreply after changing carriage-returns
*  to spaces.
***********************************************************************/
static sfsistat
do_reply(SMFICTX *ctx, char const *code, char const *dsn, char *reply)
{
    char *s;
    char *lines[MAX_ML_LINES+1];
    int i;

    /* If there are carriage returns and we don't have smfi_setmlreply,
       change them to spaces and call smfi_setreply */
#ifndef MILTER_BUILDLIB_HAS_SETMLREPLY
    for (s = reply; *s; s++) {
	if (*s == '\n') *s = ' ';
    }
    return smfi_setreply(ctx, (char *) code, (char *) dsn, reply);
#else
    /* Split on carriage-returns and pass to smfi_setmlreply */
    for (i=0; i<MAX_ML_LINES+1; i++) {
	lines[i] = NULL;
    }
    lines[0] = reply;
    s = reply;
    for (i=1; i<MAX_ML_LINES; i++) {
	s = strchr(s, '\n');
	if (!s) break;
	*s++ = 0;
	if (!*s) break;
	lines[i] = s;
    }

    /* Convert remaining newlines to spaces */
    while(s && *s) {
	if (*s == '\n') *s = ' ';
	s++;
    }

    /* Sigh... wtf were milter developers thinking??? */
    return smfi_setmlreply(ctx, (char *) code, (char *) dsn,
			   lines[0], lines[1], lines[2], lines[3],
			   lines[4], lines[5], lines[6], lines[7],
			   lines[8], lines[9], lines[10], lines[11],
			   lines[12], lines[13], lines[14], lines[15],
			   lines[16], lines[17], lines[18], lines[19],
			   lines[20], lines[21], lines[22], lines[23],
			   lines[24], lines[25], lines[26], lines[27],
			   lines[28], lines[29], lines[30], lines[31]);
#endif
}
/**********************************************************************
* %FUNCTION: set_reply
* %ARGUMENTS:
*  ctx -- filter context
*  first -- digit with which code must start
*  code -- SMTP three-digit code
*  dsn -- SMTP DSN status notification code
*  reply -- text message
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sets the SMTP reply code and message.  code and dsn are validated.
***********************************************************************/
static sfsistat
set_reply(SMFICTX *ctx,
	  char const *first,
	  char const *code,
	  char const *dsn,
	  char const *reply)
{
    char *safe_reply;

    char stack_safe_reply[SMALLBUF];

    sfsistat retcode;
    char const *s;
    char *t;
    int len;

    if (!reply || !*reply) {
	if (*first == '4') {
	    reply = "Please try again later";
	} else {
	    reply = "Forbidden for policy reasons";
	}
    }
    if (!validate_smtp_code(code, first)) {
	if (*first == '4') code = "451";
	else               code = "554";
    }
    if (!validate_smtp_dsn(dsn, first)) {
	if (*first == '4') dsn  = "4.3.0";
	else               dsn  = "5.7.1";
    }

    /* We need to double any "%" chars in reply */
    /* Worst-case, we'll double our length */
    len = strlen(reply) * 2 + 1;
    if (len <= SMALLBUF) {
	/* avoid malloc if the reply is short enough */
	safe_reply = stack_safe_reply;
    } else {
	safe_reply = malloc(len);
	if (!safe_reply) {
	    syslog(LOG_ERR, "Out of memory to escape reply %s", reply);
	    return smfi_setreply(ctx, (char *) code, (char *) dsn, "Out of memory");
	}
    }

    s = reply;
    t = safe_reply;
    while (*s) {
	if (*s == '%') *t++ = '%';
	/* Replace control chars except for \n with a space */
	if ((*s < ' ' && *s != '\n') || *s == 0x7f) {
	    *t++ = ' ';
	    s++;
	} else {
	    *t++ = *s++;
	}
    }
    *t = 0;
    if (!strchr(reply, '\n')) {
	retcode = smfi_setreply(ctx, (char *) code, (char *) dsn, safe_reply);
    } else {
	retcode = do_reply(ctx, code, dsn, safe_reply);
    }
    if (safe_reply != stack_safe_reply) {
	free(safe_reply);
    }
    return retcode;
}

/**********************************************************************
*%FUNCTION: mfconnect
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
* hostname -- name of connecting host
* sa -- socket address of connecting host
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* Allocates a private data structure for tracking this connection
***********************************************************************/
static sfsistat
mfconnect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *sa)
{
    struct privdata *data;

    char const *tmp;
    char *me;
    struct sockaddr_in *insa = (struct sockaddr_in *) sa;
#if defined(AF_INET6) && defined(HAVE_INET_NTOP)
    struct sockaddr_in6 *in6sa = (struct sockaddr_in6 *) sa;
#endif

    DEBUG_ENTER("mfconnect");

    /* Delete any existing context data */
    mfclose(ctx);

    /* If too many running filters, reject connection at this phase.
       However, if workersReservedForLoopback >= 0, accept or queue
       connections from localhost
     */
    if (!AllowNewConnectionsToQueue) {
	int is_local;
	int required_workers;
	int n = MXCheckFreeWorkers(MultiplexorSocketName, NULL);
	if (n < 0) {
	    syslog(LOG_WARNING, "mfconnect: Error communicating with multiplexor");
	    DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	if (!sa) {
	    is_local = 1;
	} else {
	    is_local = is_localhost(sa);
	}

	if (workersReservedForLoopback >= 0) {
	    if (is_local) {
		required_workers = 0;
	    } else {
		required_workers = workersReservedForLoopback;
	    }
	} else {
	    required_workers = 0;
	}
	if (n <= required_workers) {
	    if (workersReservedForLoopback < 0 ||
		! is_local) {
		syslog(LOG_WARNING, "mfconnect: No free workers: Need %d, found %d", required_workers+1, n);
		DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
		return SMFIS_TEMPFAIL;
	    }
	}
    }

    data = malloc_with_log(sizeof *data);
    if (!data) {
	DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    data->hostname = NULL;
    data->hostip   = NULL;
    data->hostport = 0;
    data->myip     = NULL;
    data->daemon_port = 0;
    data->sender   = NULL;
    data->firstRecip = NULL;
    data->dir      = NULL;
    data->heloArg  = NULL;
    data->qid_written = 0;
    data->qid      = NOQUEUE;
    data->fd       = -1;
    data->headerFD = -1;
    data->cmdFD    = -1;
    data->numContentTypeHeaders = 0;
    data->seenMimeVersionHeader = 0;
    data->validatePresent = 0;
    data->suspiciousBody = 0;
    data->lastWasCR      = 0;
    data->filterFailed   = 0;

    /* Save private data */
    if (smfi_setpriv(ctx, data) != MI_SUCCESS) {
	free(data);
	/* Can't hurt... */
	smfi_setpriv(ctx, NULL);
	syslog(LOG_WARNING, "Unable to set private data pointer: smfi_setpriv failed");
	DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    if (hostname) {
	data->hostname = strdup_with_log(hostname);
	if (!data->hostname) {
	    cleanup(ctx);
	    DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
    } else {
	data->hostname = NULL;
    }

    /* Port */
    if (sa) {
#ifdef AF_INET6
      if (sa->sa_family == AF_INET6) {
	data->hostport = ntohs(in6sa->sin6_port);
      }
#endif
      if (sa->sa_family == AF_INET) {
	data->hostport = ntohs(insa->sin_port);
      }
    }
    /* Padding -- should be big enough for IPv6 addresses */
    if (!sa) {
	data->hostip = NULL;
    } else {
	data->hostip = malloc_with_log(65);
	if (!data->hostip) {
	    cleanup(ctx);
	    DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
#ifdef HAVE_INET_NTOP
#ifdef AF_INET6
        if (sa->sa_family == AF_INET6) {
	    tmp = inet_ntop(AF_INET6, &in6sa->sin6_addr, data->hostip, 65);
	    /* Convert IPv6-mapped IPv4 address to pure IPv4.  That is:
	       ::ffff:xxx.yyy.zzz.www to simply xxx.yyy.zzz.www */
	    if (tmp) {
		if (IN6_IS_ADDR_V4MAPPED(&in6sa->sin6_addr) ||
		    IN6_IS_ADDR_V4COMPAT(&in6sa->sin6_addr)) {
		    if (strchr(data->hostip, '.')) {
			char const *lastcolon = strrchr(data->hostip, ':');
			char *dst = data->hostip;
			while(lastcolon) {
			    lastcolon++;
			    *dst++ = *lastcolon;
			    if (!*lastcolon) break;
			}
		    }
		}
	    }
	} else
#endif
        if (sa->sa_family == AF_INET) {
	    tmp = inet_ntop(AF_INET, &insa->sin_addr, data->hostip, 65);
	} else if (sa->sa_family == AF_LOCAL) {
	    tmp = "127.0.0.1";
	    strcpy(data->hostip, tmp);
	} else {
	    syslog(LOG_WARNING, "Unknown address family %d",
		   (int) sa->sa_family);
	    cleanup(ctx);
	    DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
#else
	pthread_mutex_lock(&ntoa_mutex);
	tmp = inet_ntoa(insa->sin_addr);
	if (tmp) strncpy(data->hostip, tmp, 64);
	pthread_mutex_unlock(&ntoa_mutex);
#endif
	if (!tmp) {
	    syslog(LOG_WARNING, "inet_ntoa or inet_ntop failed: %m");
	    cleanup(ctx);
	    DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	data->hostip[64] = 0;
    }

    /* Is host IP equivalent to loopback?  If so, replace with 127.0.0.1 */
    /* (We have enough room because data->hostip can hold 64 chars + nul) */
    if (data->hostip    &&
	EquivToLoopback &&
	!strcmp(data->hostip, EquivToLoopback)) {
	strcpy(data->hostip, "127.0.0.1");
    }

    data->dir = NULL;
    data->fd = -1;
    data->headerFD = -1;
    data->cmdFD = -1;
    data->suspiciousBody = 0;
    data->lastWasCR = 0;

    /* Get my IP address */
    me = smfi_getsymval(ctx, "{if_addr}");
    if (me && *me && MyIPAddress && !strcmp(me, MyIPAddress)) {
	data->myip = MyIPAddress;
    } else if (me && *me && strcmp(me, "127.0.0.1")) {
	data->myip = strdup_with_log(me);
    } else {
	/* Sigh... use our computed address */
	data->myip = MyIPAddress;
    }

    /* Get my port */
    if (!data->daemon_port) {
	me = smfi_getsymval(ctx, "{daemon_port}");
	if (me && *me) {
	    sscanf(me, "%u", &(data->daemon_port));
	}
    }


    /* Try grabbing the Queue ID */
    set_queueid(ctx);

    if (doRelayCheck) {
	char buf2[SMALLBUF];
	int n = MXRelayOK(MultiplexorSocketName, buf2, data->hostip,
			  data->hostname, data->hostport, data->myip, data->daemon_port, data->qid);
	if (n == MD_REJECT) {
	    /* Can't call smfi_setreply from connect callback */
	    /* set_dsn(ctx, buf2, 5); */
	    /* We reject connections from this relay */
	    cleanup(ctx);
	    DEBUG_EXIT("mfconnect", "SMFIS_REJECT");
	    return SMFIS_REJECT;
	}
	if (n <= MD_TEMPFAIL) {
	    /* Can't call smfi_setreply from connect callback */
	    /* set_dsn(ctx, buf2, 4); */
	    cleanup(ctx);
	    DEBUG_EXIT("mfconnect", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	if (n == MD_ACCEPT_AND_NO_MORE_FILTERING) {
	    /* Can't call smfi_setreply from connect callback */
	    /* set_dsn(ctx, buf2, 2); */
	    cleanup(ctx);
	    DEBUG_EXIT("mfconnect", "SMFIS_ACCEPT");
	    return SMFIS_ACCEPT;
	}
	if (n == MD_DISCARD) {
	    /* Can't call smfi_setreply from connect callback */
	    /* set_dsn(ctx, buf2, 2); */
	    cleanup(ctx);
	    DEBUG_EXIT("mfconnect", "SMFIS_DISCARD");
	    return SMFIS_DISCARD;
	}
    }

    DEBUG_EXIT("mfconnect", "SMFIS_CONTINUE");
    return SMFIS_CONTINUE;
}

/**********************************************************************
* %FUNCTION: helo
* %ARGUMENTS:
*  ctx -- Milter context
*  helohost -- argument to "HELO" or "EHLO" SMTP command
* %RETURNS:
*  SMFIS_CONTINUE
* %DESCRIPTION:
*  Stores the HELO argument in the private data area
***********************************************************************/
static sfsistat
helo(SMFICTX *ctx, char *helohost)
{
    struct privdata *data = DATA;
    DEBUG_ENTER("helo");
    if (!data) {
	DEBUG_EXIT("helo", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    if (data->heloArg) {
	free(data->heloArg);
	data->heloArg = NULL;
    }
    data->heloArg = strdup_with_log(helohost);

    /* Try grabbing the Queue ID */
    set_queueid(ctx);

    if (doHeloCheck) {
	char buf2[SMALLBUF];
	int n = MXHeloOK(MultiplexorSocketName, buf2, data->hostip,
			 data->hostname, data->heloArg, data->hostport, data->myip, data->daemon_port, data->qid);
	if (n == MD_REJECT) {
	    set_dsn(ctx, buf2, 5);
	    cleanup(ctx);
	    DEBUG_EXIT("helo", "SMFIS_REJECT");
	    return SMFIS_REJECT;
	}
	if (n <= MD_TEMPFAIL) {
	    set_dsn(ctx, buf2, 4);
	    cleanup(ctx);
	    DEBUG_EXIT("helo", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	if (n == MD_ACCEPT_AND_NO_MORE_FILTERING) {
	    set_dsn(ctx, buf2, 2);
	    cleanup(ctx);
	    DEBUG_EXIT("helo", "SMFIS_ACCEPT");
	    return SMFIS_ACCEPT;
	}
	if (n == MD_DISCARD) {
	    set_dsn(ctx, buf2, 2);
	    cleanup(ctx);
	    DEBUG_EXIT("helo", "SMFIS_DISCARD");
	    return SMFIS_DISCARD;
	}
	if (n == MD_CONTINUE) {
	    /* Called only in case we need to delay */
	    set_dsn(ctx, buf2, 2);
	}
    }
    DEBUG_EXIT("helo", "SMFIS_CONTINUE");
    return SMFIS_CONTINUE;
}

/**********************************************************************
*%FUNCTION: envfrom
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
* from -- list of arguments to "MAIL FROM:" SMTP command.
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* Allocates a private data structure for tracking this message, and
* opens a temporary file for saving message body.
***********************************************************************/
static sfsistat
envfrom(SMFICTX *ctx, char **from)
{
    struct privdata *data;
    int i;
    char buffer[SMALLBUF];
    char buf2[SMALLBUF];
    char **macro;
    dynamic_buffer dbuf;

    char mxid[MX_ID_LEN+1];

    DEBUG_ENTER("envfrom");

    /* Generate the MIMEDefang ID */
    (void) gen_mx_id(mxid);

    /* Get the private context */
    data = DATA;
    if (!data) {
	syslog(LOG_WARNING, "envfrom: Unable to obtain private data from milter context");
	DEBUG_EXIT("envfrom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Set the Queue ID if it hasn't yet been set */
    set_queueid(ctx);

    /* Copy sender */
    if (data->sender) {
	free(data->sender);
    }
    data->sender = strdup_with_log(from[0]);
    if (!data->sender) {
	cleanup(ctx);
	DEBUG_EXIT("envfrom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Old data lying around? */
    if (data->firstRecip) {
	free(data->firstRecip);
	data->firstRecip = NULL;
    }

    /* Make the working directory */
    if (!data->qid || data->qid == NOQUEUE) {
	/* No queue ID, so use the mxid */
	snprintf(buffer, SMALLBUF, "%s/mdefang-%s", SpoolDir, mxid);
    } else {
	/* We have a queue ID, so use it */
	snprintf(buffer, SMALLBUF, "%s/mdefang-%s", SpoolDir, data->qid);
    }

    if (mkdir(buffer, 0750) != 0) {
        /* Could not create temp. directory */
	syslog(LOG_WARNING, "%s: Could not create directory %s: %m",
	       data->qid, buffer);
	cleanup(ctx);
	DEBUG_EXIT("envfrom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    if (data->fd >= 0) closefd(data->fd);
    if (data->headerFD >= 0) closefd(data->headerFD);
    if (data->cmdFD >= 0) closefd(data->cmdFD);
    if (data->dir) {
	/* Clean data->dir up if it's still lying around */
	if (access(data->dir, R_OK) == 0) {
	    (void) rm_r(data->qid, data->dir);
	}
	free(data->dir);
	data->dir = NULL;
    }

    data->fd = -1;
    data->headerFD = -1;
    data->cmdFD = -1;
    data->validatePresent = 0;
    data->filterFailed = 0;
    data->numContentTypeHeaders = 0;
    data->seenMimeVersionHeader = 0;
    data->dir = strdup_with_log(buffer);

    if (!data->dir) {
	/* Don't forget to clean up directory... */
	rmdir(buffer);
	cleanup(ctx);
	DEBUG_EXIT("envfrom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Create the HEADERS file.  Even if we get a wacky e-mail without
     * any headers, we want an empty HEADERS file lying around */
    data->headerFD = get_fd(data, "HEADERS", data->headerFD);
    if (data->headerFD >= 0) {
	data->headerFD = put_fd(data->headerFD);
    }

    /* Initialize the dynamic buffer for writing COMMANDS file */
    dbuf_init(&dbuf);

    /* Generate an ID */
    append_mx_command(&dbuf, 'i', mxid);

    /* Write the sender */
    append_mx_command(&dbuf, 'S', from[0]);

    /* Write ESMTP args */
    for (i=1; from[i]; i++) {
	append_mx_command(&dbuf, 's', from[i]);
    }

    /* Write the standard macros */
    macro = StandardSendmailMacros;
    while (*macro) {
	append_macro_value(&dbuf, ctx, *macro);
	macro++;
    }

    /* Fake client_port: We don't get the macro, but we have the connection
       info cached in our private data area. */
    dbuf_putc(&dbuf, '=');
    append_percent_encoded(&dbuf, "client_port");
    dbuf_putc(&dbuf, ' ');
    {
	char portstring[32];
	snprintf(portstring, sizeof(portstring), "%u", data->hostport);
	append_percent_encoded(&dbuf, portstring);
    }
    dbuf_putc(&dbuf, '\n');

    /* Write any additional macros requested by user */
    for (i=0; i<NumAdditionalMacros; i++) {
	append_macro_value(&dbuf, ctx, AdditionalMacros[i]);
    }

    /* Clear out any old myip address */
    if (data->myip && (data->myip != MyIPAddress)) {
	free(data->myip);
	data->myip = NULL;
    }

    if (data->qid && data->qid != NOQUEUE) {
	append_mx_command(&dbuf, 'Q', data->qid);
	data->qid_written = 1;
    }

    /* Write host name and host IP */
    append_mx_command(&dbuf, 'H', data->hostname);
    append_mx_command(&dbuf, 'I', data->hostip);

    /* Write HELO value */
    if (data->heloArg) {
	append_mx_command(&dbuf, 'E', data->heloArg);
    }

    /* Now actually dump the dbuf contents to COMMANDS */
    /* Open command file */
    data->cmdFD = get_fd(data, "COMMANDS", data->cmdFD);
    if (data->cmdFD < 0) {
	dbuf_free(&dbuf);
	cleanup(ctx);
	DEBUG_EXIT("envfrom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    if (write_dbuf(&dbuf, data->cmdFD, data, "COMMANDS") < 0) {
	dbuf_free(&dbuf);
	cleanup(ctx);
	DEBUG_EXIT("envfrom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    dbuf_free(&dbuf);
    data->cmdFD = put_fd(data->cmdFD);

    if (doSenderCheck) {
	int n = MXSenderOK(MultiplexorSocketName, buf2,
			   (char const **) from, data->hostip, data->hostname,
			   data->heloArg, data->dir, data->qid);
	if (n == MD_REJECT) {
	    set_dsn(ctx, buf2, 5);

	    /* We reject connections from this sender */
	    cleanup(ctx);
	    DEBUG_EXIT("envfrom", "SMFIS_REJECT");
	    return SMFIS_REJECT;
	}
	if (n <= MD_TEMPFAIL) {
	    set_dsn(ctx, buf2, 4);

	    cleanup(ctx);
	    DEBUG_EXIT("envfrom", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	if (n == MD_ACCEPT_AND_NO_MORE_FILTERING) {
	    set_dsn(ctx, buf2, 2);
	    cleanup(ctx);
	    DEBUG_EXIT("envfrom", "SMFIS_ACCEPT");
	    return SMFIS_ACCEPT;
	}
	if (n == MD_DISCARD) {
	    set_dsn(ctx, buf2, 2);
	    cleanup(ctx);
	    DEBUG_EXIT("envfrom", "SMFIS_DISCARD");
	    return SMFIS_DISCARD;
	}
	if (n == MD_CONTINUE) {
	    /* Called only in case we need to delay */
	    set_dsn(ctx, buf2, 2);
	}
    }

    DEBUG_EXIT("envfrom", "SMFIS_CONTINUE");
    return SMFIS_CONTINUE;
}

/**********************************************************************
*%FUNCTION: mf_data
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
*%RETURNS:
* Standard milter reply code
*%DESCRIPTION:
* Does a post-DATA callback
***********************************************************************/
#ifdef MILTER_BUILDLIB_HAS_DATA
static sfsistat mf_data(SMFICTX *ctx)
{
    return SMFIS_CONTINUE;
}
#endif

/**********************************************************************
*%FUNCTION: mf_unknown
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
*%RETURNS:
* Standard milter reply code
*%DESCRIPTION:
* Does a post-DATA callback
***********************************************************************/
#ifdef MILTER_BUILDLIB_HAS_UNKNOWN
static sfsistat mf_unknown(SMFICTX *ctx, char const *arg)
{
    return SMFIS_CONTINUE;
}
#endif

/**********************************************************************
*%FUNCTION: mf_negotiate
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
* Remaining args -- crappy args as described in libmilter docs.
*%RETURNS:
* Standard milter reply code
*%DESCRIPTION:
* Negotiates protocol options
***********************************************************************/
#ifdef MILTER_BUILDLIB_HAS_NEGOTIATE
static sfsistat mf_negotiate(SMFICTX *ctx,
			     unsigned long f0,
			     unsigned long f1,
			     unsigned long f2,
			     unsigned long f3,
			     unsigned long *pf0,
			     unsigned long *pf1,
			     unsigned long *pf2,
			     unsigned long *pf3)
{
    dynamic_buffer dbuf;
    char **macroname;
    int done_one = 0;
    int i;

    *pf0 = f0;
    *pf1 = 0;
    *pf2 = 0;
    *pf3 = 0;

    if (f1 & SMFIP_RCPT_REJ) {
	if (SeeRejectedRecipients) {
	    *pf1 |= SMFIP_RCPT_REJ;
	}
    }
    /* Don't want leading spaces */
    *pf1 &= (~SMFIP_HDR_LEADSPC);

    /*** libmilter 8.14.3 leaked memory, so don't use smfi_setsymlist
	 unless invoked with -y option ***/

    if (!setsymlist_ok) {
	return SMFIS_CONTINUE;
    }

    /* Send along the list of macros we want */
    dbuf_init(&dbuf);

    for (macroname = StandardSendmailMacros; *macroname; macroname++) {
	if (done_one) {
	    dbuf_putc(&dbuf, ' ');
	}
	if (strlen(*macroname) > 1) {
	    dbuf_putc(&dbuf, '{');
	}
	dbuf_puts(&dbuf, *macroname);
	if (strlen(*macroname) > 1) {
	    dbuf_putc(&dbuf, '}');
	}
	done_one = 1;
    }

    for (i=0, macroname=AdditionalMacros; i<NumAdditionalMacros; i++, macroname++) {
	if (done_one) {
	    dbuf_putc(&dbuf, ' ');
	}
	if (strlen(*macroname) > 1) {
	    dbuf_putc(&dbuf, '{');
	}
	dbuf_puts(&dbuf, *macroname);
	if (strlen(*macroname) > 1) {
	    dbuf_putc(&dbuf, '}');
	}
	done_one = 1;
    }

    i = 1;
    if (smfi_setsymlist(ctx, SMFIM_CONNECT, DBUF_VAL(&dbuf)) != MI_SUCCESS) i = 0;
    if (smfi_setsymlist(ctx, SMFIM_HELO,    DBUF_VAL(&dbuf)) != MI_SUCCESS) i = 0;
    if (smfi_setsymlist(ctx, SMFIM_ENVFROM, DBUF_VAL(&dbuf)) != MI_SUCCESS) i = 0;
    if (smfi_setsymlist(ctx, SMFIM_ENVRCPT, DBUF_VAL(&dbuf)) != MI_SUCCESS) i = 0;
    if (smfi_setsymlist(ctx, SMFIM_DATA,    DBUF_VAL(&dbuf)) != MI_SUCCESS) i = 0;
    if (smfi_setsymlist(ctx, SMFIM_EOM,     DBUF_VAL(&dbuf)) != MI_SUCCESS) i = 0;
    if (smfi_setsymlist(ctx, SMFIM_EOH,     DBUF_VAL(&dbuf)) != MI_SUCCESS) i = 0;

    dbuf_free(&dbuf);
    if (!i) {
	syslog(LOG_INFO, "smfi_setsymlist() failed");
    }
    return SMFIS_CONTINUE;

}
#endif

/**********************************************************************
*%FUNCTION: rcptto
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
* to -- list of arguments to each RCPT_TO
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* Saves recipient data
***********************************************************************/
static sfsistat
rcptto(SMFICTX *ctx, char **to)
{
    struct privdata *data = DATA;
    char ans[SMALLBUF];
    sfsistat retcode = SMFIS_CONTINUE;
    char const *rcpt_mailer, *rcpt_host, *rcpt_addr;
    int i;
    dynamic_buffer dbuf;

    DEBUG_ENTER("rcptto");
    if (!data) {
	syslog(LOG_WARNING, "rcptto: Unable to obtain private data from milter context");
	DEBUG_EXIT("rcptto", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Apparently, Postfix offers an option to set the "i" macro at
       rcptto time */
    set_queueid(ctx);
    if (data->qid && data->qid != NOQUEUE) {
        if (!data->qid_written) {
            /* Write this out separately; the write below may be skipped */
            data->cmdFD = get_fd(data, "COMMANDS", data->cmdFD);
            if (data->cmdFD >= 0) {
                dbuf_init(&dbuf);
                append_mx_command(&dbuf, 'Q', data->qid);
                if (write_dbuf(&dbuf, data->cmdFD, data, "COMMANDS") >= 0) {
                    data->qid_written = 1;
                }
                dbuf_free(&dbuf);
                data->cmdFD = put_fd(data->cmdFD);
            }
        }
    }

    rcpt_mailer = smfi_getsymval(ctx, "{rcpt_mailer}");
    if (!rcpt_mailer || !*rcpt_mailer) rcpt_mailer = "?";

    rcpt_host = smfi_getsymval(ctx, "{rcpt_host}");
    if (!rcpt_host || !*rcpt_host) rcpt_host = "?";

    rcpt_addr = smfi_getsymval(ctx, "{rcpt_addr}");
    if (!rcpt_addr || !*rcpt_addr) rcpt_addr = "?";

    /* Recipient check if enabled */
    if (doRecipientCheck) {
	int n;

	/* If this is first recipient, copy it */
	if (!data->firstRecip) {
	    data->firstRecip = strdup_with_log(to[0]);
	    if (!data->firstRecip) {
		DEBUG_EXIT("rcptto", "SMFIS_TEMPFAIL");
		return SMFIS_TEMPFAIL;
	    }
	}
	n = MXRecipientOK(MultiplexorSocketName, ans,
			  (char const **) to, data->sender, data->hostip,
			  data->hostname, data->firstRecip, data->heloArg,
			  data->dir, data->qid,
			  rcpt_mailer, rcpt_host, rcpt_addr);
	if (n == MD_REJECT) {
	    /* We reject to this recipient */
	    set_dsn(ctx, ans, 5);

	    DEBUG_EXIT("rcptto", "SMFIS_REJECT");
	    return SMFIS_REJECT;
	}
	if (n <= MD_TEMPFAIL) {
	    set_dsn(ctx, ans, 4);

	    DEBUG_EXIT("rcptto", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	if (n == MD_ACCEPT_AND_NO_MORE_FILTERING) {
	    set_dsn(ctx, ans, 2);
	    cleanup(ctx);
	    DEBUG_EXIT("rcptto", "SMFIS_ACCEPT");
	    return SMFIS_ACCEPT;
	}
	if (n == MD_DISCARD) {
	    set_dsn(ctx, ans, 2);

	    cleanup(ctx);
	    DEBUG_EXIT("rcptto", "SMFIS_DISCARD");
	    return SMFIS_DISCARD;
	}
	if (n == MD_CONTINUE) {
	    /* Called only in case we need to delay */
	    set_dsn(ctx, ans, 2);
	}
    }
    /* Write recipient line, only for recipients we accept! */
    dbuf_init(&dbuf);
    dbuf_putc(&dbuf, 'R');
    append_percent_encoded(&dbuf, to[0]);
    dbuf_putc(&dbuf, ' ');
    append_percent_encoded(&dbuf, rcpt_mailer);
    dbuf_putc(&dbuf, ' ');
    append_percent_encoded(&dbuf, rcpt_host);
    dbuf_putc(&dbuf, ' ');
    append_percent_encoded(&dbuf, rcpt_addr);
    dbuf_putc(&dbuf, '\n');

    /* Write ESMTP args */
    for (i=1; to[i]; i++) {
	append_mx_command(&dbuf, 'r', to[i]);
    }

    /* Now flush out to cmdFD */
    data->cmdFD = get_fd(data, "COMMANDS", data->cmdFD);
    if (data->cmdFD < 0) {
	dbuf_free(&dbuf);
	cleanup(ctx);
	DEBUG_EXIT("rcptto", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    if (write_dbuf(&dbuf, data->cmdFD, data, "COMMANDS") < 0) {
	dbuf_free(&dbuf);
	cleanup(ctx);
	DEBUG_EXIT("rcptto", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    dbuf_free(&dbuf);
    data->cmdFD = put_fd(data->cmdFD);
    DEBUG_EXIT("rcptto", "SMFIS_CONTINUE or SMFIS_ACCEPT");
    return retcode;
}

/**********************************************************************
*%FUNCTION: header
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
* headerf -- Header field name
* headerv -- Header value
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* Writes the header to the temporary file
***********************************************************************/
static sfsistat
header(SMFICTX *ctx, char *headerf, char *headerv)
{
    struct privdata *data = DATA;
    int suspicious = 0;
    int write_header = 1;
    dynamic_buffer dbuf;

    DEBUG_ENTER("header");
    if (!data) {
	syslog(LOG_WARNING, "header: Unable to obtain private data from milter context");
	DEBUG_EXIT("header", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Check for multiple content-type headers */
    if (!strcasecmp(headerf, "content-type")) {
	data->numContentTypeHeaders++;
	/* If more than one content-type header, only write the first one
	   to ensure reliable interpretation by filter! */
	if (data->numContentTypeHeaders > 1) write_header = 0;
    } else if (!strcasecmp(headerf, "mime-version")) {
	/* We have seen a MIME-Version: header? */
	data->seenMimeVersionHeader = 1;
    }

    if (write_header) {
	/* Write the header to the message file */
	dbuf_init(&dbuf);
	suspicious = safe_append_header(&dbuf, headerf);
	dbuf_puts(&dbuf, ": ");
	suspicious |= safe_append_header(&dbuf, headerv);
	dbuf_putc(&dbuf, '\n');
	data->fd = get_fd(data, "INPUTMSG", data->fd);
	if (data->fd < 0) {
	    dbuf_free(&dbuf);
	    cleanup(ctx);
	    DEBUG_EXIT("header", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	if (write_dbuf(&dbuf, data->fd, data, "INPUTMSG") < 0) {
	    dbuf_free(&dbuf);
	    cleanup(ctx);
	    DEBUG_EXIT("header", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	dbuf_free(&dbuf);
	data->fd = put_fd(data->fd);
    }

    /* Remove embedded newlines and save to our HEADERS file */
    chomp(headerf);
    chomp(headerv);
    if (write_header) {
	data->headerFD = get_fd(data, "HEADERS", data->headerFD);
	if (data->headerFD < 0) {
	    cleanup(ctx);
	    DEBUG_EXIT("header", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	dbuf_init(&dbuf);
	dbuf_puts(&dbuf, headerf);
	dbuf_puts(&dbuf, ": ");
	dbuf_puts(&dbuf, headerv);
	dbuf_putc(&dbuf, '\n');
	if (write_dbuf(&dbuf, data->headerFD, data, "HEADERS") < 0) {
	    dbuf_free(&dbuf);
	    cleanup(ctx);
	    DEBUG_EXIT("header", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	dbuf_free(&dbuf);
	data->headerFD = put_fd(data->headerFD);
    }

    dbuf_init(&dbuf);
    if (suspicious) {
	append_mx_command(&dbuf, '!', NULL);
    }
    /* Check for subject -- special case */
    if (!strcasecmp(headerf, "subject")) {
	append_mx_command(&dbuf, 'U', headerv);
    } else if (!strcasecmp(headerf, "message-id")) {
	append_mx_command(&dbuf, 'X', headerv);
    }

    /* Check for validating IP header.  If found, write a J line
       to the file to reset the SMTP host address */
    if (ValidateHeader[0] && !strcmp(headerf, ValidateHeader)) {
	/* Make sure it looks like an IP address, though... */
	int n, a, b, c, d;
	char ipaddr[32];
	n = sscanf(headerv, "%d.%d.%d.%d", &a, &b, &c, &d);
	if (n == 4 &&
	    a >= 0 && a <= 255 &&
	    b >= 0 && b <= 255 &&
	    c >= 0 && c <= 255 &&
	    d >= 0 && d <= 255) {
	    sprintf(ipaddr, "%d.%d.%d.%d", a, b, c, d);
	    append_mx_command(&dbuf, 'J', ipaddr);
	    data->validatePresent = 1;
	}
    }

    if (DBUF_LEN(&dbuf)) {
	data->cmdFD = get_fd(data, "COMMANDS", data->cmdFD);
	if (data->cmdFD < 0) {
	    dbuf_free(&dbuf);
	    cleanup(ctx);
	    DEBUG_EXIT("header", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	if (write_dbuf(&dbuf, data->cmdFD, data, "COMMANDS") < 0) {
	    dbuf_free(&dbuf);
	    cleanup(ctx);
	    DEBUG_EXIT("header", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
	data->cmdFD = put_fd(data->cmdFD);
    }
    dbuf_free(&dbuf);

    DEBUG_EXIT("header", "SMFIS_CONTINUE");
    return SMFIS_CONTINUE;
}

/**********************************************************************
*%FUNCTION: eoh
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* Writes a blank line to indicate the end of headers.
***********************************************************************/
static sfsistat
eoh(SMFICTX *ctx)
{
    struct privdata *data = DATA;

    DEBUG_ENTER("eoh");
    if (!data) {
	syslog(LOG_WARNING, "eoh: Unable to obtain private data from milter context");
	DEBUG_EXIT("eoh", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Set the Queue ID if it hasn't yet been set */
    set_queueid(ctx);

    /* We can close headerFD to save a descriptor */
    if (data->headerFD >= 0 && closefd(data->headerFD) < 0) {
	data->headerFD = -1;
	syslog(LOG_WARNING, "%s: Error closing header descriptor: %m", data->qid);
	cleanup(ctx);
	DEBUG_EXIT("eoh", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    data->headerFD = -1;
    data->suspiciousBody = 0;
    data->lastWasCR = 0;

    data->fd = get_fd(data, "INPUTMSG", data->fd);
    if (data->fd < 0) {
	cleanup(ctx);
	DEBUG_EXIT("eoh", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Write blank line separating headers from body */
    if (writestr(data->fd, "\n") != 1) {
	cleanup(ctx);
	DEBUG_EXIT("eoh", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    data->fd = put_fd(data->fd);
    DEBUG_EXIT("eoh", "SMFIS_CONTINUE");
    return SMFIS_CONTINUE;
}

/**********************************************************************
*%FUNCTION: body
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
* text -- a chunk of text from the mail body
* len -- length of chunk
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* Writes a chunk of the body to the temporary file
***********************************************************************/
static sfsistat
body(SMFICTX *ctx, u_char *text, size_t len)
{
    struct privdata *data = DATA;

    char buf[4096];
    int nsaved = 0;

    DEBUG_ENTER("body");

    if (!data) {
	syslog(LOG_WARNING, "body: Unable to obtain private data from milter context");
	DEBUG_EXIT("body", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Set the Queue ID if it hasn't yet been set */
    set_queueid(ctx);

    /* Write to file and scan body for suspicious characters */
    if (len) {
	u_char *s = text;
	size_t n;

	/* If last was CR, and this is not LF, suspicious! */
	if (data->lastWasCR && *text != '\n') {
	    data->suspiciousBody = 1;
	    if (!StripBareCR) {
		/* Do not suppress bare CR's.  Only suppress those
		   followed by LF */
		buf[nsaved++] = '\r';
	    }
	}

	data->lastWasCR = 0;
	data->fd = get_fd(data, "INPUTMSG", data->fd);
	if (data->fd < 0) {
	    cleanup(ctx);
	    DEBUG_EXIT("body", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}

	for (n=0; n<len; n++, s++) {
	    if (*s == '\r') {
		if (n == len-1) {
		    data->lastWasCR = 1;
		    continue;
		} else if (*(s+1) != '\n') {
		    data->suspiciousBody = 1;
		    if (StripBareCR) {
			/* Suppress ALL CR's */
			continue;
		    }
		} else {
		    /* Suppress the CR immediately preceding a LF */
		    continue;
		}
	    }

	    /* Write char */
	    if (nsaved == sizeof(buf)) {
		if (writen(data->fd, buf, nsaved) < 0) {
		    syslog(LOG_WARNING, "%s: writen failed: %m line %d",
			   data->qid, __LINE__);
		    cleanup(ctx);
		    DEBUG_EXIT("body", "SMFIS_TEMPFAIL");
		    return SMFIS_TEMPFAIL;
		}
		nsaved = 0;
	    }
	    buf[nsaved++] = *s;
	    /* Embedded NULL's are cause for concern */
	    if (!*s) {
		data->suspiciousBody = 1;
	    }
	}
	/* Flush buffer */
	if (nsaved) {
	    if (writen(data->fd, buf, nsaved) < 0) {
		syslog(LOG_WARNING, "%s: writen failed: %m line %d",
		       data->qid, __LINE__);
		cleanup(ctx);
		DEBUG_EXIT("body", "SMFIS_TEMPFAIL");
		return SMFIS_TEMPFAIL;
	    }
	}
	data->fd = put_fd(data->fd);
    }

    DEBUG_EXIT("body", "SMFIS_CONTINUE");
    return SMFIS_CONTINUE;
}

/**********************************************************************
*%FUNCTION: eom
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* This is where all the action happens.  Called at end of message, it
* runs the Perl scanner which may or may not ask for the body to be
* replaced.
***********************************************************************/
static sfsistat
eom(SMFICTX *ctx)
{
    char buffer[SMALLBUF];
    char result[SMALLBUF];
    char *rbuf, *rptr, *eptr;

    int seen_F = 0;
    int res_fd;
    int n;
    struct privdata *data = DATA;
    int r;
    int problem = 0;
    int fd;
    int j;
    char chunk[CHUNK];
    char *hdr, *val, *count;
    char *code, *dsn, *reply;

    struct stat statbuf;
    dynamic_buffer dbuf;
    struct timeval start, finish;
    int rejecting;

    DEBUG_ENTER("eom");
    if (LogTimes) {
	gettimeofday(&start, NULL);
    }

    /* Close output file */
    if (!data) {
	syslog(LOG_WARNING, "eom: Unable to obtain private data from milter context");
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    dbuf_init(&dbuf);

    /* Set the Queue ID if it hasn't yet been set */
    set_queueid(ctx);

    if (!data->qid_written && data->qid && (data->qid != NOQUEUE)) {
	append_mx_command(&dbuf, 'Q', data->qid);
	data->qid_written = 1;
    }

    /* Signal suspicious body chars */
    if (data->suspiciousBody) {
	append_mx_command(&dbuf, '?', NULL);
    }

    /* Signal end of command file */
    append_mx_command(&dbuf, 'F', NULL);

    data->cmdFD = get_fd(data, "COMMANDS", data->cmdFD);
    if (data->cmdFD < 0) {
	dbuf_free(&dbuf);
	cleanup(ctx);
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    if (write_dbuf(&dbuf, data->cmdFD, data, "COMMANDS") < 0) {
	dbuf_free(&dbuf);
	cleanup(ctx);
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }
    dbuf_free(&dbuf);

    /* All the fd's are closed unconditionally -- no need for put_fd */
    if (data->fd >= 0       && (closefd(data->fd) < 0))       problem = 1;
    if (data->headerFD >= 0 && (closefd(data->headerFD) < 0)) problem = 1;
    if (data->cmdFD >= 0    && (closefd(data->cmdFD) < 0))    problem = 1;
    data->fd = -1;
    data->headerFD = -1;
    data->cmdFD = -1;

    if (problem) {
	cleanup(ctx);
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    data->suspiciousBody = 0;
    data->lastWasCR = 0;

    /* Run the filter */
    if (MXScanDir(MultiplexorSocketName, data->qid, data->dir) < 0) {
	data->filterFailed = 1;
	cleanup(ctx);
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Read the results file */
    snprintf(buffer, SMALLBUF, "%s/RESULTS", data->dir);
    res_fd = open(buffer, O_RDONLY);
    if (res_fd < 0) {
	syslog(LOG_WARNING, "%s: Filter did not create RESULTS file", data->qid);
	data->filterFailed = 1;
	cleanup(ctx);
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Slurp in the entire RESULTS file in one go... */
    if (fstat(res_fd, &statbuf) < 0) {
	syslog(LOG_WARNING, "%s: Unable to stat RESULTS file: %m", data->qid);
	closefd(res_fd);
	cleanup(ctx);
	data->filterFailed = 1;
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* If file is unreasonable big, forget it! */
    if (statbuf.st_size > BIGBUF - 1) {
	syslog(LOG_WARNING, "%s: RESULTS file is unreasonably large - %ld byes; max is %d bytes",
	       data->qid, (long) statbuf.st_size, BIGBUF-1);
	closefd(res_fd);
	cleanup(ctx);
	data->filterFailed = 1;
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* RESULTS files are typically pretty small and will fit into our */
    /* SMALLBUF-sized buffer.  However, we'll allocate up to BIGBUF bytes */
    /* for weird, large RESULTS files. */

    if (statbuf.st_size < SMALLBUF) {
	rbuf = result;
    } else {
	rbuf = malloc(statbuf.st_size + 1);
	if (!rbuf) {
	    syslog(LOG_WARNING, "%s: Unable to allocate memory for RESULTS data", data->qid);
	    closefd(res_fd);
	    cleanup(ctx);
	    DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	    return SMFIS_TEMPFAIL;
	}
    }

    /* Slurp in the file */
    n = readn(res_fd, rbuf, statbuf.st_size);
    if (n < 0) {
	syslog(LOG_WARNING, "%s: Error reading RESULTS file: %m", data->qid);
	closefd(res_fd);
	if (rbuf != result) free(rbuf);
	cleanup(ctx);
	DEBUG_EXIT("eom", "SMFIS_TEMPFAIL");
	return SMFIS_TEMPFAIL;
    }

    /* Done with descriptor -- close it. */
    closefd(res_fd);
    rbuf[n] = 0;

    /* Make a pass through the RESULTS file to see if mail will
       be rejected or discarded */
    rejecting = 0;
    rptr = rbuf;
    while (rptr && *rptr) {
	if (*rptr == 'T' ||
	    *rptr == 'D' ||
	    *rptr == 'B') {
	    /* We are tempfailing, discarding or bouncing the message */
	    rejecting = 1;
	    break;
	}

	/* Move to start of next line */
	while (*rptr && (*rptr != '\n')) {
	    rptr++;
	}
	if (*rptr == '\n') {
	    rptr++;
	}
    }

    /* Now process the commands in the results file */
    for (rptr = rbuf, eptr = rptr ; rptr && *rptr; rptr = eptr) {
	/* Get end-of-line character */
	while (*eptr && (*eptr != '\n')) {
	    eptr++;
	}
	/* Check line length */
	if (eptr - rptr >= SMALLBUF-1) {
	    syslog(LOG_WARNING, "%s: Overlong line in RESULTS file - %d chars (max %d)",
		   data->qid, (int) (eptr - rptr), SMALLBUF-1);
	    cleanup(ctx);
	    MD_SMFI_TRY(set_reply, (ctx, "5", "554", "5.4.0" , "Overlong line in RESULTS file"));
	    r = SMFIS_REJECT;
	    goto bail_out;
	}

	if (*eptr == '\n') {
	    *eptr = 0;
	    eptr++;
	} else {
	    eptr = NULL;
	}

	switch(*rptr) {
	case 'B':
	    /* Bounce */
	    syslog(LOG_DEBUG, "%s: Bouncing because filter instructed us to",
		   data->qid);
	    split_on_space3(rptr+1, &code, &dsn, &reply);
	    percent_decode(code);
	    percent_decode(dsn);
	    percent_decode(reply);

	    MD_SMFI_TRY(set_reply, (ctx, "5", code, dsn, reply));
	    cleanup(ctx);
	    r = SMFIS_REJECT;
	    goto bail_out;

	case 'D':
	    /* Discard */
	    syslog(LOG_DEBUG, "%s: Discarding because filter instructed us to",
		   data->qid);
	    cleanup(ctx);
	    r = SMFIS_DISCARD;
	    goto bail_out;

	case 'T':
	    /* Tempfail */
	    syslog(LOG_DEBUG, "%s: Tempfailing because filter instructed us to",
		   data->qid);
	    split_on_space3(rptr+1, &code, &dsn, &reply);
	    percent_decode(code);
	    percent_decode(dsn);
	    percent_decode(reply);

	    MD_SMFI_TRY(set_reply, (ctx, "4", code, dsn, reply));

	    cleanup(ctx);
	    r = SMFIS_TEMPFAIL;
	    goto bail_out;

	case 'C':
	    if (!rejecting) {
		snprintf(buffer, SMALLBUF, "%s/NEWBODY", data->dir);
		fd = open(buffer, O_RDONLY);
		if (fd < 0) {
		    syslog(LOG_WARNING, "%s: Could not open %s for reading: %m",
			   data->qid, buffer);
		    closefd(fd);
		    cleanup(ctx);
		    data->filterFailed = 1;
		    r = SMFIS_TEMPFAIL;
		    goto bail_out;
		}
		while ((j=read(fd, chunk, CHUNK)) > 0) {
		    MD_SMFI_TRY(smfi_replacebody, (ctx, (unsigned char *) chunk, j));
		}
		close(fd);
	    }
	    break;

	case 'M':
	    if (!rejecting) {
		/* New content-type header */
		percent_decode(rptr+1);
		if (strlen(rptr+1) > 0) {
		    MD_SMFI_TRY(smfi_chgheader, (ctx, "Content-Type", 1, rptr+1));
		}
		if (!data->seenMimeVersionHeader) {
		    /* No MIME-Version: header.  Add one. */
		    MD_SMFI_TRY(smfi_chgheader, (ctx, "MIME-Version", 1, "1.0"));
		}
	    }
	    break;

	case 'H':
	    /* Add a header */
	    if (!rejecting) {
		split_on_space(rptr+1, &hdr, &val);
		if (hdr && val) {
		    percent_decode(hdr);
		    percent_decode(val);
		    MD_SMFI_TRY(smfi_addheader, (ctx, hdr, val));
		}
	    }
	    break;

	case 'N':
	    /* Insert a header in position count */
	    if (!rejecting) {
		split_on_space3(rptr + 1, &hdr, &count, &val);
		if (hdr && val && count) {
		    percent_decode(hdr);
		    percent_decode(count);
		    percent_decode(val);
		    if (sscanf(count, "%d", &j) != 1 || j < 0) {
			j = 0; /* 0 means add header at the top */
		    }
#ifdef SMFIR_INSHEADER
		    MD_SMFI_TRY(smfi_insheader, (ctx, j, hdr, val));
#else
		    syslog(LOG_WARNING,
			   "%s: No smfi_insheader; using smfi_addheader instead.",
			   data->qid);

		    MD_SMFI_TRY(smfi_addheader, (ctx, hdr, val));
#endif
		}
	    }
	    break;
	case 'I':
	    /* Change a header */
	    if (!rejecting) {
		split_on_space3(rptr+1, &hdr, &count, &val);
		if (hdr && val && count) {
		    percent_decode(hdr);
		    percent_decode(count);
		    percent_decode(val);
		    if (sscanf(count, "%d", &j) != 1 || j < 1) {
			j = 1;
		    }
		    MD_SMFI_TRY(smfi_chgheader, (ctx, hdr, j, val));
		}
	    }
	    break;

	case 'J':
	    /* Delete a header */
	    if (!rejecting) {
		split_on_space(rptr+1, &hdr, &count);
		if (hdr && count) {
		    percent_decode(hdr);
		    percent_decode(count);
		    if (sscanf(count, "%d", &j) != 1 || j < 1) {
			j = 1;
		    }
		    MD_SMFI_TRY(smfi_chgheader, (ctx, hdr, j, NULL));
		}
	    }
	    break;

	case 'R':
	    /* Add a recipient */
	    if (!rejecting) {
		percent_decode(rptr+1);
		MD_SMFI_TRY(smfi_addrcpt, (ctx, rptr+1));
	    }
	    break;

	case 'Q':
	    /* Quarantine a message using Sendmail's facility */
	    percent_decode(rptr+1);
	    MD_SMFI_TRY(do_sm_quarantine, (ctx, rptr+1));
	    break;

	case 'f':
	    /* Change the "from" address */
#ifdef MILTER_BUILDLIB_HAS_CHGFROM
	    if (!rejecting) {
		percent_decode(rptr+1);
		MD_SMFI_TRY(smfi_chgfrom, (ctx, rptr+1, NULL));
	    }
#else
	    syslog(LOG_WARNING, "%s: change_sender called, but this version of libmilter does not support CHGFROM", data->qid);
#endif
	    break;
	case 'S':
	    /* Delete a recipient */
	    if (!rejecting) {
		percent_decode(rptr+1);
		MD_SMFI_TRY(smfi_delrcpt, (ctx, rptr+1));
	    }
	    break;

	case 'F':
	    seen_F = 1;
	    /* We're done */
	    break;

	default:
	    syslog(LOG_WARNING, "%s: Unknown command '%c' in RESULTS file",
		   data->qid, *rptr);
	}
	if (*rptr == 'F') break;
    }

    if (!seen_F) {
	syslog(LOG_ERR, "%s: RESULTS file did not finish with 'F' line: Tempfailing",
	       data->qid);
	r = SMFIS_TEMPFAIL;
	goto bail_out;
    }
    if (scan_body && *scan_body && !rejecting) {
	if (data->myip) {
	    snprintf(buffer, SMALLBUF, "%s on %s", scan_body, data->myip);
	    buffer[SMALLBUF-1] = 0;
	    MD_SMFI_TRY(smfi_addheader, (ctx, "X-Scanned-By", buffer));
	} else {
	    MD_SMFI_TRY(smfi_addheader, (ctx, "X-Scanned-By", scan_body));
	}
    }

    /* Delete first validation header if it was present */
    if (ValidateHeader[0] && data->validatePresent) {
	MD_SMFI_TRY(smfi_chgheader, (ctx, ValidateHeader, 1, NULL));
    }

    /* Delete any excess Content-Type headers and log */
    if (data->numContentTypeHeaders > 1) {
	syslog(LOG_WARNING, "%s: WARNING: %d Content-Type headers found -- deleting all but first", data->qid, data->numContentTypeHeaders);
	for (j=2; j<=data->numContentTypeHeaders; j++) {
	    MD_SMFI_TRY(smfi_chgheader, (ctx, "Content-Type", j, NULL));
	}
    }

    r = cleanup(ctx);

  bail_out:
    if (rbuf != result) free(rbuf);

    if (LogTimes) {
	long sec_diff, usec_diff;

	gettimeofday(&finish, NULL);

	sec_diff = finish.tv_sec - start.tv_sec;
	usec_diff = finish.tv_usec - start.tv_usec;

	if (usec_diff < 0) {
	    usec_diff += 1000000;
	    sec_diff--;
	}

	/* Convert to milliseconds */
	sec_diff = sec_diff * 1000 + (usec_diff / 1000);
	syslog(LOG_INFO, "%s: Filter time is %ldms", data->qid, sec_diff);
    }

    DEBUG(syslog(LOG_DEBUG, "%p: %s(%d): EXIT %s: %d", ctx, __FILE__, __LINE__, "eom", r));
    return r;
}

/**********************************************************************
*%FUNCTION: mfclose
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
*%RETURNS:
* SMFIS_ACCEPT
*%DESCRIPTION:
* Called when connection is closed.
***********************************************************************/
static sfsistat
mfclose(SMFICTX *ctx)
{
    struct privdata *data = DATA;

    DEBUG_ENTER("mfclose");
    cleanup(ctx);
    if (data) {
	if (data->fd >= 0)       closefd(data->fd);
	if (data->headerFD >= 0) closefd(data->headerFD);
	if (data->cmdFD >= 0)    closefd(data->cmdFD);
	if (data->dir)           free(data->dir);
	if (data->hostname)      free(data->hostname);
	if (data->hostip)        free(data->hostip);
	if (data->myip && data->myip != MyIPAddress) free(data->myip);
	if (data->sender)        free(data->sender);
	if (data->firstRecip)    free(data->firstRecip);
	if (data->heloArg)       free(data->heloArg);
	if (data->qid && data->qid != NOQUEUE) free(data->qid);
	free(data);
    }
    smfi_setpriv(ctx, NULL);
    DEBUG_EXIT("mfclose", "SMFIS_CONTINUE");
    return SMFIS_CONTINUE;
}

/**********************************************************************
*%FUNCTION: mfabort
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* Called if current message is aborted.  Just cleans up.
***********************************************************************/
static sfsistat
mfabort(SMFICTX *ctx)
{
    return cleanup(ctx);
}

/**********************************************************************
*%FUNCTION: cleanup
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
*%RETURNS:
* SMFIS_TEMPFAIL or SMFIS_CONTINUE
*%DESCRIPTION:
* Cleans up temporary files.
***********************************************************************/
static sfsistat
cleanup(SMFICTX *ctx)
{
    sfsistat r = SMFIS_CONTINUE;
    struct privdata *data = DATA;

    DEBUG_ENTER("cleanup");
    if (!data) {
	DEBUG_EXIT("cleanup", "SMFIS_CONTINUE");
	return r;
    }

    if (data->fd >= 0 && (closefd(data->fd) < 0)) {
	syslog(LOG_ERR, "%s: Failure in cleanup line %d: %m",
	       data->qid, __LINE__);
	r = SMFIS_TEMPFAIL;
    }
    data->fd = -1;

    if (data->headerFD >= 0 && (closefd(data->headerFD) < 0)) {
	syslog(LOG_ERR, "%s: Failure in cleanup line %d: %m",
	       data->qid, __LINE__);
	r = SMFIS_TEMPFAIL;
    }
    data->headerFD = -1;

    if (data->cmdFD >= 0 && (closefd(data->cmdFD) < 0)) {
	syslog(LOG_ERR, "%s: Failure in cleanup line %d: %m",
	       data->qid, __LINE__);
	r = SMFIS_TEMPFAIL;
    }
    data->cmdFD = -1;

    remove_working_directory(ctx, data);

    if (data->dir) {
	free(data->dir);
	data->dir = NULL;
    }
    if (data->sender) {
	free(data->sender);
	data->sender = NULL;
    }
    if (data->firstRecip) {
	free(data->firstRecip);
	data->firstRecip = NULL;
    }

    /* Do NOT free qid here; we need it for logging filter times */

    DEBUG_EXIT("cleanup", (r == SMFIS_TEMPFAIL ? "SMFIS_TEMPFAIL" : "SMFIS_CONTINUE"));
    return r;
}

static struct smfiDesc filterDescriptor =
{
    "MIMEDefang-" VERSION,      /* Filter name */
    SMFI_VERSION,		/* Version code */

#if SMFI_VERSION >= 2
    SMFIF_ADDHDRS|SMFIF_CHGBODY|SMFIF_ADDRCPT|SMFIF_DELRCPT|SMFIF_CHGHDRS
#ifdef SMFIF_QUARANTINE
    |SMFIF_QUARANTINE
#endif
#ifdef MILTER_BUILDLIB_HAS_CHGFROM
    |SMFIF_CHGFROM
#endif
    ,
#elif SMFI_VERSION == 1
    /* We can: add a header and may alter body and add/delete recipients*/
    SMFIF_MODHDRS|SMFIF_MODBODY|SMFIF_ADDRCPT|SMFIF_DELRCPT,
#endif

    mfconnect,			/* connection */
    helo,			/* HELO */
    envfrom,			/* MAIL FROM: */
    rcptto,			/* RCPT TO: */
    header,			/* Called for each header */
    eoh,			/* Called at end of headers */
    body,			/* Called for each body chunk */
    eom,			/* Called at end of message */
    mfabort,			/* Called on abort */
    mfclose			/* Called on connection close */
#ifdef MILTER_BUILDLIB_HAS_UNKNOWN
    ,
    mf_unknown			/* xxfi_unknown */
#endif
#ifdef MILTER_BUILDLIB_HAS_DATA
    ,
    mf_data			/* xxfi_data    */
#endif
#ifdef MILTER_BUILDLIB_HAS_NEGOTIATE
    ,
    mf_negotiate                /* xxfi_negotiate */
#endif
};

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
    fprintf(stderr, "mimedefang version %s\n", VERSION);
    fprintf(stderr, "Usage: mimedefang [options]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h                -- Print usage info and exit\n");
    fprintf(stderr, "  -v                -- Print version and exit\n");
    fprintf(stderr, "  -y                -- Invoke smfi_setsymlist to set macro list\n");
    fprintf(stderr, "  -m /path          -- Use /path as UNIX-domain socket for multiplexor\n");
    fprintf(stderr, "  -p /path          -- Path to UNIX-domain socket for sendmail communication\n");
    fprintf(stderr, "  -U user           -- Run as user instead of root\n");
    fprintf(stderr, "  -d                -- Enable debugging (do not remove spool files)\n");
    fprintf(stderr, "  -k                -- Do not remove spool files if filter fails\n");
    fprintf(stderr, "  -z dir            -- Spool directory\n");
    fprintf(stderr, "  -r                -- Do relay check before processing body\n");
    fprintf(stderr, "  -s                -- Do sender check before processing body\n");
    fprintf(stderr, "  -t                -- Do recipient checks before processing body\n");
    fprintf(stderr, "  -q                -- Allow new connections to be queued by multiplexor\n");
    fprintf(stderr, "  -P file           -- Write process-ID of daemon to specified file\n");
    fprintf(stderr, "  -o file           -- Use specified file as a lock file\n");
    fprintf(stderr, "  -T                -- Log filter times to syslog\n");
    fprintf(stderr, "  -b n              -- Set listen() backlog to n\n");
    fprintf(stderr, "  -C                -- Try very hard to conserve file descriptors\n");
    fprintf(stderr, "  -x string         -- Add string as X-Scanned-By header\n");
    fprintf(stderr, "  -X                -- Do not add X-Scanned-By header\n");
    fprintf(stderr, "  -D                -- Do not become a daemon (stay in foreground)\n");
    fprintf(stderr, "  -S facility       -- Set syslog(3) facility\n");
    fprintf(stderr, "  -a macro          -- Pass additional Sendmail macro\n");
    fprintf(stderr, "  -L ip.addr        -- Specify 'equivalent-to-loopback' address\n");
    fprintf(stderr, "  -H                -- Do HELO checks before processing any messages\n");
    fprintf(stderr, "  -c                -- Strip bare <CR> characters from message body\n");
    fprintf(stderr, "  -R num            -- Reserve num workers for connections from localhost\n");
    fprintf(stderr, "  -G                -- Make sockets group-writable and files group-readable\n");
    fprintf(stderr, "  -N                -- Do not pass rejected recipients to milter (Sendmail\n");
    fprintf(stderr, "                       8.14.0 and newer only.)\n");

    exit(EXIT_FAILURE);
}

#define REPORT_FAILURE(msg) do { if (kidpipe[1] >= 0) { write(kidpipe[1], "E" msg, strlen(msg)+1); } else { fprintf(stderr, "%s\n", msg); } } while(0)

/**********************************************************************
* %FUNCTION: main
* %ARGUMENTS:
*  argc, argv -- the usual suspects
* %RETURNS:
*  Whatever smfi_main returns
* %DESCRIPTION:
*  Main program
***********************************************************************/
int
main(int argc, char **argv)
{
    int c;
    int mx_alive;
    pid_t i;
    struct passwd *pw = NULL;
    FILE *fp;
    int facility = LOG_MAIL;
    int nodaemon = 0;
    char buf[SMALLBUF];
    int got_p_option = 0;
    int kidpipe[2];
    char kidmsg[256];
    int pidfile_fd = -1;
    int lockfile_fd = -1;
    int rc;
    int j;
    mode_t socket_umask = 077;
    mode_t file_umask   = 077;

#ifdef ENABLE_DEBUGGING
    /* Keep debugging malloc macros happy... */
    void *ctx = NULL;
#endif

    /* If first arg is "prcap", just print milter capabilities and quit */
    if (argc == 2 && !strcmp(argv[1], "prcap")) {
	dump_milter_buildlib_info();
	exit(0);
    }

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

    MyIPAddress = NULL;
    EquivToLoopback = NULL;

    /* Determine my IP address */
    if (gethostname(buf, sizeof(buf)) >= 0) {
	struct hostent *he = gethostbyname(buf);
	struct in_addr in;
	if (he && he->h_addr) {
	    memcpy(&in.s_addr, he->h_addr, sizeof(in.s_addr));
#ifdef HAVE_INET_NTOP
	    if (inet_ntop(AF_INET, &in.s_addr, buf, sizeof(buf))) {
		if (*buf) MyIPAddress = strdup_with_log(buf);
	    }
#else
	    {
		char *s = inet_ntoa(in);
		if (s && *s) MyIPAddress = strdup_with_log(s);
	    }
#endif
	} else {
	    syslog(LOG_WARNING, "Could not determine my own IP address!  Ensure that %s has an entry in /etc/hosts or the DNS", buf);
	    fprintf(stderr, "Could not determine my own IP address!  Ensure that %s has an entry in /etc/hosts or the DNS\n", buf);
	}
    }

    /* Process command line options */
    while ((c = getopt(argc, argv, "GNCDHL:MP:o:R:S:TU:Xa:b:cdhkm:p:qrstvx:z:y")) != -1) {
	switch (c) {
	case 'y':
	    setsymlist_ok = 1;
	    break;

	case 'G':
	    socket_umask = 007;
	    file_umask   = 027;
	    break;

	case 'N':
#ifdef MILTER_BUILDLIB_HAS_NEGOTIATE
	    SeeRejectedRecipients = 0;
#else
	    fprintf(stderr, "-N option only available with Sendmail/Milter 8.14.0 and higher... ignoring\n");
#endif
	    break;
	case 'R':
	    sscanf(optarg, "%d", &workersReservedForLoopback);
	    if (workersReservedForLoopback < -1) {
		workersReservedForLoopback = -1;
	    }
	    break;
	case 'H':
	    doHeloCheck = 1;
	    break;
	case 'c':
	    StripBareCR = 1;
	    break;
	case 'z':
	    SpoolDir = strdup(optarg);
	    if (!SpoolDir) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'q':
	    AllowNewConnectionsToQueue = 1;
	    break;
	case 'b':
	    sscanf(optarg, "%d", &Backlog);
	    if (Backlog < 5) Backlog = 5;
	    break;
	case 'C':
	    ConserveDescriptors = 1;
	    break;

	case 'v':
	    printf("mimedefang version %s\n", VERSION);
	    exit(0);

	case 'D':
	    nodaemon = 1;
	    break;
	case 'a':
	    if (strlen(optarg) > 200) {
		fprintf(stderr, "%s: Macro name too long: %s\n",
			argv[0], optarg);
		exit(EXIT_FAILURE);
	    }
	    if (NumAdditionalMacros == MAX_ADDITIONAL_SENDMAIL_MACROS) {
		fprintf(stderr, "%s: Too many Sendmail macros (max %d)\n",
			argv[0],
			MAX_ADDITIONAL_SENDMAIL_MACROS);
		exit(EXIT_FAILURE);
	    }
	    AdditionalMacros[NumAdditionalMacros] = strdup(optarg);
	    if (!AdditionalMacros[NumAdditionalMacros]) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    NumAdditionalMacros++;
	    break;
	case 'S':
	    facility = find_syslog_facility(optarg);
	    if (facility < 0) {
		fprintf(stderr, "%s: Unknown syslog facility %s\n",
			argv[0], optarg);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'M':
	    /* Ignore.  This once set protectMkdirWithMutex, which has been removed. */
	    break;
	case 'X':
	    if (scan_body) {
		free(scan_body);
	    }
	    scan_body = strdup("");
	    if (!scan_body) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;

	case 'L':
	    if (EquivToLoopback) {
		free(EquivToLoopback);
	    }
	    EquivToLoopback = strdup(optarg);
	    if (!EquivToLoopback) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;

	case 'x':
	    if (scan_body) {
		free(scan_body);
	    }
	    scan_body = strdup(optarg);
	    if (!scan_body) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;

	case 'T':
	    LogTimes = 1;
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
	case 'o':
	    /* Use this as our lock file */
	    if (lockfile != NULL) free(lockfile);

	    lockfile = strdup(optarg);
	    if (!lockfile) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'P':
	    /* Write our pid to this file */
	    if (pidfile != NULL) free(pidfile);

	    pidfile = strdup(optarg);
	    if (!pidfile) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'k':
	    keepFailedDirectories = 1;
	    break;
	case 's':
	    doSenderCheck = 1;
	    break;
	case 'r':
	    doRelayCheck = 1;
	    break;
	case 't':
	    doRecipientCheck = 1;
	    break;
	case 'h':
	    usage();
	    break;
	case 'm':
	    /* Multiplexor */
	    MultiplexorSocketName = strdup(optarg);
	    if (!MultiplexorSocketName) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'd':
	    DebugMode = 1;
	    break;

	case 'p':
	    if (optarg == NULL || *optarg == '\0') {
		fprintf(stderr, "%s: Illegal conn: %s\n",
			argv[0], optarg);
		exit(EXIT_FAILURE);
	    }
	    got_p_option = 1;
	    /* Remove socket from file system if it's a local socket */
	    (void) remove_local_socket(optarg);
	    if (smfi_setconn(optarg) != MI_SUCCESS) {
		fprintf(stderr, "%s: Could not open connection %s: %s",
			argv[0], optarg, strerror(errno));
		exit(EXIT_FAILURE);
	    }
	    break;
	default:
	    usage();
	    break;
	}
    }

    /* Set SpoolDir if it wasn't set on command line */
    if (!SpoolDir) {
	SpoolDir = SPOOLDIR;
    }
    if (!NoDeleteDir) {
	NoDeleteDir = malloc(strlen(SpoolDir) + strlen(NO_DELETE_NAME) + 1);
	if (!NoDeleteDir) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	strcpy((char *) NoDeleteDir, SpoolDir);
	strcat((char *) NoDeleteDir, NO_DELETE_NAME);
    }

    if (!scan_body) {
	scan_body = SCAN_BODY;
    }

    if (Backlog > 0) {
	smfi_setbacklog(Backlog);
    }

    if (!got_p_option) {
	fprintf(stderr, "%s: You must use the `-p' option.\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    if (!MultiplexorSocketName) {
	fprintf(stderr, "%s: You must use the `-m' option.\n", argv[0]);
	exit(EXIT_FAILURE);
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

    /* Look up user */
    if (user) {
	pw = getpwnam(user);
	if (!pw) {
	    fprintf(stderr, "%s: Unknown user `%s'", argv[0], user);
	    exit(EXIT_FAILURE);
	}
	if (drop_privs(user, pw->pw_uid, pw->pw_gid) < 0) {
	    fprintf(stderr, "%s: Could not drop privileges: %s",
		    argv[0], strerror(errno));
	    exit(EXIT_FAILURE);
	}
	free(user);
    }

    /* Warn */
    if (!getuid() || !geteuid()) {
	fprintf(stderr,
		"ERROR: You must not run mimedefang as root.\n"
		"Use the -U option to set a non-root user.\n");
	exit(EXIT_FAILURE);
    }


    if (chdir(SpoolDir) < 0) {
	fprintf(stderr, "%s: Unable to chdir(%s): %s\n",
		argv[0], SpoolDir, strerror(errno));
	exit(EXIT_FAILURE);
    }

    /* Read key file if present */
    fp = fopen(KEY_FILE, "r");
    if (fp) {
	fgets(ValidateHeader, sizeof(ValidateHeader), fp);
	fclose(fp);
	chomp(ValidateHeader);
    } else {
	ValidateHeader[0] = 0;
    }
    if (smfi_register(filterDescriptor) == MI_FAILURE) {
	fprintf(stderr, "%s: smfi_register failed\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    (void) closelog();

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
	    close(kidpipe[1]);

	    /* Wait for a message from kid */
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

	/* In the child */
	close(kidpipe[0]);
	setsid();
	signal(SIGHUP, SIG_IGN);
	i = fork();
	if (i < 0) {
	    REPORT_FAILURE("fork() failed");
	    exit(EXIT_FAILURE);
	} else if (i != 0) {
	    exit(EXIT_SUCCESS);
	}
    } else {
	/* nodaemon */
	kidpipe[0] = -1;
	kidpipe[1] = -1;
    }

    /* In the actual daemon */
    for (j=0; j<CLOSEFDS; j++) {
	/* If we are not a daemon, leave stdin/stdout/stderr open */
	if (nodaemon && j < 3) {
	    continue;
	}
	if (j != pidfile_fd && j != kidpipe[1]) {
	    close(j);
	}
    }

    /* Do the locking */
    if (pidfile || lockfile) {
	if ( (lockfile_fd = write_and_lock_pidfile(pidfile, lockfile, pidfile_fd)) < 0) {
	    /* Signal the waiting parent */
	    REPORT_FAILURE("Cannot lock lockfile: Is another copy running?");
	    exit(EXIT_FAILURE);
	}
    }

    /* Direct stdin/stdout/stderr to /dev/null */
    if (!nodaemon) {
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
    }

    openlog("mimedefang", LOG_PID, facility);

    /* Open the milter socket if library has smfi_opensocket */
#ifdef MILTER_BUILDLIB_HAS_OPENSOCKET
    umask(socket_umask);
    (void) smfi_opensocket(1);
    umask(file_umask);
#else
    /* Gah, we can't create the socket, so use socket_umask throughout */
    umask(socket_umask);
#endif

    if (ValidateHeader[0]) {
	syslog(LOG_DEBUG, "IP validation header is %s", ValidateHeader);
    }
    syslog(LOG_INFO, "MIMEDefang alive. workersReservedForLoopback=%d AllowNewConnectionsToQueue=%d doRelayCheck=%d doHeloCheck=%d doSenderCheck=%d doRecipientCheck=%d", workersReservedForLoopback, AllowNewConnectionsToQueue, doRelayCheck, doHeloCheck, doSenderCheck, doRecipientCheck);

#ifdef ENABLE_DEBUGGING
    signal(SIGSEGV, handle_sig);
    signal(SIGBUS, handle_sig);
#endif

    /* Wait up to 20 seconds for the multiplexor to come alive */
    mx_alive = 0;
    for (c=0; c<100; c++) {
	struct timeval sleeptime;
	sleeptime.tv_sec = 0;
	sleeptime.tv_usec = 200000;
	if (MXCheckFreeWorkers(MultiplexorSocketName, NULL) >= 0) {
	    mx_alive = 1;
	    break;
	}
	/* Sleep for 200ms */
	select(0, NULL, NULL, NULL, &sleeptime);
    }
    if (mx_alive) {
	syslog(LOG_INFO, "Multiplexor alive - entering main loop");
    } else {
	/* Signal the waiting parent */
	REPORT_FAILURE("Multiplexor socket did not appear.  Exiting.");
	if (pidfile) unlink(pidfile);
	if (lockfile) unlink(lockfile);
	exit(EXIT_FAILURE);
    }

    /* Tell the waiting parent that everything is A-OK */
    if (kidpipe[1] >= 0) {
	write(kidpipe[1], "X", 1);
	close(kidpipe[1]);
    }
    rc = (int) smfi_main();
    if (pidfile) {
	unlink(pidfile);
    }
    if (lockfile) {
	unlink(lockfile);
    }
    return rc;
}

/**********************************************************************
* %FUNCTION: append_macro_value
* %ARGUMENTS:
*  ctx -- Sendmail milter context
*  macro -- name of a macro
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends a command to Perl code to set a macro value
***********************************************************************/
static void
append_macro_value(dynamic_buffer *dbuf,
		   SMFICTX *ctx,
		   char *macro)
{
    struct privdata *data;
    char *val;
    char buf[256];

    data = DATA;
    if (!data) return;

    if (*macro && *(macro+1)) {
	/* Longer than 1 char -- use curlies */
	snprintf(buf, sizeof(buf), "{%s}", macro);
	val = smfi_getsymval(ctx, buf);
    } else {
	val = smfi_getsymval(ctx, macro);
    }
    if (!val) return;
    dbuf_putc(dbuf, '=');
    append_percent_encoded(dbuf, macro);
    dbuf_putc(dbuf, ' ');
    append_percent_encoded(dbuf, val);
    dbuf_putc(dbuf, '\n');
}

/**********************************************************************
* %FUNCTION: remove_working_directory
* %ARGUMENTS:
*  data -- our private data
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Removes working directory if appropriate.
***********************************************************************/
static void
remove_working_directory(SMFICTX *ctx, struct privdata *data)
{
    if (!data || !data->dir || !*(data->dir)) return;

    /* Don't remove if in debug mode or various other reasons */
    if (DebugMode) {
	syslog(LOG_INFO, "%s: Not cleaning up %s because of command-line `-d' flag",
	       data->qid,
	       data->dir);
	return;
    }

    if (access(NoDeleteDir, F_OK) == 0) {
	syslog(LOG_INFO, "%s: Not cleaning up %s because of %s",
	       data->qid,
	       (data->dir ? data->dir : ""),
	       NoDeleteDir);
	return;
    }

    if (keepFailedDirectories && data->filterFailed) {
	syslog(LOG_WARNING, "%s: Filter failed.  Message kept in %s",
	       data->qid, data->dir);
	return;
    }

    if (rm_r(data->qid, data->dir) < 0) {
	syslog(LOG_ERR, "%s: failed to clean up %s: %m",
	       data->qid, data->dir);
    }
}

/**********************************************************************
* %FUNCTION: set_dsn
* %ARGUMENTS:
*  data -- our private data area
*  ctx -- Milter context
*  buf2 -- return from a relay/sender/filter check.  Consists of
*    space-separated "reply code dsn sleep_amount" list.
*  num -- 0, 4 or 5 -- if 4 or 5, we use the code and dsn in set_reply.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sets SMTP reply and possibly delays
***********************************************************************/
static void
set_dsn(SMFICTX *ctx, char *buf2, int num) {
    char *reply, *code, *dsn, *sleepstr;

    if (*buf2) {
	split_on_space4(buf2, &reply, &code, &dsn, &sleepstr);
	percent_decode(code);
	percent_decode(dsn);
	percent_decode(reply);
	percent_decode(sleepstr);
	do_delay(sleepstr);
	if (num == 4 || num == 5) {
	    struct privdata *data = DATA;
	    if (num == 5) {
		MD_SMFI_TRY(set_reply, (ctx, "5", code, dsn, reply));
	    } else {
		MD_SMFI_TRY(set_reply, (ctx, "4", code, dsn, reply));
	    }
	}
    }
}

/**********************************************************************
* %FUNCTION: do_sm_quarantine
* %ARGUMENTS:
*  ctx -- Milter context
*  reason -- reason for quarantine
* %RETURNS:
*  Whatever smfi_quarantine returns
* %DESCRIPTION:
*  Quarantines a message using Sendmail's quarantine facility, if supported.
***********************************************************************/
static int
do_sm_quarantine(SMFICTX *ctx,
		 char const *reason)
{
#ifdef SMFIF_QUARANTINE
    return smfi_quarantine(ctx, (char *) reason);
#else
    syslog(LOG_WARNING, "smfi_quarantine not supported: Requires Sendmail 8.13.0 or later");
    return MI_FAILURE;
#endif
}

/**********************************************************************
* %FUNCTION: append_percent_encoded
* %ARGUMENTS:
*  dbuf -- dynamic buffer to append to
*  buf -- a buffer
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Appends a percent-encoded version of "buf" to dbuf.
***********************************************************************/
static void
append_percent_encoded(dynamic_buffer *dbuf,
		       char const *buf)
{
    char pbuf[16];
    unsigned char const *ubuf = (unsigned char const *) buf;
    unsigned int c;
    while ((c = *ubuf++) != 0) {
	if (c <= 32 || c > 126 || c == '%') {
	    sprintf(pbuf, "%%%02X", c);
	    dbuf_puts(dbuf, pbuf);
	} else {
	    dbuf_putc(dbuf, c);
	}
    }
}

/**********************************************************************
* %FUNCTION: append_mx_command
* %ARGUMENTS:
*  dbuf -- dynamic buffer to append to
*  cmd -- the command to write.  A single character.
*  buf -- command arguments
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Appends a command to dynamic buffer
***********************************************************************/
static void
append_mx_command(dynamic_buffer *dbuf,
		  char cmd,
		  char const *buf)
{
    dbuf_putc(dbuf, cmd);
    if (buf) {
	append_percent_encoded(dbuf, buf);
    }
    dbuf_putc(dbuf, '\n');
}

/**********************************************************************
* %FUNCTION: safe_append_header
* %ARGUMENTS:
*  dbuf -- dynamic buffer to append to
*  str -- a string value
* %RETURNS:
*  0 if header seems OK; 1 if suspicious character found.
* %DESCRIPTION:
*  Writes "str" to dbuf with the following changes:
*    CR   -> written as space
***********************************************************************/
static int
safe_append_header(dynamic_buffer *dbuf,
		   char *str)
{
    int suspicious = 0;

    for(; *str; str++) {
	/* Do not write \r to header file -- convert to space */
	if (*str == '\r') {
	    if (*(str+1) != '\n') {
		suspicious = 1;
		dbuf_putc(dbuf, ' ');
		continue;
	    }
	}
	dbuf_putc(dbuf, *str);
    }
    return suspicious;
}

static int
write_dbuf(dynamic_buffer *dbuf,
	   int fd,
	   struct privdata *data,
	   char const *filename)
{
    int i;
    i = writen(fd, DBUF_VAL(dbuf), DBUF_LEN(dbuf));
    if (i == DBUF_LEN(dbuf)) {
	return 0;
    }
    syslog(LOG_WARNING, "%s: Unable to write %d bytes to file %s (ret = %d): %m",
	   data->qid, DBUF_LEN(dbuf), filename, i);
    return -1;
}

/**********************************************************************
*%FUNCTION: set_queueid
*%ARGUMENTS:
* ctx -- Sendmail filter mail context
*%RETURNS:
* -2: Could not set queue ID because no 'i' macro available
* -1: Some other error (eg, strdup failed)
*  0: Success
*%DESCRIPTION:
* Obtains the Sendmail "i" macro and sets the privata data->qid
* string to the value of the macro, if its value could be obtained.
***********************************************************************/
static int
set_queueid(SMFICTX *ctx)
{
    struct privdata *data = DATA;
    char const *queueid;

    /* This should never happen... not much we can do if it does */
    if (!data) {
        return -1;
    }

    /* Get value of "i" macro */
    queueid = smfi_getsymval(ctx, "i");

    if (!queueid) {
        /* Macro not set - nothing we can do.  */
        return -2;
    }

    /* If qid is already set and is the same as what
       we have, do nothing */
    if (data->qid && !strcmp(data->qid, queueid)) {
        return 0;
    }

    /* If qid is already set, free it */
    if (data->qid && data->qid != NOQUEUE) {
        free(data->qid);
        data->qid_written = 0;
    }
    data->qid = strdup_with_log(queueid);
    if (!data->qid) {
        data->qid = NOQUEUE;
        return -1;
    }
    return 0;
}
