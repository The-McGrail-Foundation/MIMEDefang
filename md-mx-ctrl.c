/***********************************************************************
*
* md-mx-ctrl.c
*
* Command-line utility for talking to mimedefang-multiplexor directly
*
* Copyright (C) 2002-2005 by Roaring Penguin Software Inc.
*
* http://www.roaringpenguin.com
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2, or (at your option) any later version.
*
***********************************************************************/

#include "config.h"
#define SMALLBUF 262144

#include <ctype.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

char cmdbuf[SMALLBUF+1];
int read_stdin = 0;
FILE *errfp;

static int
percent_encode(unsigned char *in,
	       unsigned char *out,
	       int outlen);

static int process(char const *sock, char const *cmd);

/**********************************************************************
* %FUNCTION: percent_decode
* %ARGUMENTS:
*  buf -- a buffer with percent-encoded data
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Decodes buf IN PLACE.
***********************************************************************/
static void
percent_decode(unsigned char *buf)
{
    unsigned char *in = buf;
    unsigned char *out = buf;
    unsigned int val;

    while(*in) {
	if (*in == '%' && isxdigit(*(in+1)) && isxdigit(*(in+2))) {
	    sscanf((char *) in+1, "%2x", &val);
	    *out++ = (unsigned char) val;
	    in += 3;
	    continue;
	}
	*out++ = *in++;
    }
    /* Copy terminator */
    *out = 0;
}

/**********************************************************************
* %FUNCTION: MXCommand
* %ARGUMENTS:
*  sockname -- multiplexor socket name
*  cmd -- command to send
*  buf -- buffer for reply
*  len -- length of buffer
* %RETURNS:
*  0 if all went well, -1 on error.
* %DESCRIPTION:
*  Sends a command to the multiplexor and reads the answer back.
***********************************************************************/
static int
MXCommand(char const *sockname,
	  char const *cmd,
	  char *buf,
	  int len)
{
    int fd;
    struct sockaddr_un addr;
    int nleft, nwritten, nread;
    int n;

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
	fprintf(errfp, "ERROR MXCommand: socket: %s\n", strerror(errno));
	return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, sockname, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	if (errno == EPERM || errno == EACCES) {
	    fprintf(errfp, "ERROR MXCommand: connect: %s\n", strerror(errno));
	} else {
	    fprintf(errfp,
		    "ERROR MXCommand: connect: %s: Is multiplexor running?\n",
		strerror(errno));
	}
	close(fd);
	return -1;
    }

    nwritten = 0;
    nleft = strlen(cmd);
    n = 0;
    while(nleft) {
	n = write(fd, cmd+nwritten, nleft);
	if (n < 0) {
	    if (errno == EINTR) continue;
	    break;
	}
	nwritten += n;
	nleft -= n;
    }
    if (n < 0) {
	fprintf(errfp, "ERROR MXCommand: write: %s: Is multiplexor running?\n",
		strerror(errno));
	close(fd);
	return -1;
    }

    /* Now read the answer */
    nread = 0;
    nleft = len;
    while(nleft) {
	n = read(fd, buf+nread, nleft);
	if (n <= 0) {
	    if (n < 0 && errno == EINTR) continue;
	    break;
	}
	nread += n;
	nleft -= n;
    }
    if (n < 0) {
	fprintf(errfp, "ERROR MXCommand: read: %s: Is multiplexor running?\n",
		strerror(errno));
	close(fd);
	return -1;
    }
    buf[nread] = 0;
    close(fd);
    return 0;
}

static void
buildCmd(int argc, char *argv[], char *outbuf, int buflen)
{
    int i;
    int k;
    int len = 0;
    for (i=0; i<argc; i++) {
	k = percent_encode((unsigned char *) argv[i], (unsigned char *) outbuf+len, buflen-len);
	len += k;
	if (len >= buflen-1) {
	    outbuf[buflen-1] = 0;
	    return;
	}
	if (i < argc-1) {
	    outbuf[len] = ' ';
	    len++;
	}
    }
    outbuf[len++] = '\n';
    outbuf[len] = 0;
}

static int
percent_encode(unsigned char *in,
	       unsigned char *out,
	       int outlen)
{
    unsigned char tmp[8];
    int nwritten = 0;
    unsigned char c;

    if (outlen <= 0) {
	return 0;
    }
    if (outlen == 1) {
	*out = 0;
	return 0;
    }

    /* Do real work */
    while((c = *in++) != 0) {
	if (c <= 32 || c > 126 || c == '%' || c == '\\' || c == '\'' || c == '"') {
	    if (nwritten >= outlen-3) {
		break;
	    }
	    sprintf((char *) tmp, "%%%02X", (unsigned int) c);
	    *out++ = tmp[0];
	    *out++ = tmp[1];
	    *out++ = tmp[2];
	    nwritten += 3;
	} else {
	    *out++ = c;
	    nwritten++;
	}
	if (nwritten >= outlen-1) {
	    break;
	}
    }
    out[nwritten] = 0;
    return nwritten;
}
static int
doCmd(char const *sock, char const *cmd, int decode)
{
    char ans[SMALLBUF];
    size_t l;

    if (MXCommand(sock, cmd, ans, sizeof(ans)) < 0) {
	return EXIT_FAILURE;
    }
    if (decode) {
	percent_decode((unsigned char *)ans);
    }
    printf("%s", ans);

    /* If it didn't end with a newline, add one */
    l = strlen(ans);
    if (l > 0) {
	if (ans[l-1] != '\n') {
	    printf("\n");
	}
    }

    return EXIT_SUCCESS;
}

static int
doStatus(char const *sock)
{
    char ans[4096];
    char *s;
    int i, l;

    if (MXCommand(sock, "status\n", ans, sizeof(ans)) < 0) {
	return EXIT_FAILURE;
    }
    if (*ans != 'I' && *ans != 'K' && *ans != 'S' && *ans != 'B') {
	fprintf(errfp, "ERROR %s", ans);
	return EXIT_FAILURE;
    }

    /* Chop off message and activation count */
    s = ans;
    while (*s && *s != ' ') s++;
    *s = 0;

    l = strlen(ans);
    printf("Max workers: %d\n", l);
    for (i=0; i<l; i++) {
	printf("Worker %d: ", i);
	switch(ans[i]) {
	case 'I':
	    printf("idle\n");
	    break;
	case 'K':
	    printf("killed\n");
	    break;
	case 'S':
	    printf("stopped\n");
	    break;
	case 'B':
	    printf("busy\n");
	    break;
	default:
	    printf("unknown state '%c'\n", ans[i]);
	}
    }
    return EXIT_SUCCESS;
}

#define BARLEN 25
#define QBARLEN 20
static int
doBarStatus(char const *sock)
{
    char ans[4096];
    char *s;
    int i;
    int nbusy, ntotal, nqueued, maxqueue;
    int nmsgs;

    if (MXCommand(sock, "status\n", ans, sizeof(ans)) < 0) {
	return EXIT_FAILURE;
    }
    if (*ans != 'I' && *ans != 'K' && *ans != 'S' && *ans != 'B') {
	fprintf(errfp, "ERROR %s", ans);
	return EXIT_FAILURE;
    }

    nbusy = 0;
    ntotal = 0;
    nqueued = 0;
    maxqueue = 0;

    /* Count number of busy workers */
    s = ans;
    while (*s && *s != ' ') {
	if (*s == 'B') {
	    nbusy++;
	}
	ntotal++;
	s++;
    }

    if (ntotal == 0) {
	printf("Max 0 workers ??\n");
	return EXIT_SUCCESS;
    }

    /* Get num queue and max queued */
    sscanf(s, "%d %d %d %d", &nmsgs, &i, &maxqueue, &nqueued);

    /* Print busy graph */
    printf("%3d/%d ", nbusy, ntotal);
    if (ntotal <= BARLEN) {
	for (i=0; i<ntotal; i++) {
	    if (i < nbusy) {
		printf("B");
	    } else {
		printf(".");
	    }
	}
    } else {
	for (i=0; i<BARLEN; i++) {
	    if (i < ( (float) nbusy / (float) ntotal) * (float) BARLEN) {
		printf("B");
	    } else {
		printf(".");
	    }
	}
    }
    if (maxqueue == 0) {
	printf(" %d\n", nmsgs);
	return EXIT_SUCCESS;
    }

    printf("  %3d/%d ", nqueued, maxqueue);
    if (maxqueue <= QBARLEN) {
	for (i=0; i<maxqueue; i++) {
	    if (i < nqueued) {
		printf("Q");
	    } else {
		printf(".");
	    }
	}
    } else {
	for (i=0; i<QBARLEN; i++) {
	    if (i < (float) nqueued / (float) maxqueue * (float) QBARLEN) {
		printf("Q");
	    } else {
		printf(".");
	    }
	}
    }
    printf(" %d\n", nmsgs);
    return EXIT_SUCCESS;
}

static int
doHLoad(char const *rawcmd,
	char const *msgstr,
	char const *scanstr,
	char const *sock)
{
    char ans[4096];
    int msgs_1, msgs_4, msgs_12, msgs_24;
    int secs_1, secs_4, secs_12, secs_24;
    double avg_1, avg_4, avg_12, avg_24;
    double mps_1, mps_4, mps_12, mps_24;
    double ams_1, ams_4, ams_12, ams_24;

    char persec[256];
    char ms[256];
    sprintf(persec, "%s/Sec", msgstr);
    sprintf(ms, "Avg ms/%s", scanstr);

    if (MXCommand(sock, rawcmd, ans, sizeof(ans)) < 0) {
	return EXIT_FAILURE;
    }

    sscanf(ans, "%d %d %d %d %lf %lf %lf %lf %lf %lf %lf %lf %d %d %d %d",
	   &msgs_1, &msgs_4, &msgs_12, &msgs_24,
	   &avg_1, &avg_4, &avg_12, &avg_24,
	   &ams_1, &ams_4, &ams_12, &ams_24,
	   &secs_1, &secs_4, &secs_12, &secs_24);

    if (secs_1) mps_1 = (double) msgs_1 / (double) secs_1;
    else        mps_1 = 0;
    if (secs_4) mps_4 = (double) msgs_4 / (double) secs_4;
    else        mps_4 = 0;
    if (secs_12) mps_12 = (double) msgs_12 / (double) secs_12;
    else        mps_12 = 0;
    if (secs_24) mps_24 = (double) msgs_24 / (double) secs_24;
    else        mps_24 = 0;

    printf("%6s %17s %15s %15s %s\n", "Load", msgstr, persec, ms, "  Avg Busy Workers");
    printf("%6s %15d %15.2f %15.1f %15.2f\n", " 1h", msgs_1, mps_1, ams_1, avg_1);
    printf("%6s %15d %15.2f %15.1f %15.2f\n", " 4h", msgs_4, mps_4, ams_4, avg_4);
    printf("%6s %15d %15.2f %15.1f %15.2f\n", "12h", msgs_12, mps_12, ams_12, avg_12);
    printf("%6s %15d %15.2f %15.1f %15.2f\n", "24h", msgs_24, mps_24, ams_24, avg_24);
    return EXIT_SUCCESS;
}

static int
doLoad1(char const *sock,
	char const *cmd)
{
    char ans[4096];

    int num_scans, num_relayoks, num_senderoks, num_recipoks;
    double avg_scans, avg_relayoks, avg_senderoks, avg_recipoks;
    double ms_scans, ms_relayoks, ms_senderoks, ms_recipoks;
    int busy_workers, idle_workers, stopped_workers, killed_workers;
    int msgs_processed, activations, queue_size, queued_requests, uptime, back;
    int cscan, crelayok, csenderok, crecipok;

    if (MXCommand(sock, cmd, ans, sizeof(ans)) < 0) {
	return EXIT_FAILURE;
    }
    if (sscanf(ans, "%d %lf %lf %d %lf %lf %d %lf %lf %d %lf %lf %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
	       &num_scans, &avg_scans, &ms_scans,
	       &num_relayoks, &avg_relayoks, &ms_relayoks,
	       &num_senderoks, &avg_senderoks, &ms_senderoks,
	       &num_recipoks, &avg_recipoks, &ms_recipoks,
	       &busy_workers, &idle_workers, &stopped_workers, &killed_workers,
	       &msgs_processed, &activations, &queue_size, &queued_requests, &uptime, &back, &cscan, &crelayok, &csenderok, &crecipok) != 26) {
	printf("Could not interpret response: %s", ans);
	return EXIT_FAILURE;
    }

    printf("Statistics for last %d seconds:\n", back);
    printf("%10s %15s %15s %15s %15s\n", "Cmd", "Num", "Num/s", "AvgWorkers", "AvgMS");
    printf("%10s %15d %15.1f %15.1f %15.1f\n", "Scan", num_scans, (double) num_scans / (double) back, avg_scans, ms_scans);
    printf("%10s %15d %15.1f %15.1f %15.1f\n", "Relayok", num_relayoks, (double) num_relayoks / (double) back, avg_relayoks, ms_relayoks);
    printf("%10s %15d %15.1f %15.1f %15.1f\n", "Senderok", num_senderoks, (double) num_senderoks / (double) back, avg_senderoks, ms_senderoks);
    printf("%10s %15d %15.1f %15.1f %15.1f\n", "Recipok", num_recipoks, (double) num_recipoks / (double) back, avg_recipoks, ms_recipoks);
    printf("\nCurrent Snapshot:\nWorkers: busy=%d idle=%d stopped=%d killed=%d\n", busy_workers, idle_workers, stopped_workers, killed_workers);
    printf("Cmds:   scan=%d relayok=%d senderok=%d recipok=%d\n", cscan, crelayok, csenderok, crecipok);
    printf("Queue:  size=%d queued=%d\n", queue_size, queued_requests);
    return EXIT_SUCCESS;
}

static int
doLoad(char const *rawcmd,
       char const *msgstr,
       char const *scanstr,
       char const *sock)
{
    char ans[4096];
    int msgs_0, msgs_1, msgs_5, msgs_10;
    double avg_0, avg_1, avg_5, avg_10;
    double mps_0, mps_1, mps_5, mps_10;
    double ams_0, ams_1, ams_5, ams_10;

    char persec[256];
    char ms[256];
    sprintf(persec, "%s/Sec", msgstr);
    sprintf(ms, "Avg ms/%s", scanstr);

    if (MXCommand(sock, rawcmd, ans, sizeof(ans)) < 0) {
	return EXIT_FAILURE;
    }

    sscanf(ans, "%d %d %d %d %lf %lf %lf %lf %lf %lf %lf %lf",
	   &msgs_0, &msgs_1, &msgs_5, &msgs_10,
	   &avg_0, &avg_1, &avg_5, &avg_10,
	   &ams_0, &ams_1, &ams_5, &ams_10);

    mps_0 = (double) msgs_0 / 10.0;
    mps_1 = (double) msgs_1 / 60.0;
    mps_5 = (double) msgs_5 / (5*60.0);
    mps_10 = (double) msgs_10 / (10*60.0);

    printf("%6s %17s %15s %15s %s\n", "Load", msgstr, persec, ms, "  Avg Busy Workers");
    printf("%6s %15d %15.2f %15.1f %15.2f\n", "10 Sec", msgs_0, mps_0, ams_0, avg_0);
    printf("%6s %15d %15.2f %15.1f %15.2f\n", "1 Min", msgs_1, mps_1, ams_1, avg_1);
    printf("%6s %15d %15.2f %15.1f %15.2f\n", "5 Min", msgs_5, mps_5, ams_5, avg_5);
    printf("%6s %15d %15.2f %15.1f %15.2f\n", "10 Min", msgs_10, mps_10, ams_10, avg_10);
    return EXIT_SUCCESS;
}

static void
usage(char const *sock)
{
    char ans[SMALLBUF];
    fprintf(stderr, "Usage: md-mx-ctrl [options] command\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "-h              -- Display help\n");
    fprintf(stderr, "-s path         -- Specify path to multiplexor socket\n");
    fprintf(stderr, "-i              -- Read commands from stdin\n");
    if (!sock) {
	sock = SPOOLDIR "/mimedefang-multiplexor.sock";
    }
    if (MXCommand(sock, "help\n", ans, sizeof(ans)) >= 0) {
	fprintf(stderr, "\nPossible commands:\n%s", ans);
    }
}

int
main(int argc, char *argv[])
{
    int c;

    char *sock = NULL;
    errfp = stderr;

    while ((c = getopt(argc, argv, "hs:i")) != -1) {
	switch(c) {
	case 'i':
	    read_stdin = 1;
	    errfp = stdout;
	    break;
	case 'h':
	    usage(sock);
	    exit(EXIT_SUCCESS);
	case 's':
	    if (sock) free(sock);
	    sock = strdup(optarg);
	    if (!sock) {
		fprintf(stderr, "Out of memory\n");
		exit(EXIT_FAILURE);
	    }
	    break;
	default:
	    usage(sock);
	    exit(EXIT_FAILURE);
	}
    }

    if (!read_stdin && !argv[optind]) {
	usage(sock);
	exit(EXIT_FAILURE);
    }
    if (!sock) {
	sock = SPOOLDIR "/mimedefang-multiplexor.sock";
    }


    if (read_stdin) {
	while(fgets(cmdbuf, SMALLBUF, stdin)) {
	    process(sock, cmdbuf);
	    fflush(stdout);
	}
    } else {
	buildCmd(argc-optind, argv+optind, cmdbuf, SMALLBUF);
	exit(process(sock, cmdbuf));
    }
    exit(EXIT_SUCCESS);
}

static int
process(char const *sock, char const *cmd) {
    if (!strcmp(cmd, "status\n")) {
	return doStatus(sock);
    } else if (!strcmp(cmd, "barstatus\n")) {
	return doBarStatus(sock);
    } else if (!strcmp(cmd, "reread\n")) {
	return doCmd(sock, "reread\n", 0);
    } else if (!strcmp(cmd, "rawstatus\n")) {
	return doCmd(sock, "status\n", 0);
    } else if (!strcmp(cmd, "msgs\n")) {
	return doCmd(sock, "msgs\n", 0);
    } else if (!strcmp(cmd, "rawload\n")) {
	return doCmd(sock, "load\n", 0);
    } else if (!strcmp(cmd, "rawload-relayok\n")) {
	return doCmd(sock, "load-relayok\n", 0);
    } else if (!strncmp(cmd, "rawload1 ", 9)) {
	return doCmd(sock, cmd+3, 0);
    } else if (!strncmp(cmd, "load1 ", 6)) {
	return doLoad1(sock, cmd);
    } else if (!strcmp(cmd, "rawload-senderok\n")) {
	return doCmd(sock, "load-senderok\n", 0);
    } else if (!strcmp(cmd, "rawload-recipok\n")) {
	return doCmd(sock, "load-recipok\n", 0);
    } else if (!strcmp(cmd, "rawhload\n")) {
	return doCmd(sock, "hload\n", 0);
    } else if (!strcmp(cmd, "rawhload-relayok\n")) {
	return doCmd(sock, "hload-relayok\n", 0);
    } else if (!strcmp(cmd, "rawhload-senderok\n")) {
	return doCmd(sock, "hload-senderok\n", 0);
    } else if (!strcmp(cmd, "rawhload-recipok\n")) {
	return doCmd(sock, "hload-recipok\n", 0);
    } else if (!strcmp(cmd, "load\n")) {
	return doLoad(cmd, "Msgs", "Scan", sock);
    } else if (!strcmp(cmd, "load-relayok\n")) {
	return doLoad(cmd, "Conn", "Conn", sock);
    } else if (!strcmp(cmd, "load-senderok\n")) {
	return doLoad(cmd, "MAIL", "MAIL", sock);
    } else if (!strcmp(cmd, "load-recipok\n")) {
	return doLoad(cmd, "RCPT", "RCPT", sock);
    } else if (!strcmp(cmd, "hload\n")) {
	return doHLoad(cmd, "Msgs", "Scan", sock);
    } else if (!strcmp(cmd, "hload-relayok\n")) {
	return doHLoad(cmd, "Conn", "Conn", sock);
    } else if (!strcmp(cmd, "hload-senderok\n")) {
	return doHLoad(cmd, "MAIL", "MAIL", sock);
    } else if (!strcmp(cmd, "hload-recipok\n")) {
	return doHLoad(cmd, "RCPT", "RCPT", sock);
    } else {
	return doCmd(sock, cmd, 1);
    }
}
