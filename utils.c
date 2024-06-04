/***********************************************************************
*
* utils.c
*
* Utility functions for MIMEDefang
*
* Copyright (C) 2002-2005 Roaring Penguin Software Inc.
* http://www.roaringpenguin.com
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#define _DEFAULT_SOURCE 1

#include "config.h"
#include "mimedefang.h"

#include <stdio.h>
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
#include <netinet/in.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef ENABLE_DEBUGGING
extern void *malloc_debug(void *, size_t, char const *fname, int);
extern char *strdup_debug(void *, char const *, char const *, int);
extern void free_debug(void *, void *, char const *, int);
#undef malloc
#undef strdup
#undef free
#define malloc(x) malloc_debug(ctx, x, __FILE__, __LINE__)
#define strdup(x) strdup_debug(ctx, x, __FILE__, __LINE__)
#define free(x) free_debug(ctx, x, __FILE__, __LINE__)
#define malloc_with_log(x) malloc_debug(ctx, x, __FILE__, __LINE__)
#define strdup_with_log(x) strdup_debug(x, __FILE__, __LINE__)
#endif

#ifndef HAVE_UINT32_T
/* On these machines, punt to unsigned int */
typedef unsigned int uint32_t;
#endif

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

#ifndef SUN_LEN
#define SUN_LEN(ptr)  ((size_t) (((struct sockaddr_un *) 0)->sun_path) \
       + strlen ((ptr)->sun_path))
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

static int percent_encode_command(int term_with_newline,
				  char *out, int outlen, ...);

/**********************************************************************
* %FUNCTION: split_on_space
* %ARGUMENTS:
*  buf -- input buffer
*  first -- set to first word
*  rest -- set to everything following a space, or NULL if no space
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Splits a line on whitespace.
***********************************************************************/
void
split_on_space(char *buf,
	       char **first,
	       char  **rest)
{
    *first = buf;
    *rest = NULL;
    while(*buf && !isspace(*buf)) buf++;
    if (*buf && isspace(*buf)) {
	*buf = 0;
	*rest = buf+1;
    }
}

/**********************************************************************
* %FUNCTION: split_on_space3
* %ARGUMENTS:
*  buf -- input buffer
*  first -- set to first word
*  second -- set to second word or NULL
*  rest -- set to everything following a space, or NULL if no space
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Splits a line on whitespace.
***********************************************************************/
void
split_on_space3(char *buf,
		char **first,
		char **second,
		char **rest)
{
    *first = buf;
    *second = NULL;
    *rest = NULL;
    while(*buf && !isspace(*buf)) buf++;
    if (*buf && isspace(*buf)) {
	*buf = 0;
	*second = buf+1;
	buf++;
	while(*buf && !isspace(*buf)) buf++;
	if (*buf && isspace(*buf)) {
	    *buf = 0;
	    *rest = buf+1;
	}
    }
}

/**********************************************************************
* %FUNCTION: split_on_space4
* %ARGUMENTS:
*  buf -- input buffer
*  first -- set to first word
*  second -- set to second word or NULL
*  third -- set to third word or NULL
*  rest -- set to everything following a space, or NULL if no space
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Splits a line on whitespace.
***********************************************************************/
void
split_on_space4(char *buf,
		char **first,
		char **second,
		char **third,
		char **rest)
{
    *first = buf;
    *second = NULL;
    *third = NULL;
    *rest = NULL;
    while(*buf && !isspace(*buf)) buf++;
    if (*buf && isspace(*buf)) {
	*buf = 0;
	*second = buf+1;
	buf++;
	while(*buf && !isspace(*buf)) buf++;
	if (*buf && isspace(*buf)) {
	    *buf = 0;
	    *third = buf+1;
	    buf++;
	    while(*buf && !isspace(*buf)) buf++;
	    if (*buf && isspace(*buf)) {
		*buf = 0;
		*rest = buf+1;
	    }
	}
    }
}

#ifndef ENABLE_DEBUGGING
/**********************************************************************
* %FUNCTION: malloc_with_log
* %ARGUMENTS:
*  size -- amount of memory to allocate
* %RETURNS:
*  Allocated memory
* %DESCRIPTION:
*  Calls malloc, but syslogs an error on failure to allocate memory.
***********************************************************************/
void *
malloc_with_log(size_t s)
{
    void *p = malloc(s);
    if (!p) {
	syslog(LOG_WARNING, "Failed to allocate %lu bytes of memory",
	       (unsigned long) s);
    }
    return p;
}

/**********************************************************************
* %FUNCTION: strdup_with_log
* %ARGUMENTS:
*  s -- string to strdup
* %RETURNS:
*  A copy of s in malloc'd memory.
* %DESCRIPTION:
*  Calls strdup, but syslogs an error on failure to allocate memory.
***********************************************************************/
char *
strdup_with_log(char const *s)
{
    char *p = strdup(s);
    if (!p) {
	syslog(LOG_WARNING, "Failed to allocate %d bytes of memory in strdup",
	       (int) strlen(s)+1);
    }
    return p;
}
#endif

/**********************************************************************
*%FUNCTION: chomp
*%ARGUMENTS:
* str -- a string
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Removes newlines and carriage-returns (if any) from str
***********************************************************************/
void
chomp(char *str)
{
    char *s, *t;
    s = str;
    for (t=str; *t; t++) {
	if (*t == '\n' || *t == '\r') continue;
	*s++ = *t;
    }
    *s = 0;
}

/**********************************************************************
* %FUNCTION: MXCommand
* %ARGUMENTS:
*  sockname -- multiplexor socket name
*  cmd -- command to send
*  buf -- buffer for reply
*  len -- length of buffer
*  qid -- Sendmail queue identifier
* %RETURNS:
*  0 if all went well, -1 on error.
* %DESCRIPTION:
*  Sends a command to the multiplexor and reads the answer back.
***********************************************************************/
int
MXCommand(char const *sockname,
	  char const *cmd,
	  char *buf,
	  int len,
	  char const *qid)
{
    int fd;
    struct sockaddr_un addr;
    int nread;
    int n;

    if (!qid || !*qid) {
	qid = "NOQUEUE";
    }

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
	syslog(LOG_ERR, "%s: MXCommand: socket: %m", qid);
	return MD_TEMPFAIL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, sockname, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	syslog(LOG_ERR, "%s: MXCommand: connect: %m: Is multiplexor running?", qid);
	close(fd);
	return MD_TEMPFAIL;
    }

    n = writestr(fd, cmd);
    if (n < 0) {
	syslog(LOG_ERR, "%s: MXCommand: write: %m: Is multiplexor running?", qid);
	close(fd);
	return MD_TEMPFAIL;
    }

    /* Now read the answer */
    nread = readn(fd, buf, len-1);
    if (nread < 0) {
	syslog(LOG_ERR, "%s: MXCommand: read: %m: Is multiplexor running?", qid);
	close(fd);
	return MD_TEMPFAIL;
    }
    buf[nread] = 0;
    /* If we read a full buffer, read to EOF to maintain synchronizaion */
    if (nread == len-1) {
	char slop[SMALLBUF];
	if (readn(fd, slop, SMALLBUF) > 0) {
	    syslog(LOG_WARNING, "%s: MXCommand: Overlong reply from multiplexor was truncated!", qid);
	    /* Read all the way to EOF */
	    while (readn(fd, slop, SMALLBUF) > 0);
	}
    }
    close(fd);
    return 0;
}

/**********************************************************************
* %FUNCTION: MXCheckFreeWorkers
* %ARGUMENTS:
*  sockname -- MX socket name
* %RETURNS:
*  >0 if there are free workers, 0 if all workers are busy, -1 if there
*  was an error.
* %DESCRIPTION:
*  Queries multiplexor for number of free workers.
***********************************************************************/
int
MXCheckFreeWorkers(char const *sockname, char const *qid)
{
    char ans[SMALLBUF];
    int workers;

    if (MXCommand(sockname, "free\n", ans, SMALLBUF-1, qid) < 0) return MD_TEMPFAIL;

    if (sscanf(ans, "%d", &workers) != 1) return MD_TEMPFAIL;
    return workers;
}

/**********************************************************************
* %FUNCTION: MXScanDir
* %ARGUMENTS:
*  sockname -- MX socket name
*  qid -- Sendmail queue ID
*  dir -- directory to scan
* %RETURNS:
*  0 if scanning succeeded; -1 if there was an error.
* %DESCRIPTION:
*  Asks multiplexor to initiate a scan.
***********************************************************************/
int
MXScanDir(char const *sockname,
	  char const *qid,
	  char const *dir)
{
    char cmd[SMALLBUF];
    char ans[SMALLBUF];
    int len;

    if (!qid || !*qid) {
	qid = "NOQUEUE";
    }

    if (percent_encode_command(1, cmd, sizeof(cmd), "scan", qid, dir, NULL) < 0) {
	return MD_TEMPFAIL;
    }

    if (MXCommand(sockname, cmd, ans, SMALLBUF-1, qid) < 0) return MD_TEMPFAIL;

    if (!strcmp(ans, "ok\n")) return 0;

    len = strlen(ans);
    if (len > 0 && ans[len-1] == '\n') ans[len-1] = 0;
    syslog(LOG_ERR, "%s: Error from multiplexor: %s", qid, ans);
    return MD_TEMPFAIL;
}

/**********************************************************************
* %FUNCTION: percent_decode
* %ARGUMENTS:
*  buf -- a buffer with percent-encoded data
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Decodes buf IN PLACE.
***********************************************************************/
void
percent_decode(char *buf)
{
    unsigned char *in = (unsigned char *) buf;
    unsigned char *out = (unsigned char *) buf;
    unsigned int val;

    if (!buf) {
	return;
    }

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
* %FUNCTION: percent_encode
* %ARGUMENTS:
*  in -- input buffer to encode
*  out -- output buffer to place encoded data
*  outlen -- number of chars in output buffer.
* %RETURNS:
*  Number of chars written, not including trailing NULL.  Ranges from
*  0 to outlen-1
* %DESCRIPTION:
*  Encodes "in" into "out", writing at most (outlen-1) chars.  Then writes
*  trailing 0.
***********************************************************************/
int
percent_encode(char const *in,
	       char *out,
	       int outlen)
{
    unsigned char tmp[8];
    int nwritten = 0;
    unsigned char c;
    unsigned char const *uin = (unsigned char const *) in;
    unsigned char *uout = (unsigned char *) out;

    if (outlen <= 0) {
	return 0;
    }
    if (outlen == 1) {
	*uout = 0;
	return 0;
    }

    /* Do real work */
    while((c = *uin++) != 0) {
	if (c <= 32 || c > 126 || c == '%' || c == '\\' || c == '\'' || c == '"') {
	    if (nwritten >= outlen-3) {
		break;
	    }
	    sprintf((char *) tmp, "%%%02X", (unsigned int) c);
	    *uout++ = tmp[0];
	    *uout++ = tmp[1];
	    *uout++ = tmp[2];
	    nwritten += 3;
	} else {
	    *uout++ = c;
	    nwritten++;
	}
	if (nwritten >= outlen-1) {
	    break;
	}
    }
    *uout = 0;
    return nwritten;
}

/**********************************************************************
* %FUNCTION: percent_encode_command
* %ARGUMENTS:
*  term_with_newline -- if true, terminate with "\n\0".  Otherwise, just "\0"
*  out -- output buffer
*  outlen -- length of output buffer
*  args -- arguments.  Each one is percent-encoded and space-separated from
*          previous.
* %RETURNS:
*  0 if everything fits; -1 otherwise.
* %DESCRIPTION:
*  Writes a series of space-separated, percent-encoded words to a buffer.
***********************************************************************/
static int
percent_encode_command(int term_with_newline, char *out, int outlen, ...)
{
    va_list ap;
    int spaceleft = outlen-2;
    int first = 1;
    int len;
    char *arg;

    if (outlen < 2) return MD_TEMPFAIL;

    va_start(ap, outlen);

    while ((arg = va_arg(ap, char *)) != NULL) {
	if (first) {
	    first = 0;
	} else {
	    if (spaceleft <= 0) {
		va_end(ap);
		return MD_TEMPFAIL;
	    }
	    *out++ = ' ';
	    spaceleft--;
	}
	len = percent_encode(arg, out, spaceleft);
	spaceleft -= len;
	out += len;
    }
    va_end(ap);
    if (term_with_newline) *out++ = '\n';
    *out = 0;
    return 0;
}


/**********************************************************************
* %FUNCTION: munch_mx_return
* %ARGUMENTS:
*  ans -- answer from multiplexor
*  msg -- buffer for holding error message, at least SMALLBUF chars
*  qid -- Sendmail queue ID
* %RETURNS:
*  1 if it's OK to accept connections from this host; 0 if not, -1 if error.
*  If connection is rejected, error message *may* be set.
***********************************************************************/
static int
munch_mx_return(char *ans, char *msg, char const *qid)
{
    size_t len;

    if (!qid || !*qid) {
	qid = "NOQUEUE";
    }

    if (!strcmp(ans, "ok -1\n")) return MD_TEMPFAIL;
    if (!strcmp(ans, "ok 1\n")) return MD_CONTINUE;
    if (!strcmp(ans, "ok 2\n")) return MD_ACCEPT_AND_NO_MORE_FILTERING;
    if (!strcmp(ans, "ok 3\n")) return MD_DISCARD;
    if (!strcmp(ans, "ok 0\n")) return MD_REJECT;

    chomp(ans);

    /* If rejection message is supplied, set failure code and return 0 */
    len = strlen(ans);
    if (len >= 6 && !strncmp(ans, "ok 0 ", 5)) {
	strcpy(msg, ans+5);
	return MD_REJECT;
    }

    if (len >= 7 && !strncmp(ans, "ok -1 ", 6)) {
	strcpy(msg, ans+6);
	return MD_TEMPFAIL;
    }

    if (len >= 6 && !strncmp(ans, "ok 1 ", 5)) {
	strcpy(msg, ans+5);
	return MD_CONTINUE;
    }

    if (len >= 6 && !strncmp(ans, "ok 2 ", 5)) {
	strcpy(msg, ans+5);
	return MD_ACCEPT_AND_NO_MORE_FILTERING;
    }

    if (len >= 6 && !strncmp(ans, "ok 3 ", 5)) {
	strcpy(msg, ans+5);
	return MD_DISCARD;
    }

    if (len > 0 && ans[len-1] == '\n') ans[len-1] = 0;
    syslog(LOG_ERR, "%s: Error from multiplexor: %s", qid, ans);
    return MD_TEMPFAIL;
}

/**********************************************************************
* %FUNCTION: MXRelayOK
* %ARGUMENTS:
*  sockname -- multiplexor socket name
*  msg -- buffer for holding error message, at least SMALLBUF chars
*  ip -- relay IP address
*  name -- relay name
*  port -- client port
*  myip -- My IP address, if known.
*  daemon_port -- Listening port
*  qid -- Queue ID
* %RETURNS:
*  1 if it's OK to accept connections from this host; 0 if not, -1 if error.
*  If connection is rejected, error message *may* be set.
***********************************************************************/
int
MXRelayOK(char const *sockname,
	  char *msg,
	  char const *ip,
	  char const *name,
	  unsigned int port,
	  char const *myip,
	  unsigned int daemon_port,
          char const *qid)
{
    char cmd[SMALLBUF];
    char ans[SMALLBUF];

    char port_string[65];
    char daemon_port_string[65];

    snprintf(port_string, sizeof(port_string), "%u", port);
    snprintf(daemon_port_string, sizeof(daemon_port_string), "%u", daemon_port);

    *msg = 0;

    if (!ip || !*ip) {
	ip = "UNKNOWN";
    }
    if (!name || !*name) {
	name = ip;
    }
    if (!myip || !*myip) {
	myip = "UNKNOWN";
    }

    if (!qid || !*qid) {
        qid = "NOQUEUE";
    }
    if (percent_encode_command(1, cmd, sizeof(cmd), "relayok", ip, name, port_string, myip, daemon_port_string, qid, NULL) < 0) {
	return MD_TEMPFAIL;
    }
    if (MXCommand(sockname, cmd, ans, SMALLBUF-1, NULL) < 0) return MD_TEMPFAIL;
    return munch_mx_return(ans, msg, NULL);
}

/**********************************************************************
* %FUNCTION: MXHeloOK
* %ARGUMENTS:
*  sockname -- multiplexor socket name
*  msg -- buffer for holding error message, at least SMALLBUF chars
*  ip -- IP address of client
*  name -- resolved name of client
*  helo -- the helo string
*  port -- client port
*  myip -- My IP address, if known.
*  daemon_port -- Listening port
*  qid -- Queue ID
* %RETURNS:
*  1 if it's OK to accept messages from this sender; 0 if not, -1 if error or
*  we should tempfail.
***********************************************************************/
int
MXHeloOK(char const *sockname,
	 char *msg,
	 char const *ip,
	 char const *name,
	 char const *helo,
	 unsigned int port,
	 char const *myip,
	 unsigned int daemon_port,
         char const *qid)
{
    char cmd[SMALLBUF];
    char ans[SMALLBUF];

    char port_string[65];
    char daemon_port_string[65];

    snprintf(port_string, sizeof(port_string), "%u", port);
    snprintf(daemon_port_string, sizeof(daemon_port_string), "%u", daemon_port);

    *msg = 0;

    if (!ip || !*ip) {
	ip = "UNKNOWN";
    }
    if (!name || !*name) {
	name = ip;
    }
    if (!helo) {
	helo = "UNKNOWN";
    }

    if (!myip || !*myip) {
	myip = "UNKNOWN";
    }

    if (!qid || !*qid) {
        qid = "NOQUEUE";
    }

    if (percent_encode_command(1, cmd, sizeof(cmd), "helook", ip, name, helo, port_string, myip, daemon_port_string, qid, NULL) < 0) {
	return MD_TEMPFAIL;
    }
    if (MXCommand(sockname, cmd, ans, SMALLBUF-1, NULL) < 0) return MD_TEMPFAIL;
    return munch_mx_return(ans, msg, NULL);
}


/**********************************************************************
* %FUNCTION: MXSenderOK
* %ARGUMENTS:
*  sockname -- socket name
*  msg -- buffer of at least SMALLBUF size for error message
*  sender_argv -- args from sendmail.  sender_argv[0] is sender; rest are
*                 ESMTP args.
*  ip -- sending relay's IP address
*  name -- sending relay's host name
*  helo -- argument to "HELO/EHLO" (may be NULL)
*  dir -- MIMEDefang working directory
*  qid -- Sendmail queue identifier
* %RETURNS:
*  1 if it's OK to accept messages from this sender; 0 if not, -1 if error or
*  we should tempfail.
*  If message is rejected, error message *may* be set.
***********************************************************************/
int
MXSenderOK(char const *sockname,
	   char *msg,
	   char const **sender_argv,
	   char const *ip,
	   char const *name,
	   char const *helo,
	   char const *dir,
	   char const *qid)
{
    char cmd[SMALLBUF];
    char ans[SMALLBUF];
    int l, l2, i;

    char const *sender = sender_argv[0];

    *msg = 0;

    if (!sender || !*sender) {
	sender = "UNKNOWN";
    }

    if (!ip || !*ip) {
	ip = "UNKNOWN";
    }
    if (!name || !*name) {
	name = ip;
    }
    if (!helo) {
	helo = "UNKNOWN";
    }

    if (percent_encode_command(0, cmd, sizeof(cmd)-1, "senderok", sender, ip,
			       name,
			       helo, dir, qid, NULL) < 0) {
	return MD_TEMPFAIL;
    }

    /* Append ESMTP args */
    l = strlen(cmd);
    for (i=1; sender_argv[i]; i++) {
	percent_encode(sender_argv[i],
		       ans,
		       sizeof(ans));
	l2 = strlen(ans) + 1;
	if (l + l2 < sizeof(cmd)-1) {
	    strcat(cmd, " ");
	    strcat(cmd, ans);
	    l += l2;
	} else {
	    break;
	}
    }

    /* Add newline */
    strcat(cmd, "\n");

    if (MXCommand(sockname, cmd, ans, SMALLBUF-1, qid) < 0) return MD_TEMPFAIL;
    return munch_mx_return(ans, msg, qid);
}

/**********************************************************************
* %FUNCTION: MXRecipientOK
* %ARGUMENTS:
*  sockname -- multiplexor socket name
*  msg -- buffer of at least SMALLBUF size for error messages
*  recip_argv -- recipient e-mail address and ESMTP args
*  sender -- sender's e-mail address
*  ip -- sending relay's IP address
*  name -- sending relay's host name
*  firstRecip -- first recipient of the message
*  helo -- argument to "HELO/EHLO" (may be NULL)
*  dir -- MIMEDefang working directory
*  qid -- Sendmail queue identifier
*  rcpt_mailer -- the "mailer" part of the triple for RCPT TO address
*  rcpt_host -- the "host" part of the triple for RCPT TO address
*  rcpt_addr -- the "addr" part of the triple for RCPT TO address
* %RETURNS:
*  1 if it's OK to accept messages to this recipient; 0 if not, -1 if error.
*  If recipient is rejected, error message *may* be set.
***********************************************************************/
int
MXRecipientOK(char const *sockname,
	      char *msg,
	      char const **recip_argv,
	      char const *sender,
	      char const *ip,
	      char const *name,
	      char const *firstRecip,
	      char const *helo,
	      char const *dir,
	      char const *qid,
	      char const *rcpt_mailer,
	      char const *rcpt_host,
	      char const *rcpt_addr)

{
    char cmd[SMALLBUF];
    char ans[SMALLBUF];
    int i, l, l2;
    char const *recipient = recip_argv[0];

    *msg = 0;

    if (!recipient || !*recipient) {
	recipient = "UNKNOWN";
    }

    if (!sender || !*sender) {
	sender = "UNKNOWN";
    }

    if (!ip || !*ip) {
	ip = "UNKNOWN";
    }
    if (!name || !*name) {
	name = ip;
    }

    if (!firstRecip || !*firstRecip) {
	firstRecip = "UNKNOWN";
    }
    if (!helo) {
	helo = "UNKNOWN";
    }

    if (percent_encode_command(0, cmd, sizeof(cmd),
			       "recipok", recipient, sender, ip, name, firstRecip,
			       helo, dir, qid, rcpt_mailer, rcpt_host, rcpt_addr,
			       NULL) < 0) {
	return MD_TEMPFAIL;
    }

    /* Append ESMTP args */
    l = strlen(cmd);
    for (i=1; recip_argv[i]; i++) {
	percent_encode(recip_argv[i],
		       ans,
		       sizeof(ans));
	l2 = strlen(ans) + 1;
	if (l + l2 < sizeof(cmd)-1) {
	    strcat(cmd, " ");
	    strcat(cmd, ans);
	    l += l2;
	} else {
	    break;
	}
    }

    /* Add newline */
    strcat(cmd, "\n");

    if (MXCommand(sockname, cmd, ans, SMALLBUF-1, qid) < 0) return MD_TEMPFAIL;
    return munch_mx_return(ans, msg, qid);
}

/**********************************************************************
* %FUNCTION: writen
* %ARGUMENTS:
*  fd -- file to write to
*  buf -- buffer to write
*  len -- length to write
* %RETURNS:
*  Number of bytes written, or -1 on error
* %DESCRIPTION:
*  Writes exactly "len" bytes from "buf" to file descriptor fd
***********************************************************************/
int
writen(int fd,
       char const *buf,
       size_t len)
{
    int r;
    int nleft = len;
    while(nleft) {
	r = write(fd, buf, nleft);
	if (r > 0) {
	    nleft -= r;
	    buf += r;
	    continue;
	}
	if (r == 0) {
	    /* Shouldn't happen! */
	    errno = EIO;
	    return MD_TEMPFAIL;
	}
	if (r < 0) {
	    if (errno == EINTR || errno == EAGAIN) {
		continue;
	    }
	}
	return r;
    }
    return len;
}

/**********************************************************************
* %FUNCTION: writestr
* %ARGUMENTS:
*  fd -- file to write to
*  buf -- null-terminated string to write
* %RETURNS:
*  Number of bytes written, or -1 on error
* %DESCRIPTION:
*  Writes the string in "buf" to fd.
***********************************************************************/
int
writestr(int fd,
	 char const *buf)
{
    return writen(fd, buf, strlen(buf));
}

/**********************************************************************
* %FUNCTION: readn
* %ARGUMENTS:
*  fd -- file descriptor to read from
*  buf -- buffer to read into
*  count -- number of bytes to read
* %RETURNS:
*  The number of bytes actually read, or -1 on error
* %DESCRIPTION:
*  Attempts to read exactly "count" bytes from a descriptor.
***********************************************************************/
int
readn(int fd, void *buf, size_t count)
{
    size_t num_read = 0;
    char *c = (char *) buf;
    while (count) {
	int n = read(fd, c, count);
	if (n == 0) { /* EOF */
	    return num_read;
	}
	if (n < 0) { /* Error */
	    if (errno == EINTR || errno == EAGAIN) {
		continue;
	    }
	    return n;
	}
	num_read += n;
	count -= n;
	c += n;
    }
    return num_read;
}

/**********************************************************************
* %FUNCTION: closefd
* %ARGUMENTS:
*  fd -- file to close
* %RETURNS:
*  Whatever close(2) returns
* %DESCRIPTION:
*  Closes fd, handling EINTR
***********************************************************************/
int
closefd(int fd)
{
    int r;
    while(1) {
	r = close(fd);
	if (r >= 0) return r;
	if (errno != EINTR) return r;
    }
}

/**********************************************************************
* %FUNCTION: validate_smtp_code
* %ARGUMENTS:
*  code -- an SMTP code (eg 451)
*  first -- what the first char must be
* %RETURNS:
*  1 if it's a valid code; 0 otherwise.  A valid code consists
*  of three decimal digits only.  The first digit must match "first".
***********************************************************************/
int
validate_smtp_code(char const *code,
		   char const *first)
{
    if (!code) return 0;
    if (*code != *first) return 0;

    if (!isdigit(*(code+1))) return 0;
    if (!isdigit(*(code+2))) return 0;
    if (*(code+3)) return 0;

    return 1;
}

/**********************************************************************
* %FUNCTION: validate_smtp_dsn
* %ARGUMENTS:
*  dsn -- an SMTP dsn reply (eg 4.7.1)
*  first -- what the first char must be
* %RETURNS:
*  1 if it's a valid dsn; 0 otherwise.  A valid DSN consists of three
*  numerical fields separated by periods.  The first field must be a
*  single digit that matches "first".  The second and
*  third fields can be 1-3 digits long each.
***********************************************************************/
int
validate_smtp_dsn(char const *dsn,
		  char const *first)
{
    char const *s;
    int count;

    if (!dsn) return 0;
    if (*dsn != *first) return 0;

    if (*(dsn+1) != '.') return 0;

    s = dsn+2;
    count = 0;
    while (isdigit(*s) && count < 4) {
	count++;
	s++;
    }

    if (count == 0 || count > 3) return 0;
    if (*s != '.') return 0;

    s++;
    count = 0;
    while (isdigit(*s) && count < 4) {
	count++;
	s++;
    }
    if (count == 0 || count > 3) return 0;
    if (*s) return 0;

    return 1;
}

/**********************************************************************
* %FUNCTION: remove_local_socket
* %ARGUMENTS:
*  str -- a string of the form:
*                   /path/to/sock   (assumed to be unix:/path/to/sock)
*                   unix:/path/to/sock
*                   local:/path/to/sock
*                   inet:port  (host defaults to LOOPBACK)
*                   inet_any:port (host defaults to INADDR_ANY)
* %RETURNS:
*  Whatever remove() returns if it's a local socket; otherwise zero
* %DESCRIPTION:
*  If the socket is local, then it's removed from the file system
***********************************************************************/
int
remove_local_socket(char const *str)
{
    char const *path;

    if (*str == '/') {
	path = str;
    } else if (!strncmp(str, "unix:", 5)) {
	path = str+5;
    } else if (!strncmp(str, "local:", 6)) {
	path = str+6;
    } else {
	/* Not unix-domain socket */
	return 0;
    }
    return remove(path);
}

/**********************************************************************
* %FUNCTION: make_listening_socket
* %ARGUMENTS:
*  str -- a string of the form:
*                   /path/to/sock   (assumed to be unix:/path/to/sock)
*                   unix:/path/to/sock
*                   local:/path/to/sock
*                   inet:port  (host defaults to LOOPBACK)
*                   inet_any:port (host defaults to INADDR_ANY)
*                   inet6:port (host defaults to in6addr_loopback)
*                   inet6_any:port (host defaults to in6addr_any)
*  backlog -- listen backlog.  If -1, we use default of 5
*  must_be_unix -- If true, do not accept the inet: or inet_any: sockets.
* %RETURNS:
*  A listening UNIX-domain or TCP socket.  If must_be_unix is true
*  and we asked for a TCP socket, return -2.  Other failures return -1.
* %DESCRIPTION:
*  Utility function for opening a listening socket.
***********************************************************************/
int
make_listening_socket(char const *str, int backlog, int must_be_unix)
{
    char const *path;
    int sock;
    struct sockaddr_in addr_in;
    struct sockaddr_un addr_un;
    int opt;
    int port;
    uint32_t bind_addr;

    if (backlog <= 0) backlog = 5;

    if (!strncmp(str, "inet:", 5) ||
	!strncmp(str, "inet_any:", 9)) {
	if (must_be_unix) {
	    return -2;
	}
	if (!strncmp(str, "inet:", 5)) {
	    path = str+5;
	    bind_addr = htonl(INADDR_LOOPBACK);
	} else {
	    path = str+9;
	    bind_addr = htonl(INADDR_ANY);
	}

	if (sscanf(path, "%d", &port) != 1 ||
	    port < 1 ||
	    port > 65535) {
	    syslog(LOG_ERR, "make_listening_socket: Invalid port %s", path);
	    errno = EINVAL;
	    return -1;
	}

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
	    syslog(LOG_ERR, "make_listening_socket: socket: %m");
	    return -1;
	}

	opt = 1;
	/* Reuse port */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
	    syslog(LOG_ERR, "make_listening_socket: setsockopt: %m");
	    close(sock);
	    return -1;
	}

	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(port);
	addr_in.sin_addr.s_addr = bind_addr;
	if (bind(sock, (struct sockaddr *) &addr_in, sizeof(addr_in)) < 0) {
	    syslog(LOG_ERR, "make_listening_socket: bind: %m");
	    close(sock);
	    return -1;
	}
    } else if (!strncmp(str, "inet6:", 6) ||
	       !strncmp(str, "inet6_any:", 10)) {
#if defined(AF_INET6)
	struct in6_addr const *bind6_addr;
	struct sockaddr_in6 addr6;
	if (must_be_unix) {
	    return -2;
	}
	if (!strncmp(str, "inet6:", 6)) {
	    path = str+6;
	    bind6_addr = &in6addr_loopback;
	} else {
	    path = str+10;
	    bind6_addr = &in6addr_any;
	}
	if (sscanf(path, "%d", &port) != 1 ||
	    port < 1 ||
	    port > 65535) {
	    syslog(LOG_ERR, "make_listening_socket: Invalid port %s", path);
	    errno = EINVAL;
	    return -1;
	}

	sock = socket(PF_INET6, SOCK_STREAM, 0);
	if (sock < 0) {
	    syslog(LOG_ERR, "make_listening_socket: socket: %m");
	    return -1;
	}

	opt = 1;
	/* Reuse port */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
	    syslog(LOG_ERR, "make_listening_socket: setsockopt: %m");
	    close(sock);
	    return -1;
	}
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port   = htons(port);
	addr6.sin6_addr   = *bind6_addr;
	if (bind(sock, (struct sockaddr *) &addr6, sizeof(addr6)) < 0) {
	    syslog(LOG_ERR, "make_listening_socket: bind: %m");
	    close(sock);
	    return -1;
	}
#else
	syslog(LOG_ERR, "Cannot specify inet6 socket: No IPv6 support");
	fprintf(stderr, "Cannot specify inet6 socket: No IPv6 support\n");
	return -1;
#endif
    } else {
	/* Assume unix-domain socket */
	path = str;
	if (!strncmp(str, "unix:", 5)) path = str+5;
	else if (!strncmp(str, "local:", 6)) path = str+6;
	(void) remove(path);
	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
	    syslog(LOG_ERR, "make_listening_socket: socket: %m");
	    return -1;
	}

	memset(&addr_un, 0, sizeof(addr_un));
	addr_un.sun_family = AF_LOCAL;
	strncpy(addr_un.sun_path, path, sizeof(addr_un.sun_path)-1);

	if (bind(sock, (struct sockaddr *) &addr_un, SUN_LEN(&addr_un)) < 0) {
	    syslog(LOG_ERR, "make_listening_socket: bind: %m");
	    close(sock);
	    return -1;
	}
    }

    if (listen(sock, backlog) < 0) {
	/* Maybe backlog is too high... try again */
	if (backlog > 5) {
	    if (listen(sock, 5) < 0) {
		syslog(LOG_ERR, "make_listening_socket: listen: %m");
		close(sock);
		return -1;
	    }
	}
	syslog(LOG_ERR, "make_listening_socket: listen: %m");
	close(sock);
	return -1;
    }
    return sock;
}

/**********************************************************************
* %FUNCTION: do_delay
* %ARGUMENTS:
*  sleepstr -- Number of seconds to delay as an ASCII string.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sleeps for specified number of seconds
***********************************************************************/
void
do_delay(char const *sleepstr)
{
    int snooze;
    if (!sleepstr || !*sleepstr) {
	return;
    }

    if (sscanf(sleepstr, "%d", &snooze) != 1 || snooze <= 0) {
	return;
    }
    while(snooze) {
	snooze = sleep(snooze);
    }
}

/**********************************************************************
* %FUNCTION: is_localhost
* %ARGUMENTS:
*  sa -- a socket address
* %RETURNS:
*  True if sa is the loopback address; false otherwise.
***********************************************************************/
int
is_localhost(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
	struct sockaddr_in *sa_in = (struct sockaddr_in *) sa;
	return (sa_in->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    }
#ifdef AF_INET6
    if (sa->sa_family == AF_INET6) {
	struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *) sa;
	return IN6_IS_ADDR_LOOPBACK(&sa_in6->sin6_addr);
    }
#endif
    return 0;
}

#ifdef ENABLE_DEBUGGING
void *
malloc_debug(void *ctx, size_t x, char const *fname, int line)
{
    void *ptr = (malloc) (x);
    syslog(LOG_DEBUG, "%p: %s(%d): malloc(%lu) = %p\n", ctx, fname,
	   line, (unsigned long) x, ptr);
    return ptr;
}

char *
strdup_debug(void *ctx, char const *s, char const *fname, int line)
{
    char *dup = (strdup) (s);
    syslog(LOG_DEBUG, "%p: %s(%d): strdup(\"%.25s\") = %p\n", ctx, fname, line, s, dup);
    return dup;
}

void
free_debug(void *ctx, void *x, char const *fname, int line)
{
    syslog(LOG_DEBUG, "%p: %s(%d): free(%p)\n", ctx, fname, line, x);
    (free)(x);
}
#endif

int
write_and_lock_pidfile(char const *pidfile, char *lockfile, int pidfile_fd)
{
    struct flock fl;
    char buf[64];
    int lockfile_fd;
    size_t len;

    if (!lockfile) {
	if (!pidfile) {
	    return -1;
	}
	len = strlen(pidfile) + 6;
	/* If no lockfile was supplied, construct one based on pidfile */
	lockfile = malloc(len);
	if (!lockfile) {
	    return -1;
	}

	snprintf(lockfile, len, "%s.lock", pidfile);
    }

    lockfile_fd = open(lockfile, O_RDWR|O_CREAT, 0666);
    if (lockfile_fd < 0) {
      return -1;
    }

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (fcntl(lockfile_fd, F_SETLK, &fl) < 0) {
      syslog(LOG_ERR, "Could not lock lockfile file %s: %m.  Is another copy running?", lockfile);
      return -1;
    }
    if (pidfile_fd >= 0) {
	ftruncate(pidfile_fd, 0);
	snprintf(buf, sizeof(buf), "%lu\n", (unsigned long) getpid());
	write(pidfile_fd, buf, strlen(buf));

	/* Close the pidfile fd; no longer needed */
	if (close(pidfile_fd) < 0) {
	    return -1;
	}
    }

    /* Do NOT close lockfile_fd... it will close and lock will be released
       when we exit */
    return lockfile_fd;
}
