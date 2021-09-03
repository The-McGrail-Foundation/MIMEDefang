/***********************************************************************
*
* mimedefang.h
*
* External declarations and defines.
*
* Copyright (C) 2002-2005 by Roaring Penguin Software Inc.
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#ifndef MIMEDEFANG_H
#define MIMEDEFANG_H 1

#define SMALLBUF 16384
#define BIGBUF 65536

/* Identifier is 7 chars long: 5 time plus 2 counter */
#define MX_ID_LEN 7

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>   /* For struct sockaddr */

extern void chomp(char *str);
extern int percent_encode(char const *in, char *out, int outlen);
extern void percent_decode(char *buf);

extern int MXCheckFreeWorkers(char const *sockname, char const *qid);
extern int MXScanDir(char const *sockname, char const *qid, char const *dir);
extern int MXCommand(char const *sockname, char const *cmd, char *buf, int len, char const *qid);
extern int MXRelayOK(char const *sockname, char *msg,
		     char const *ip, char const *name, unsigned int port,
		     char const *myip, unsigned int daemon_port, char const *qid);
extern int MXHeloOK(char const *sockname, char *msg,
		    char const *ip, char const *name, char const *helo,
		    unsigned int port, char const *myip, unsigned int daemon_port, char const *qid);

extern int MXSenderOK(char const *sockname, char *msg,
		      char const **sender_argv, char const *ip, char const *name,
		      char const *helo, char const *dir, char const *qid);
extern int MXRecipientOK(char const *sockname, char *msg,
			 char const **recip_argv,
			 char const *sender, char const *ip, char const *name,
			 char const *firstRecip, char const *helo,
			 char const *dir, char const *qid,
			 char const *rcpt_mailer, char const *rcpt_host,
			 char const *rcpt_addr);

extern int safeWriteHeader(int fd, char *str);
extern void split_on_space(char *buf, char **first, char **rest);
extern void split_on_space3(char *buf,
			    char **first, char **second, char **rest);
extern void split_on_space4(char *buf,
			    char **first, char **second, char **third,
			    char **rest);
extern void *malloc_with_log(size_t s);
extern char *strdup_with_log(char const *s);
extern int rm_r(char const *qid, char const *dir);
extern int writen(int fd, char const *buf, size_t len);
extern int readn(int fd, void *buf, size_t count);
extern int writestr(int fd, char const *buf);
extern int closefd(int fd);
extern int validate_smtp_code(char const *code, char const *first);
extern int validate_smtp_dsn(char const *dsn, char const *first);
extern int make_listening_socket(char const *str, int backlog, int must_be_unix);
extern void do_delay(char const *sleepstr);
extern int is_localhost(struct sockaddr *);
extern int remove_local_socket(char const *str);
extern int write_and_lock_pidfile(char const *pidfile, char *lockfile, int fd);
#ifdef EMBED_PERL
extern int make_embedded_interpreter(char const *progPath,
				     char const *subFilter,
				     int wantStatusReports,
				     char **env);
extern void init_embedded_interpreter(int, char **, char **);
extern void deinit_embedded_interpreter(void);
extern void term_embedded_interpreter(void);
extern void run_embedded_filter(void);
extern void dump_milter_buildlib_info(void);

#endif

extern char *gen_mx_id(char *);
/* Magic return values */
#define MD_TEMPFAIL                    -1
#define MD_REJECT                       0
#define MD_CONTINUE                     1
#define MD_ACCEPT_AND_NO_MORE_FILTERING 2
#define MD_DISCARD                      3
#endif

