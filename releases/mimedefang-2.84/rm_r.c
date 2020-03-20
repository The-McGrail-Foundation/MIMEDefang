/***********************************************************************
*
* rm_r.c
*
* Implementation in C of recursive deletion of directory (rm -r dir)
*
* Copyright (C) 2002-2005 Roaring Penguin Software Inc.
* http://www.roaringpenguin.com
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2, or (at your option) any later version.
*
***********************************************************************/

#include "config.h"
#include "mimedefang.h"
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef EXEC_RM_FOR_CLEANUP
#include <sys/wait.h>
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
#define strdup_with_log(x) strdup_debug(ctx, x, __FILE__, __LINE__)
#endif

#ifndef EXEC_RM_FOR_CLEANUP
/**********************************************************************
* %FUNCTION: rm_r
* %ARGUMENTS:
*  dir -- directory or file name
* %RETURNS:
*  -1 on error, 0 otherwise.
* %DESCRIPTION:
*  Deletes dir and recursively deletes contents
***********************************************************************/
int
rm_r(char const *qid, char const *dir)
{
    char buf[SMALLBUF];
    struct stat sbuf;
    DIR *d;
    struct dirent *entry;
    struct dirent *result = NULL;
    int n;
    int retcode = 0;

    if (!qid || !*qid) {
	qid = "NOQUEUE";
    }

    if (lstat(dir, &sbuf) < 0) {
	syslog(LOG_WARNING, "%s: lstat(%s) failed: %m", qid, dir);
	return -1;
    }

    if (!S_ISDIR(sbuf.st_mode)) {
	/* Not a directory - just unlink */
	if (unlink(dir) < 0) {
	    syslog(LOG_WARNING, "%s: unlink(%s) failed: %m", qid, dir);
	    return -1;
	}
	return 0;
    }

    /* Allocate room for entry */
#ifdef HAVE_PATHCONF
    entry = (struct dirent *) malloc(sizeof(struct dirent) + pathconf(dir, _PC_NAME_MAX) + 1);
#else
    /* Can't use _POSIX_NAME_MAX because it's often defined as 14...
       useless... */
    entry = (struct dirent *) malloc(sizeof(struct dirent) + 257);
#endif
    if (!entry) {
	syslog(LOG_WARNING, "%s: Unable to allocate space for dirent entry: %m", qid);
	return -1;
    }

    d = opendir(dir);
    if (!d) {
	int errno_save = errno;
	syslog(LOG_WARNING, "%s: opendir(%s) failed: %m", qid, dir);
	free(entry);
	errno = errno_save;
	return -1;
    }

    for (;;) {
	n = readdir_r(d, entry, &result);
	if (n != 0) {
	    errno = n;
	    syslog(LOG_WARNING, "%s: readdir_r failed: %m", qid);
	    closedir(d);
	    free(entry);
	    errno = n;
	    return -1;
	}
	if (!result) break;
	if (!strcmp(entry->d_name, ".") ||
	    !strcmp(entry->d_name, "..")) {
	    continue;
	}
	snprintf(buf, sizeof(buf), "%s/%s", dir, entry->d_name);
	if (rm_r(qid, buf) < 0) {
	    retcode = -1;
	}
    }
    free(entry);
    closedir(d);
    if (rmdir(dir) < 0) {
	syslog(LOG_WARNING, "%s: rmdir(%s) failed: %m", qid, dir);
	return -1;
    }
    return retcode;
}

#else /* EXEC_RM_FOR_CLEANUP */
/**********************************************************************
* %FUNCTION: rm_r
* %ARGUMENTS:
*  dir -- directory or file name
* %RETURNS:
*  -1 on error, 0 otherwise.
* %DESCRIPTION:
*  Deletes dir and recursively deletes contents.  Does so by forking and
*  exec'ing "rm".
***********************************************************************/
int
rm_r(char const *qid, char const *dir)
{
    pid_t pid;

    if (!qid || !*qid) {
	qid = "NOQUEUE";
    }


    pid = fork();
    if (pid == (pid_t) -1) {
	syslog(LOG_WARNING, "%s: fork() failed -- cannot clean up: %m", qid);
	return -1;
    }

    if (pid == 0) {
	/* In the child */
	execl(RM, "rm", "-r", "-f", dir, NULL);
	_exit(EXIT_FAILURE);
    }

    /* In the parent */
    if (waitpid(pid, NULL, 0) < 0) {
	syslog(LOG_ERR, "%s: waitpid() failed -- cannot clean up: %m", qid);
	return -1;
    }

    return 0;
}
#endif  /* EXEC_RM_FOR_CLEANUP */
