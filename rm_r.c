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
    int retcode = 0;
    int errno_save;

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
       use NAME_MAX instead */
    entry = (struct dirent *) malloc(sizeof(struct dirent) + NAME_MAX);
#endif
    if (!entry) {
      syslog(LOG_WARNING, "%s: Unable to allocate space for dirent entry: %m", qid);
      return -1;
    }

    d = opendir(dir);
    if (!d) {
      errno_save = errno;
      syslog(LOG_WARNING, "%s: opendir(%s) failed: %m", qid, dir);
      free(entry);
      errno = errno_save;
      return -1;
    }

    while((entry = readdir(d)) != NULL) {
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
