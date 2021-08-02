/***********************************************************************
*
* drop_privs.c
*
* Defines the "drop_privs" function which switches to specified user name.
*
* Copyright (C) 2002-2003 by Roaring Penguin Software Inc.
* http://www.roaringpenguin.com
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#include "config.h"
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <grp.h>

/**********************************************************************
* %FUNCTION: drop_privs
* %ARGUMENTS:
*  user -- name of user to become
*  uid, gid -- uid and gid to use
* %RETURNS:
*  0 on success; -1 on failure.
* %DESCRIPTION:
*  Switches uid to uid of "user"; also enters that user's group and calls
*  initgroups.
***********************************************************************/
int
drop_privs(char const *user, uid_t uid, gid_t gid)
{
    /* Call initgroups */
#ifdef HAVE_INITGROUPS
    if (initgroups((char *) user, gid) < 0) {
	syslog(LOG_ERR, "drop_privs: initgroups for '%s' failed: %m", user);
	return -1;
    }
#endif

    /* Call setgid */
    if (setgid(gid) < 0) {
	syslog(LOG_ERR, "drop_privs: setgid for '%s' failed: %m", user);
	return -1;
    }

    /* Finally, call setuid */
    if (setuid(uid) < 0) {
	syslog(LOG_ERR, "drop_privs: setuid for '%s' failed: %m", user);
	return -1;
    }
    return 0;
}
