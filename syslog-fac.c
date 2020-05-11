/***********************************************************************
*
* syslog-fac.c
*
* Defined the function find_syslog_facility
*
* Copyright (C) 2003-2005 Roaring Penguin Software Inc.
*
***********************************************************************/

#include <syslog.h>
#include <string.h>

/**********************************************************************
* %FUNCTION: find_syslog_facility
* %ARGUMENTS:
*  facility_name -- name of a syslog facility, like "mail", "news", etc.
* %RETURNS:
*  The numerical facility value, or -1 if not found.
***********************************************************************/
int
find_syslog_facility(char const *facility_name)
#define RETURN_SYSLOG_FACILITY(nm, sym) \
    if (!strcasecmp(facility_name, nm) || !strcasecmp(facility_name, #sym)) \
        return (sym)
{
#ifdef LOG_AUTH
    RETURN_SYSLOG_FACILITY("auth", LOG_AUTH);
#endif
#ifdef LOG_AUTHPRIV
    RETURN_SYSLOG_FACILITY("authpriv", LOG_AUTHPRIV);
#endif
#ifdef LOG_CRON
    RETURN_SYSLOG_FACILITY("cron", LOG_CRON);
#endif
#ifdef LOG_DAEMON
    RETURN_SYSLOG_FACILITY("daemon", LOG_DAEMON);
#endif
#ifdef LOG_FTP
    RETURN_SYSLOG_FACILITY("ftp", LOG_FTP);
#endif
#ifdef LOG_KERN
    RETURN_SYSLOG_FACILITY("kern", LOG_KERN);
#endif
#ifdef LOG_LPR
    RETURN_SYSLOG_FACILITY("lpr", LOG_LPR);
#endif
#ifdef LOG_MAIL
    RETURN_SYSLOG_FACILITY("mail", LOG_MAIL);
#endif
#ifdef LOG_NEWS
    RETURN_SYSLOG_FACILITY("news", LOG_NEWS);
#endif
#ifdef LOG_AUTH
    RETURN_SYSLOG_FACILITY("security", LOG_AUTH);
#endif
#ifdef LOG_SYSLOG
    RETURN_SYSLOG_FACILITY("syslog", LOG_SYSLOG);
#endif
#ifdef LOG_USER
    RETURN_SYSLOG_FACILITY("user", LOG_USER);
#endif
#ifdef LOG_UUCP
    RETURN_SYSLOG_FACILITY("uucp", LOG_UUCP);
#endif
#ifdef LOG_LOCAL0
    RETURN_SYSLOG_FACILITY("local0", LOG_LOCAL0);
#endif
#ifdef LOG_LOCAL1
    RETURN_SYSLOG_FACILITY("local1", LOG_LOCAL1);
#endif
#ifdef LOG_LOCAL2
    RETURN_SYSLOG_FACILITY("local2", LOG_LOCAL2);
#endif
#ifdef LOG_LOCAL3
    RETURN_SYSLOG_FACILITY("local3", LOG_LOCAL3);
#endif
#ifdef LOG_LOCAL4
    RETURN_SYSLOG_FACILITY("local4", LOG_LOCAL4);
#endif
#ifdef LOG_LOCAL5
    RETURN_SYSLOG_FACILITY("local5", LOG_LOCAL5);
#endif
#ifdef LOG_LOCAL6
    RETURN_SYSLOG_FACILITY("local6", LOG_LOCAL6);
#endif
#ifdef LOG_LOCAL7
    RETURN_SYSLOG_FACILITY("local7", LOG_LOCAL7);
#endif
    return -1;
}
#undef RETURN_SYSLOG_FACILITY

