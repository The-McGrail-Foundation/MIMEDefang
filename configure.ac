dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT(mimedefang.c)

dnl UGLY hack... set the --sysconfdir to /etc UNLESS it was explicitly
dnl supplied on the command line.  Autoconf has no other nice way to set
dnl the default to other than ${prefix}/etc

echo $* | fgrep -e '--sysconfdir' > /dev/null 2>&1 || sysconfdir='/etc'

AC_PROG_CC                      dnl Find C compiler
AC_CHECK_PROGS(AR, ar, no)
AC_CONFIG_HEADER(config.h)

dnl Add some common directories to PATH in case they are not there
PATH=$PATH:/usr/local/bin

AC_PROG_INSTALL

AC_TYPE_LONG_LONG_INT

AC_ARG_ENABLE(embedded-perl, [  --disable-embedded-perl Disable embedded Perl interpreter], ac_cv_embedded_perl=$enableval, ac_cv_embedded_perl=yes)
AC_ARG_ENABLE(poll, [  --enable-poll           Use poll(2) instead of select(2) in multiplexor], ac_cv_use_poll=$enableval, ac_cv_use_poll=no)
AC_PATH_PROG(PERL, perl)

dnl Check for socklen_t type
AC_MSG_CHECKING(whether socklen_t is defined)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [socklen_t x;], ac_have_socklen_t=yes, ac_have_socklen_t=no)
AC_MSG_RESULT($ac_have_socklen_t)
if test "$ac_have_socklen_t" = "yes" ; then
   AC_DEFINE(HAVE_SOCKLEN_T,[],["Whether we have the variable type socklen_t"])
fi

AC_MSG_CHECKING(whether fPIC compiler option is accepted)
OLD_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fPIC -Werror"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[return 0;]])],
    [AC_MSG_RESULT(yes)
     CFLAGS="$OLD_CFLAGS -fPIC"],
    [AC_MSG_RESULT(no)
     CFLAGS="$OLD_CFLAGS"])

for thing in prefix siteprefix vendorprefix installarchlib installprivlib installbin installman1dir installman3dir installscript installsitearch installsitelib; do
    AC_MSG_CHECKING([for Perl installation variable $thing])
    val=`$PERL -V:$thing | sed -e "s/^.*='//" -e "s/';$//"`
    AC_MSG_RESULT($val)
    dnl Stupid m4....
    up=`echo $thing | tr '[[a-z]]' '[[A-Z]]'`
    eval "PERL$up=$val"
done

dnl wait3
dnl We know that wait3 works fine on Solaris 9, but autoconf
dnl sometimes misses it
un=`uname -s -r`
if test "$un" = "SunOS 5.9" ; then
   ac_cv_func_wait3_rusage=yes
fi

AC_FUNC_WAIT3

if test -z "$PERL" ; then
   AC_MSG_ERROR([*** Cannot continue without Perl.  Sorry.])
   exit 1
fi

AC_PATH_PROG(NM, nm)

dnl Allow user to tell us where Sendmail is (or will be)
SENDMAILPROG=no
AC_ARG_WITH(sendmail,
[  --with-sendmail=PATH    specify location of Sendmail binary],
   SENDMAILPROG=$with_sendmail, SENDMAILPROG=no)

DEFANGUSER=""
AC_ARG_WITH(user,
[  --with-user=LOGIN       use LOGIN as the MIMEDefang user],
   DEFANGUSER=$with_user, DEFANGUSER=defang)

AC_SUBST(DEFANGUSER)

IP_HEADER=no
AC_ARG_WITH(ipheader,
[  --with-ipheader         install /etc/mail/mimedefang-ip-key],
   IP_HEADER=$with_ipheader, IP_HEADER=no)

AC_SUBST(IP_HEADER)

dnl Allow user to tell us where milter includes are
MILTERINC=
AC_ARG_WITH(milterinc,
[  --with-milterinc=PATH   specify alternative location of milter includes],
   MILTERINC=$with_milterinc, MILTERINC=)

dnl Allow user to tell us where milter libraries are
MILTERLIB=
AC_ARG_WITH(milterlib,
[  --with-milterlib=PATH   specify alternative location of milter libraries],
   MILTERLIB=$with_milterlib, MILTERLIB=)

dnl Allow specification of sysconfig subdir
AC_ARG_WITH(confsubdir,
[  --with-confsubdir=DIR   specify configuration subdirectory
			  (mail) ],
	CONFSUBDIR="/$with_confsubdir", CONFSUBDIR=/mail)
if test "$CONFSUBDIR" = "/" -o "$CONFSUBDIR" = "//" ; then
   CONFSUBDIR=""
fi

AC_SUBST(CONFSUBDIR)

dnl Allow specification of spool dir
AC_ARG_WITH(spooldir,
[  --with-spooldir=DIR     specify location of spool directory
			  (/var/spool/MIMEDefang)],
	SPOOLDIR=$with_spooldir, SPOOLDIR=/var/spool/MIMEDefang)

dnl Allow specification of quarantine dir
AC_ARG_WITH(quarantinedir,
[  --with-quarantinedir=DIR
			  specify location of quarantine directory
			  (/var/spool/MD-Quarantine)],
	QDIR=$with_quarantinedir, QDIR=/var/spool/MD-Quarantine)

AC_ARG_ENABLE(pthread-flag,
[  --enable-pthread-flag   Supply the -pthread flag to the C compiler], FORCE_PTHREAD_FLAG=-pthread, FORCE_PTHREAD_FLAG="")

AC_ARG_ENABLE(check-perl-modules,
[  --disable-check-perl-modules
			  Disable compile-time checks for Perl modules], ac_cv_perlmodcheck=$enableval, ac_cv_perlmodcheck=yes)

dnl Check for Perl modules
if test "$ac_cv_perlmodcheck" = "no" ; then
   AC_MSG_RESULT([Compile-time checking for Perl modules disabled])
   dnl for installation of spamassassin.cf
   HAVE_SPAM_ASSASSIN=yes
else
    for module in 'IO::Socket' 'MIME::Tools 5.410 ()' 'MIME::WordDecoder' 'Digest::SHA' ; do
	AC_MSG_CHECKING([for Perl module $module])
	(echo "use lib '$PERLINSTALLSITELIB'; use $module;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
	if test $? != 0 ; then
	    AC_MSG_WARN([*** Error trying to use Perl module $module])
	    AC_MSG_WARN([*** Make sure the following Perl modules are installed:])
	    AC_MSG_WARN([*** MIME::Tools version 5.410 or higher (5.411a recommended)])
	    AC_MSG_WARN([*** MIME::WordDecoder])
	    AC_MSG_WARN([*** Digest::SHA])
	    exit 1
	fi
	AC_MSG_RESULT(ok)
    done
    dnl Check for *optional* Perl modules

    AC_MSG_CHECKING([for Perl module Mail::SpamAssassin 3.0 or better])
    (echo "use Mail::SpamAssassin 3.0 ();" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? != 0 ; then
	HAVE_SPAM_ASSASSIN=no
    else
	HAVE_SPAM_ASSASSIN=yes
    fi
    AC_MSG_RESULT($HAVE_SPAM_ASSASSIN)

    AC_MSG_CHECKING([for Perl module HTML::Parser])
    (echo "use HTML::Parser;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? != 0 ; then
	HAVE_HTML_PARSER=no
    else
	HAVE_HTML_PARSER=yes
    fi
    AC_MSG_RESULT($HAVE_HTML_PARSER)

    AC_MSG_CHECKING([for Perl module Archive::Zip])
    (echo "use Archive::Zip;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? != 0 ; then
	HAVE_ARCHIVE_ZIP=no
    else
	HAVE_ARCHIVE_ZIP=yes
    fi
    AC_MSG_RESULT($HAVE_ARCHIVE_ZIP)

    AC_MSG_CHECKING([for Perl module IO::Socket::SSL])
    (echo "use IO::Socket::SSL;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? != 0 ; then
	HAVE_IO_SOCKET_SSL=no
    else
	HAVE_IO_SOCKET_SSL=yes
    fi
    AC_MSG_RESULT($HAVE_IO_SOCKET_SSL)

    AC_MSG_CHECKING([for Perl module JSON])
    (echo "use JSON;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? != 0 ; then
	HAVE_JSON=no
    else
	HAVE_JSON=yes
    fi
    AC_MSG_RESULT($HAVE_JSON)

    AC_MSG_CHECKING([for Perl module LWP::UserAgent])
    (echo "use LWP::UserAgent;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? != 0 ; then
	HAVE_LWP=no
    else
	HAVE_LWP=yes
    fi
    AC_MSG_RESULT($HAVE_LWP)

    AC_MSG_CHECKING([for Perl module Mail::DKIM])
    (echo "use Mail::DKIM;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? != 0 ; then
	HAVE_DKIM=no
    else
	HAVE_DKIM=yes
    fi
    AC_MSG_RESULT($HAVE_DKIM)

    dnl Check MIME::Tools version
    dirs=`echo 'print "@INC\n";' | $PERL`
    foundit=""
    for i in $dirs ; do
	if test -r "$i/MIME/Field/ParamVal.pm" ; then
	    foundit="$i/MIME/Field/ParamVal.pm"
	    break
	fi
    done

    if test "$foundit" != "" ; then
	AC_MSG_CHECKING([MIME-Tools version])
	mtversion=`echo '$x = $MIME::Tools::VERSION; $y = int($x) * 10000; $z = ($x - int($x)) * 10000; print $y + $z;' | $PERL -I$PERLINSTALLSITELIB -MMIME::Tools 2>/dev/null`
	mt_actual_version=`echo 'print "$MIME::Tools::VERSION";' | $PERL -I$PERLINSTALLSITELIB -MMIME::Tools 2>/dev/null`
	if test "$mtversion" = "" ; then
	   mtversion="unknown"
	   mt_actual_version="unknown"
	fi
	AC_MSG_RESULT($mt_actual_version)
    else
	mtversion="unknown"
    fi
fi

dnl We need at least *one* of Sys::Syslog or Unix::Syslog
HAVE_A_SYSLOG=0
for module in 'Sys::Syslog' 'Unix::Syslog' ; do
    AC_MSG_CHECKING([for Perl module $module])
    (echo "use $module;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? = 0 ; then
	HAVE_A_SYSLOG=1
	AC_MSG_RESULT(ok)
    else
	AC_MSG_RESULT(no)
    fi
done

if test $HAVE_A_SYSLOG = 0 ; then
    if test "$ac_cv_perlmodcheck" = "yes" ; then
    	AC_MSG_WARN([*** Error: Could not find Sys::Syslog or Unix::Syslog])
	AC_MSG_WARN([*** One of those Perl modules is required.]);
	exit 1
    fi
fi

dnl Check for ExtUtils::Embed
if test "$ac_cv_embedded_perl" = "no" ; then
    echo "Check for embedded perl disabled by --disable-embedded-perl option"
    HAVE_EXTUTILS_EMBED=no
else
    AC_MSG_CHECKING([for Perl module ExtUtils::Embed])
    (echo "use ExtUtils::Embed;" ; echo "exit(0);") | $PERL > /dev/null 2>&1
    if test $? = 0 ; then
	HAVE_EXTUTILS_EMBED=yes
	AC_MSG_RESULT(ok)
    else
	HAVE_EXTUTILS_EMBED=no
	AC_MSG_RESULT(no)
    fi
fi

AC_SUBST(HAVE_SPAM_ASSASSIN)
AC_CHECK_HEADERS(getopt.h unistd.h stdint.h poll.h stdint.h)

dnl Check if stdint.h defines uint32_t
AC_MSG_CHECKING(whether stdint.h defines uint32_t)
AC_TRY_COMPILE([
#include <stdint.h>
], [uint32_t foo;], ac_uint32_t_defined=yes, ac_uint32_t_defined=no)
AC_MSG_RESULT($ac_uint32_t_defined)

if test "$ac_uint32_t_defined" = "yes" ; then
   AC_DEFINE(HAVE_UINT32_T,[],["whether uint32_t is defined"])
fi

dnl Check if sys/types.h defines uint32_t
AC_MSG_CHECKING(whether sys/types.h defines uint32_t)
AC_TRY_COMPILE([
#include <sys/types.h>
], [uint32_t foo;], ac_uint32_t_defined=yes, ac_uint32_t_defined=no)
AC_MSG_RESULT($ac_uint32_t_defined)

if test "$ac_uint32_t_defined" = "yes" ; then
   AC_DEFINE(HAVE_UINT32_T,[],["whether uint32_t is defined"])
fi

dnl sig_atomic_t
AC_MSG_CHECKING(whether sig_atomic_t is defined)
AC_TRY_COMPILE([
#include <signal.h>
], [sig_atomic_t foo;], ac_have_sig_atomic_t=yes, ac_have_sig_atomic_t=no)
AC_MSG_RESULT($ac_have_sig_atomic_t)
if test "$ac_have_sig_atomic_t" = "yes" ; then
   AC_DEFINE(HAVE_SIG_ATOMIC_T,[],["Whether we have the atomic_t variable type "])
fi

dnl Check if compiler allows "-pthread" option, but only if
dnl we are using GCC

if test "$FORCE_PTHREAD_FLAG" = "-pthread" ; then
   AC_MSG_RESULT(Forcing use of -pthread C compiler flag)
   PTHREAD_FLAG=-pthread
elif test "$GCC" = yes ; then
   AC_MSG_CHECKING([whether ${CC-cc} accepts -pthread])
   echo 'void f(){}' > conftest.c
   if test -z "`${CC-cc} -pthread -c conftest.c 2>&1`"; then
	   ac_cv_prog_cc_pthread=yes
	   PTHREAD_FLAG="-pthread"
   else
	PTHREAD_FLAG=""
	ac_cv_prog_cc_pthread=no
   fi
   AC_MSG_RESULT($ac_cv_prog_cc_pthread)
   rm -f conftest*
else
   PTHREAD_FLAG=""
fi

if test "$HAVE_EXTUTILS_EMBED" = "yes" ; then
   AC_MSG_CHECKING([if we can embed a Perl interpreter in C])
   OLDCFLAGS="$CFLAGS"
   OLDLDFLAGS="$LDFLAGS"
   OLDLIBS="$LIBS"
   LIBS="-lperl $LIBS"
   EMBPERLLDFLAGS="`$PERL -MExtUtils::Embed -e ldopts`"
   EMBPERLCFLAGS="`$PERL -MExtUtils::Embed -e ccopts`"
   LDFLAGS="$EMBPERLLDFLAGS $LDFLAGS"
   CFLAGS="$EMBPERLCFLAGS $CFLAGS"
   AC_TRY_RUN([
#include <EXTERN.h>
#include <perl.h>
#include <stdlib.h>
static PerlInterpreter *my_perl;
int main(int argc, char **argv, char **env) {
    my_perl = perl_alloc();
    if (!my_perl) exit(1);
    exit(0);
}
], EMBED_PERL=yes, EMBED_PERL=no)
   LIBS="$OLDLIBS"
   CFLAGS="$OLDCFLAGS"
   LDFLAGS="$OLDLDFLAGS"
   AC_MSG_RESULT($EMBED_PERL)
else
   EMBED_PERL=no
fi
if test "$EMBED_PERL" = "no" ; then
   EMBPERLCFLAGS=""
   EMBPERLLDFLAGS=""
   EMBPERLLIBS=""
   EMBPERLDEFS=""
   EMBPERLOBJS=""
else
   EMBPERLLIBS="-lperl"
   EMBPERLDEFS="-DEMBED_PERL"
   EMBPERLOBJS="embperl.o xs_init.o"
   # Check for buggy perl interpreter
   AC_MSG_CHECKING([if it is safe to destroy and recreate a Perl interpreter])
   LIBS="-lperl $LIBS"
   LDFLAGS="$EMBPERLLDFLAGS $LDFLAGS"
   CFLAGS="$EMBPERLCFLAGS $CFLAGS $PTHREAD_FLAG"
   AC_TRY_RUN([
#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl = NULL;
static char **argv = NULL;

int
make_embedded_interpreter(char **env)
{
    int argc;
    if (!argv) {
        argv = (char **) malloc(6 * sizeof(char *));
    }
    if (my_perl != NULL) {
	perl_destruct(my_perl);
	perl_free(my_perl);
	my_perl = NULL;
    }
    argv[0] = "";
    argv[1] = "-e";
    argv[2] = "print(\"\");";
    argv[3] = NULL;
    argc = 3;

#ifdef PERL_SYS_INIT3
    PERL_SYS_INIT3(&argc, &argv, &env);
#endif
    my_perl = perl_alloc();
    if (!my_perl) {
	return -1;
    }
    PERL_SET_CONTEXT(my_perl);
    PL_perl_destruct_level = 1;
    perl_construct(my_perl);
    PL_perl_destruct_level = 1;
    argv[0] = "";
    argv[1] = "-e";
    argv[2] = "print(\"\");";
    argv[3] = NULL;
    argc = 3;
    perl_parse(my_perl, NULL, argc, argv, NULL);
    perl_run(my_perl);
    return 0;
}

int
main(int argc, char **argv, char **env)
{
    make_embedded_interpreter(env);
    make_embedded_interpreter(env);
    return 0;
}
], SAFE_EMBED_PERL=yes, SAFE_EMBED_PERL=no)
   LIBS="$OLDLIBS"
   CFLAGS="$OLDCFLAGS"
   LDFLAGS="$OLDLDFLAGS"
   AC_MSG_RESULT($SAFE_EMBED_PERL)
   if test "$SAFE_EMBED_PERL" = "yes" ; then
      EMBPERLDEFS="$EMBPERLDEFS -DSAFE_EMBED_PERL"
   fi
fi

if test "$ac_cv_use_poll" = "no" ; then
    USEPOLL=""
else
    if test "$ac_cv_header_poll_h" = "no" ; then
	USEPOLL=""
	AC_MSG_WARN([*** You used --enable-poll, but I cannot find the])
	AC_MSG_WARN([*** poll.h header.  Turning OFF --enable-poll])
    else
	USEPOLL="-DEVENT_USE_POLL=1"
    fi
fi

AC_SUBST(EMBPERLCFLAGS)
AC_SUBST(EMBPERLLDFLAGS)
AC_SUBST(EMBPERLLIBS)
AC_SUBST(EMBPERLOBJS)
AC_SUBST(EMBPERLDEFS)
AC_SUBST(USEPOLL)

AC_CHECK_LIB(resolv, res_init)
AC_CHECK_LIB(socket, htons)
AC_CHECK_LIB(nsl, gethostbyname)
LIBS_WITHOUT_PTHREAD="$LIBS"
AC_CHECK_LIB(pthread, pthread_once)

dnl Do we have initgroups?
AC_CHECK_FUNCS(initgroups)
dnl How about getpwnam_r?
AC_CHECK_FUNCS(getpwnam_r)
AC_CHECK_FUNCS(setrlimit)
AC_CHECK_FUNCS(snprintf)
AC_CHECK_FUNCS(vsnprintf)
AC_CHECK_FUNCS(readdir_r)
AC_CHECK_FUNCS(pathconf)
AC_CHECK_FUNCS(inet_ntop)

if test "$SPOOLDIR" = "no" -o "$SPOOLDIR" = "" ; then
	SPOOLDIR=/var/spool/MIMEDefang
fi

if test "$QDIR" = "no" -o "$QDIR" = "" ; then
	QDIR=/var/spool/MIMEDefang
fi

AC_SUBST(SPOOLDIR)
AC_SUBST(QDIR)

dnl debugging
AC_ARG_ENABLE(debugging, [  --enable-debugging      Add debugging messages to syslog], ac_cv_debugging=$enableval, ac_cv_debugging=no)

dnl Check for virus scanners
AC_ARG_ENABLE(anti-virus,
			[  --disable-anti-virus    Do not look for anti-virus scanners], ac_cv_antivirus=$enableval, ac_cv_antivirus=yes)
AC_ARG_ENABLE(antivir,  [  --disable-antivir       Do not include support for H+BEDV antivir], ac_cv_antivir=$enableval, ac_cv_antivir=yes)
AC_ARG_ENABLE(vexira,   [  --disable-vexira        Do not include support for Central Command Vexira], ac_cv_vexira=$enableval, ac_cv_vexira=yes)
AC_ARG_ENABLE(uvscan,   [  --disable-uvscan        Do not include support for NAI uvscan], ac_cv_uvscan=$enableval, ac_cv_uvscan=yes)
AC_ARG_ENABLE(bdc,      [  --disable-bdc           Do not include support for Bitdefender bdc], ac_cv_bdc=$enableval, ac_cv_bdc=yes)
AC_ARG_ENABLE(sweep,    [  --disable-sweep         Do not include support for Sophos sweep], ac_cv_sweep=$enableval, ac_cv_sweep=yes)
AC_ARG_ENABLE(savscan,  [  --disable-savscan       Do not include support for Sophos savscan], ac_cv_savscan=$enableval, ac_cv_savscan=yes)
AC_ARG_ENABLE(trend,    [  --disable-trend         Do not include support for Trend Filescanner/Interscan], ac_cv_trend=$enableval, ac_cv_trend=yes)
AC_ARG_ENABLE(AvpLinux, [  --disable-AvpLinux      Do not include support for AVP AvpLinux], ac_cv_AvpLinux=$enableval, ac_cv_AvpLinux=yes)
AC_ARG_ENABLE(kavscanner, [  --disable-kavscanner    Do not include support for Kaspersky kavscanner], ac_cv_kavscanner=$enableval, ac_cv_kavscanner=yes)
AC_ARG_ENABLE(aveclient, [  --disable-aveclient     Do not include support for AVP5 aveclient], ac_cv_aveclient=$enableval, ac_cv_aveclient=yes)
AC_ARG_ENABLE(clamav, [  --disable-clamav        Do not include support for clamav], ac_cv_clamav=$enableval, ac_cv_clamav=yes)
AC_ARG_ENABLE(fsav,     [  --disable-fsav          Do not include support for F-Secure Anti-Virus], ac_cv_fsav=$enableval, ac_cv_fsav=yes)
AC_ARG_ENABLE(csav,     [  --disable-csav          Do not include support for Command Software CSAV], ac_cv_csav=$enableval, ac_cv_csav=yes)
AC_ARG_ENABLE(fprot,    [  --disable-fprot         Do not include support for F-prot Anti-Virus], ac_cv_fprot=$enableval, ac_cv_fprot=yes)
AC_ARG_ENABLE(fpscan,   [  --disable-fpscan        Do not include support for F-prot Anti-Virus v6], ac_cv_fpscan=$enableval, ac_cv_fpscan=yes)
AC_ARG_ENABLE(sophie,   [  --disable-sophie        Do not include support for Sophie], ac_cv_sophie=$enableval, ac_cv_sophie=yes)
AC_ARG_ENABLE(nvcc,   [  --disable-nvcc          Do not include support for Nvcc], ac_cv_nvcc=$enableval, ac_cv_nvcc=yes)
AC_ARG_ENABLE(clamd,   [  --disable-clamd         Do not include support for clamd], ac_cv_clamd=$enableval, ac_cv_clamd=yes)
AC_ARG_ENABLE(trophie, [  --disable-trophie       Do not include support for Trophie], ac_cv_trophie=$enableval, ac_cv_trophie=yes)
AC_ARG_ENABLE(nod32,   [  --disable-nod32         Do not include support for Eset NOD32], ac_cv_nod32=$enableval, ac_cv_nod32=yes)
AC_ARG_ENABLE(rspamc,   [  --disable-rspamc       Do not include support for Rspamd], ac_cv_rspamc=$enableval, ac_cv_rspamc=yes)

ANTIVIR_PATH="$PATH:/usr/lib/AntiVir:/usr/local/uvscan:/opt/AVP:/etc/iscan:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bd7:/usr/local/bd7/bin:/opt/kav/bin:/opt/kav/5.5/kav4unix/bin/:/opt/eset/nod32/bin"

if test "$ac_cv_antivirus" = "yes"; then
    if test "$ac_cv_antivir" = yes; then
	AC_PATH_PROG(HBEDV,  antivir,  /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_vexira" = yes; then
	AC_PATH_PROG(VEXIRA,  vascan,  /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_uvscan" = yes; then
	AC_PATH_PROG(NAI,    uvscan,   /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_bdc" = yes; then
	AC_PATH_PROG(BDC,    bdc,   /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_sweep" = yes; then
	AC_PATH_PROG(SOPHOS, sweep,    /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_savscan" = yes; then
	AC_PATH_PROG(SAVSCAN, savscan,    /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_trend" = yes; then
	AC_PATH_PROG(TREND, vscan,    /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_kavscanner" = yes ; then
	AC_PATH_PROG(KAVSCANNER, kavscanner, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_clamav" = yes; then
	AC_PATH_PROG(CLAMSCAN,    clamscan, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_clamav" = yes; then
	AC_PATH_PROG(CLAMDSCAN,    clamdscan, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_AvpLinux" = yes; then
	AC_PATH_PROG(AVP,    AvpLinux, /bin/false, $ANTIVIR_PATH)
	AC_PATH_PROG(AVP_KAVDAEMON, kavdaemon, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_aveclient" = yes; then
	AC_PATH_PROG(AVP5, aveclient, /bin/false, $ANTIVIR_PATH)
    fi

# Update AVP for best scanner: kavdaemon preferred over AvpLinux

    if test "$AVP_KAVDAEMON" != "/bin/false" ; then
	AVP="$AVP_KAVDAEMON"
    fi

    if test "$ac_cv_csav" = yes ; then
        AC_PATH_PROG(CSAV,    csav, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_fsav" = yes; then
	AC_PATH_PROG(FSAV,    fsav, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_fprot" = yes; then
	AC_PATH_PROG(FPROT, f-prot, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_fpscan" = yes; then
	AC_PATH_PROG(FPSCAN, fpscan, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_sophie" = yes; then
	AC_PATH_PROG(SOPHIE, sophie, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_nvcc" = yes; then
	AC_PATH_PROG(NVCC, nvcc, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_clamd" = yes; then
	AC_PATH_PROG(CLAMD, clamd, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_trophie" = yes; then
        AC_PATH_PROG(TROPHIE, trophie, /bin/false, $ANTIVIR_PATH)
    fi

    if test "$ac_cv_nod32" = yes; then
        AC_PATH_PROG(NOD32, nod32cli, /bin/false, $ANTIVIR_PATH)
    fi
fi

if test "$ac_cv_rspamc" = yes; then
   AC_PATH_PROG(RSPAMC, rspamc, /bin/false, $PATH)
fi

test -z "$HBEDV" && HBEDV=/bin/false
test -z "$VEXIRA" && VEXIRA=/bin/false
test -z "$NAI" && NAI=/bin/false
test -z "$BDC" && BDC=/bin/false
test -z "$SOPHOS" && SOPHOS=/bin/false
test -z "$SAVSCAN" && SAVSCAN=/bin/false
test -z "$TREND" && TREND=/bin/false
test -z "$CLAMSCAN" && CLAMSCAN=/bin/false
test -z "$CLAMDSCAN" && CLAMDSCAN=/bin/false
test -z "$AVP" && AVP=/bin/false
test -z "$AVP5" && AVP5=/bin/false
test -z "$AVP_KAVDAEMON" && AVP_KAVDAEMON=/bin/false
test -z "$KAVSCANNER" && KAVSCANNER=/bin/false
test -z "$CSAV" && CSAV=/bin/false
test -z "$FSAV" && FSAV=/bin/false
test -z "$FPROT" && FPROT=/bin/false
test -z "$FPSCAN" && FPSCAN=/bin/false
test -z "$SOPHIE" && SOPHIE=/bin/false
test -z "$NVCC" && NVCC=/bin/false
test -z "$CLAMD" && CLAMD=/bin/false
test -z "$TROPHIE" && TROPHIE=/bin/false
test -z "$NOD32" && NOD32=/bin/false
test -z "$RSPAMC" && RSPAMC=/bin/false

if test "$ac_cv_debugging" = yes ; then
    ENABLE_DEBUGGING=-DENABLE_DEBUGGING
else
    ENABLE_DEBUGGING=
fi

dnl find Sendmail
if test "$SENDMAILPROG" = "no" ; then
   AC_PATH_PROG(SENDMAILPROG, sendmail, no, $PATH:/sbin:/usr/sbin:/usr/lib:/usr/libexec)
fi

dnl rm
AC_PATH_PROG(RM, rm, no, $PATH)

AC_DEFUN([MD_MILTER_SFIO],[
    AC_MSG_CHECKING([whether libmilter requires -lsfio])
    RESULT=`$NM $LIBMILTER 2>/dev/null | grep sfsprintf; $NM -D $LIBMILTERSO 2>/dev/null | grep sfsprintf`
    if test -z "$RESULT" ; then
	AC_MSG_RESULT(no)
    else
	AC_MSG_RESULT(yes)
	LIBS="$LIBS -lsfio"
    fi
])

AC_DEFUN([MD_SM_LDAP],[
    AC_MSG_CHECKING([whether libsm requires -lldap])
    RESULT=`$NM $LIBSM | grep ldap_`
    if test -z "$RESULT" ; then
	AC_MSG_RESULT(no)
    else
	AC_MSG_RESULT(yes)
	LIBS="$LIBS -lldap -llber"
    fi
])

AC_DEFUN([MD_MILTER_LDAP],[
    AC_MSG_CHECKING([whether libmilter requires -lldap])
    RESULT=`$NM $LIBMILTER 2>/dev/null | grep ldap_; $NM -D $LIBMILTERSO 2>/dev/null | grep ldap_`
    if test -z "$RESULT" ; then
	AC_MSG_RESULT(no)
    else
	AC_MSG_RESULT(yes)
	LIBS="$LIBS -lldap -llber"
    fi
])

AC_DEFUN([MD_MILTER_SM],[
    OLD_LIBS="$LIBS"
    LIBS="$LIBS -lmilter"
    AC_MSG_CHECKING([whether libmilter requires -lsm])
    AC_TRY_LINK(
    [#include "libmilter/mfapi.h"
     #include <string.h>],
    [extern size_t sm_strlcpy(char *, char const *, ssize_t); char foo[10]; sm_strlcpy(foo, "", 0);],
    NEED_LIBSM=no,
    NEED_LIBSM=yes)
    AC_MSG_RESULT($NEED_LIBSM)
    LIBS="$OLD_LIBS"
    if test "$NEED_LIBSM" = yes ; then
       LIBS="$LIBS -lsm"
       MD_SM_LDAP
    else
       MD_MILTER_LDAP
    fi
])

if test "$SENDMAILPROG" = "no" ; then
    AC_MSG_WARN([Oops.. I couldn't find the 'sendmail' program.  Please install it.])
    PROBLEM=1
fi

if test "$PROBLEM" = 1 ; then
    exit 1
fi

dnl GCC warning level
if test "$GCC" = yes; then
    if test "`uname -s`" = Linux; then
	    CFLAGS="$CFLAGS -Wall -Wstrict-prototypes"
    fi
fi

AC_SUBST(ENABLE_DEBUGGING)
AC_SUBST(PTHREAD_FLAG)
VERSION=`$PERL -I modules/lib -e 'use Mail::MIMEDefang; print Mail::MIMEDefang->version'`
AC_SUBST(VERSION)

dnl Jigger for machines without snprintf
if test "$ac_cv_func_snprintf" != "yes" -o "$ac_cv_func_vsnprintf" != "yes" ; then
   AC_MSG_RESULT([Your OS lacks snprintf or vsnprintf.  Sorry!])
   exit 1
fi

dnl Find sendmail include file.  The nasty path is in case you're building
dnl Sendmail at the same level as MIMEDefang... we want to use that include
dnl file...
SMMILTER=`echo ../sendmail-*/include`
as_test_x='test -e'
as_executable_p='test -e'
# Redefine so AC_PATH_PROG works
as_fn_executable_p() {
test -e "$1"
}

AC_PATH_PROG(MINCLUDE, libmilter/mfapi.h, no, $MILTERINC:$SMMILTER:/usr/include:/usr/local/include:/usr/local/include/sendmail:/opt/local/include)

dnl Fix up the include stuff
MINCLUDE=`dirname "$MINCLUDE"`
MINCLUDE=`dirname "$MINCLUDE"`

dnl If MINCLUDE is "/usr/include", do NOT add to include path, because
dnl this messes up compilation with gcc on Solaris.
if test "$MINCLUDE" = "/usr/include" ; then
   MINCLUDE=""
else
   MINCLUDE="-I${MINCLUDE}"
fi

dnl find libmilter.a and libsm.a
SMPATH=`echo ../sendmail-*/obj.*/libmilter`
MDLIBPATH=/usr/local/lib:/usr/local/lib64:/usr/lib:/usr/lib64:/lib:/lib64:/usr/lib/libmilter:/usr/lib64/libmilter
AC_PATH_PROG(LIBMILTER, libmilter.a, no, $MILTERLIB:$SMPATH:$MDLIBPATH)
SMPATH=`echo ../sendmail-*/obj.*/libsm`
AC_PATH_PROG(LIBSM, libsm.a, no, $SMPATH:$MDLIBPATH)

dnl find libmilter.so in case we have shared libraries
AC_PATH_PROG(LIBMILTERSO, libmilter.so, no, $MILTERLIB:$SMPATH:$MDLIBPATH)

dnl Sanity checks
PROBLEM=0
if test "$LIBMILTER" = "no" -a "$LIBMILTERSO" = "no" ; then
    AC_MSG_WARN([Oops.. I couldn't find libmilter.a or libmilter.so.  Please install Sendmail])
    AC_MSG_WARN([and its libraries.  You must run Build in the libmilter/ directory])
    AC_MSG_WARN([to compile libmilter.])
    PROBLEM=1
fi

if test "$LIBMILTER" != "no" ; then
    LIBMILTERACTUAL="$LIBMILTER"
else
    LIBMILTERACTUAL="$LIBMILTERSO"
fi

dnl The directory containing libmilter
LIBMILTERDIR=`dirname "$LIBMILTERACTUAL"`

dnl Don't include standard directory paths
if test "$LIBMILTERDIR" = "/usr/lib" -o "$LIBMILTERDIR" = "/lib" -o "$LIBMILTERDIR" = "/usr/lib64" -o "$LIBMILTERDIR" = "/lib64" ; then
   LIBMILTERDIR=""
else
   LDFLAGS="$LDFLAGS -L$LIBMILTERDIR"
fi

if test "$MINCLUDE" = "no" ; then
    AC_MSG_WARN([Oops.. I couldn't find libmilter/mfapi.h.  Please install Sendmail 8.12])
    AC_MSG_WARN([and its header files.])
    PROBLEM=1
fi

dnl Check if our libmilter is old and needs LIBSM.  Also checks if it
dnl needs libldap
MD_MILTER_SM

AC_SUBST(LIBS_WITHOUT_PTHREAD)
dnl evaluated versions of conf dir
CONFDIR_EVAL=`echo ${sysconfdir}${CONFSUBDIR}`
AC_SUBST(CONFDIR_EVAL)
AC_SUBST(LDFLAGS)
AC_SUBST(PERLPREFIX)
AC_SUBST(PERLSITEPREFIX)
AC_SUBST(PERLVENDORPREFIX)
AC_SUBST(PERLINSTALLARCHLIB)
AC_SUBST(PERLINSTALLPRIVLIB)
AC_SUBST(PERLINSTALLBIN)
AC_SUBST(PERLINSTALLMAN1DIR)
AC_SUBST(PERLINSTALLMAN3DIR)
AC_SUBST(PERLINSTALLSCRIPT)
AC_SUBST(PERLINSTALLSITEARCH)
AC_SUBST(PERLINSTALLSITELIB)
AC_SUBST(PERLINSTALLDATA)
AC_SUBST(PERLINSTALLSITEDATA)
AC_SUBST(PERLINSTALLVENDORDATA)
AC_SUBST(PERLINSTALLCONF)
AC_SUBST(PERLINSTALLSITECONF)
AC_SUBST(PERLINSTALLVENDORCONF)

AC_OUTPUT(Makefile mimedefang.pl script/mimedefang-util examples/init-script mimedefang-filter.5 mimedefang-multiplexor.8 mimedefang-protocol.7 mimedefang-notify.7 mimedefang.8 mimedefang.pl.8 md-mx-ctrl.8 watch-mimedefang redhat/mimedefang-init redhat/mimedefang-sysconfig)
chmod a+x examples/init-script > /dev/null 2>&1
chmod a+x watch-mimedefang > /dev/null 2>&1
chmod a+x redhat/mimedefang-init > /dev/null 2>&1
chmod a+x script/mimedefang-util > /dev/null 2>&1

dnl Status info
echo ""
echo "*** Virus scanner detection results:"
PROBLEM=0
GOT_VIRUS_SCANNER=0
if test "$ac_cv_antivirus" != "yes" ; then
    echo "All virus-scanner detection disabled by --disable-anti-virus"
else
    if test "$HBEDV" = "/bin/false" ; then
	if test "$ac_cv_antivir" != "yes" ; then
	    echo "H+BEDV   'antivir'   NO (Disabled by configure command)"
	else
	    echo "H+BEDV   'antivir'   NO (not found)"
	fi
    else
	echo "H+BEDV   'antivir'   YES - $HBEDV"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$VEXIRA" = "/bin/false" ; then
	if test "$ac_cv_vexira" != "yes" ; then
	    echo "Vexira   'vascan'    NO (Disabled by configure command)"
	else
	    echo "Vexira   'vascan'    NO (not found)"
	fi
    else
	echo "Vexira   'vascan'    YES - $VEXIRA"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$NAI" = "/bin/false" ; then
	if test "$ac_cv_uvscan" != "yes" ; then
	    echo "NAI      'uvscan'    NO (Disabled by configure command)"
	else
	    echo "NAI      'uvscan'    NO (not found)"
	fi
    else
	echo "NAI      'uvscan'    YES - $NAI"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$BDC" = "/bin/false" ; then
	if test "$ac_cv_bdc" != "yes" ; then
	    echo "BDC      'bdc'       NO (Disabled by configure command)"
	else
	    echo "BDC      'bdc'       NO (not found)"
	fi
    else
	echo "BDC      'bdc'       YES - $BDC"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$SOPHOS" = "/bin/false" ; then
	if test "$ac_cv_sweep" != "yes" ; then
	    echo "Sophos   'sweep'     NO (Disabled by configure command)"
	else
	    echo "Sophos   'sweep'     NO (not found)"
	fi
    else
	echo "Sophos   'sweep'     YES - $SOPHOS"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$SAVSCAN" = "/bin/false" ; then
	if test "$ac_cv_savscan" != "yes" ; then
	    echo "Sophos   'savscan'   NO (Disabled by configure command)"
	else
	    echo "Sophos   'savscan'   NO (not found)"
	fi
    else
	echo "Sophos   'savscan'   YES - $SAVSCAN"
	GOT_VIRUS_SCANNER=1
    fi
    
    if test "$TREND" = "/bin/false" ; then
	if test "$ac_cv_trend" != "yes" ; then
	    echo "TREND    'vscan'     NO (Disabled by configure command)"
	else
	    echo "TREND    'vscan'     NO (not found)"
	fi
    else
	echo "TREND    'vscan'     YES - $TREND"
 	GOT_VIRUS_SCANNER=1
    fi

    if test "$CLAMSCAN" = "/bin/false" ; then
	if test "$ac_cv_clamav" != "yes" ; then
	    echo "CLAMSCAN 'clamav'    NO (Disabled by configure command)"
	else
	    echo "CLAMSCAN 'clamav'    NO (not found)"
	fi
    else
	echo "CLAMSCAN 'clamav'    YES - $CLAMSCAN"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$CLAMDSCAN" = "/bin/false" ; then
	if test "$ac_cv_clamav" != "yes" ; then
	    echo "CLAMDSCAN 'clamav'    NO (Disabled by configure command)"
	else
	    echo "CLAMDSCAN 'clamav'    NO (not found)"
	fi
    else
	echo "CLAMDSCAN 'clamav'    YES - $CLAMDSCAN"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$AVP" = "/bin/false" ; then
	if test "$ac_cv_AvpLinux" != "yes" ; then
	    echo "AVP      'AvpLinux'  NO (Disabled by configure command)"
	else
	    echo "AVP      'AvpLinux'  NO (not found)"
	fi
    else
	echo "AVP      'AvpLinux'  YES - $AVP"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$AVP5" = "/bin/false" ; then
	if test "$ac_cv_aveclient" != "yes" ; then
	    echo "AVP5     'aveclient' NO (Disabled by configure command)"
	else
	    echo "AVP5     'aveclient' NO (not found)"
	fi
    else
	echo "AVP5     'aveclient' YES - $AVP5"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$KAVSCANNER" = "/bin/false" ; then
	if test "$ac_cv_kavscanner" != "yes" ; then
	    echo "KAVSCANNER 'kavscanner' NO (Disabled by configure command)"
	else
	    echo "KAVSCANNER 'kavscanner' NO (not found)"
	fi
    else
	echo "KAVSCANNER 'kavscanner' YES - $KAVSCANNER"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$CSAV" = "/bin/false" ; then
	if test "$ac_cv_csav" != "yes" ; then
	    echo "CSAV     'csav'      NO (Disabled by configure command)"
	else
	    echo "CSAV     'csav'      NO (not found)"
	fi
    else
	echo "CSAV     'csav'      YES - $CSAV"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$FSAV" = "/bin/false" ; then
	if test "$ac_cv_fsav" != "yes" ; then
	    echo "FSAV     'fsav'      NO (Disabled by configure command)"
	else
	    echo "FSAV     'fsav'      NO (not found)"
	fi
    else
	echo "FSAV     'fsav'      YES - $FSAV"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$FPROT" = "/bin/false" ; then
	if test "$ac_cv_fprot" != "yes" ; then
	    echo "FPROT    'f-prot'    NO (Disabled by configure command)"
	else
	    echo "FPROT    'f-prot'    NO (not found)"
	fi
    else
	echo "FPROT    'f-prot'    YES - $FPROT"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$FPSCAN" = "/bin/false" ; then
	if test "$ac_cv_fpscan" != "yes" ; then
	    echo "FPSCAN   'fpscan'    NO (Disabled by configure command)"
	else
	    echo "FPSCAN   'fpscan'    NO (not found)"
	fi
    else
	echo "FPSCAN   'fpscan'    YES - $FPSCAN"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$SOPHIE" = "/bin/false" ; then
	if test "$ac_cv_sophie" != "yes" ; then
	    echo "SOPHIE   'sophie'    NO (Disabled by configure command)"
	else
	    echo "SOPHIE   'sophie'    NO (not found)"
	fi
    else
	echo "SOPHIE   'sophie'    YES - $SOPHIE"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$NVCC" = "/bin/false" ; then
	if test "$ac_cv_nvcc" != "yes" ; then
	    echo "NVCC     'nvcc'      NO (Disabled by configure command)"
	else
	    echo "NVCC     'nvcc'      NO (not found)"
	fi
    else
	echo "NVCC     'nvcc'      YES - $NVCC"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$CLAMD" = "/bin/false" ; then
	if test "$ac_cv_clamd" != "yes" ; then
	    echo "CLAMD    'clamd'     NO (Disabled by configure command)"
	else
	    echo "CLAMD    'clamd'     NO (not found)"
	fi
    else
	echo "CLAMD    'clamd'     YES - $CLAMD"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$TROPHIE" = "/bin/false" ; then
	if test "$ac_cv_trophie" != "yes" ; then
	    echo "TROPHIE  'trophie'   NO (Disabled by configure command)"
	else
	    echo "TROPHIE  'trophie'   NO (not found)"
	fi
    else
	echo "TROPHIE  'trophie'   YES - $TROPHIE"
	GOT_VIRUS_SCANNER=1
    fi

    if test "$NOD32" = "/bin/false" ; then
	if test "$ac_cv_nod32" != "yes" ; then
	    echo "NOD32    'nod32cli'  NO (Disabled by configure command)"
	else
	    echo "NOD32    'nod32cli'  NO (not found)"
	fi
    else
	echo "NOD32    'nod32cli'  YES - $NOD32"
	GOT_VIRUS_SCANNER=1
    fi
fi

if test "$GOT_VIRUS_SCANNER" = "0" ; then
    echo ""
    echo "Could not find any recognized virus scanner... do not use"
    echo "any of the contains_virus functions in your filter."
fi

if test "$CLAMD" != "/bin/false" -o "$SOPHIE" != "/bin/false" -o "$TROPHIE" != "/bin/false" ; then
   echo ""
   if test "$CLAMD" != "/bin/false" ; then
        echo "Make sure clamd runs as the $DEFANGUSER user!"
   fi
   if test "$SOPHIE" != "/bin/false" ; then
        echo "See README.SOPHIE for more information about running Sophie."
   fi
   if test "$TROPHIE" != "/bin/false" ; then
        echo "Make sure Trophie runs as the $DEFANGUSER user!"
   fi
   echo ""
fi

if test "$ac_cv_perlmodcheck" = "yes" ; then
    if test "$HAVE_SPAM_ASSASSIN" = "yes" ; then
	echo "Found Mail::SpamAssassin.  You may use spam_assassin_* functions"
    else
	echo "Did not find Mail::SpamAssassin.  Do not use spam_assassin_* functions"
    fi
    echo ""

    if test "$HAVE_HTML_PARSER" = "yes" ; then
	echo "Found HTML::Parser.  You may use append_html_boilerplate()"
    else
	echo "Did not find HTML::Parser.  Do not use append_html_boilerplate()"
    fi
fi

if test "$HAVE_IO_SOCKET_SSL" = "no" ; then
   echo ""
   echo "Could not find IO::Socket::SSL Perl module... do not use"
   echo "md_check_against_smtp_server function in your filter."
   echo ""
fi

if test "$HAVE_LWP" = "no" ; then
   if test "$HAVE_JSON" = "no" ; then
     echo ""
     echo "Could not find LWP::UserAgent and JSON Perl modules..."
     echo "it's not possible to check your emails with rspamd(8) "
     echo "using rspamd_check function in your filter."
     echo ""
   fi
fi

if test "$HAVE_DKIM" = "no" ; then
   echo ""
   echo "Could not find Mail::DKIM Perl module... do not use"
   echo "md_dkim_sign function in your filter."
   echo ""
fi


echo "Note: SpamAssassin and HTML::Parser are"
echo "detected at run-time, so if you install or remove any of those modules, you"
echo "do not need to re-run ./configure and make a new mimedefang.pl."

if test "$ac_cv_perlmodcheck" = "yes" ; then
    if test "$mtversion" = "unknown" ; then
	echo ""
	echo "Could not determine version of MIME::Tools.  Please use 5.412 or later." 1>&6
    elif test $mtversion -lt 54120 ; then
	echo "" 1>&6
	echo "**** WARNING:  We strongly recommend that you use MIME::Tools" 1>&6
	echo "**** version 5.412 or later instead of version $mt_actual_version." 1>&6
    fi
fi

if test "$DEFANGUSER" != "" ; then
   id $DEFANGUSER > /dev/null 2>&1
   if test "$?" != 0 ; then
      echo ""
      echo "Note:  The MIMEDefang user '$DEFANGUSER' does not seem to"
      echo "exist.  Please create this user before continuing."
   fi
fi

if test "$ENABLE_DEBUGGING" != "" ; then
   echo ""
   echo "*** WARNING: You have configured with --enable-debugging."
   echo "*** This will produce LARGE VOLUMES of syslog messages and"
   echo "*** is NOT RECOMMENDED for a production system."
fi
