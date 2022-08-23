##########################################################################
# Copyright @2002, Roaring Penguin Software Inc.  All rights reserved.
#
# * This program may be distributed under the terms of the GNU General
# * Public License, Version 2.
#
# Project     : MIMEDefang
# Component   : redhat/mimedefang.spec
# Author      : Michael McLagan <Michael.McLagan@linux.org>
# Creation    : 30-Apr-2002 12:25
# Description : This is the spec file for building the RedHat RPM 
#               distribution SRC and i386 files
#    
# Current Revision:
#
# $Source$
# $Revision$
# $Author$
# $Date$
#
# Revision History:
# 
# $Log$
# Revision 1.30  2004/09/19 19:55:28  dfs
# Add sa-mimedefang.cf to example.
#
# Revision 1.29  2004/09/01 21:22:52  dfs
# Fixed bug.
#
# Revision 1.28  2004/08/09 22:28:06  dfs
# Fixed spec so as not to disable service on upgrade.
#
# Revision 1.27  2004/07/15 17:13:43  dfs
# Move sa-mimedefang.cf into /etc/mail instead of /etc/mail/spamassassin
#
# Revision 1.26  2004/02/24 14:41:08  dfs
# Loosened spool permissions to make it world-readable.
# Improved spec file to allow detection of AV software at build time.
#
# Revision 1.25  2003/06/04 14:12:24  dfs
# Took out noarch.
#
# Revision 1.24  2003/06/04 14:03:33  dfs
# Copy pid files into /var/run to keep Red Hat killproc() happy.
#
# Revision 1.23  2003/06/04 13:39:33  dfs
# Split out contrib into a separate package.
#
# Revision 1.22  2002/10/25 14:01:51  dfs
# Build RPM with --disable-anti-virus
#
# Revision 1.21  2002/09/25 11:28:13  dfs
# Fixed spec.
#
# Revision 1.20  2002/08/26 03:48:40  dfs
# Install logrotate file
#
# Revision 1.19  2002/08/26 03:15:40  dfs
# Take ip key out!
#
# Revision 1.18  2002/08/26 03:13:52  dfs
# Better RPM file.
#
# Revision 1.17  2002/08/26 03:10:00  dfs
# Better RPM packaging.
#
# Revision 1.16  2002/06/21 14:50:27  dfs
# Fixed spec file.
#
# Revision 1.15  2002/06/11 12:33:14  dfs
# Fixed typo.
#
# Revision 1.14  2002/06/03 14:26:14  dfs
# Fixups for sysconfdir.
#
# Revision 1.13  2002/05/29 18:12:15  dfs
# Put pid files and sockets in /var/spool/MIMEDefang instead of /var/run
#
# Revision 1.12  2002/05/23 19:08:00  dfs
# Fixed spec file to make log directory.
#
# Revision 1.11  2002/05/15 13:39:02  dfs
# Added README.NONROOT
#
# Revision 1.10  2002/05/14 16:19:14  dfs
# Patch from Michael McLagan
#
# Revision 1.9  2002/05/13 20:32:03  dfs
# More spec fixes.
#
# Revision 1.8  2002/05/13 20:20:07  dfs
# Fixed spec file.
#
# Revision 1.7  2002/05/10 13:46:43  dfs
# Backward compatibility with Michael McLagan's RPM setup.
#
# Revision 1.6  2002/05/10 11:30:24  dfs
# Updated spec.
#
# Revision 1.5  2002/05/09 20:30:42  dfs
# Changed spool dir paths back.
#
# Revision 1.4  2002/05/09 20:26:47  dfs
# Fixed typo
#
# Revision 1.3  2002/05/09 20:24:31  dfs
# Fixed bug in spec.
#
# Revision 1.2  2002/05/09 20:22:09  dfs
# Revert spec to our style.
#
# Revision 1.1  2002/05/09 20:18:05  dfs
# Merge Michael McLagan's patch.
#
# Revision 1.7  2002/05/08 16:56:58  dfs
# Added /etc/mail/spamassassin to spec.
#
# Revision 1.6  2002/05/06 15:23:31  dfs
# Update for 2.10.
#
# Revision 1.5  2002/05/03 14:24:24  dfs
# Merge packaging patches.
# Fixed typo.
# Made default value for -n 10.
#
##########################################################################

%define dir_spool      /var/spool/MIMEDefang
%define dir_quarantine /var/spool/MD-Quarantine
%define dir_log        /var/log/mimedefang
%define user           defang
%define with_antivirus 0

%global debug_package %{nil}

%{?_with_antivirus: %{expand: %%define with_antivirus 1}}
%{?_without_antivirus: %{expand: %%define with_antivirus 0}}

Summary:       Email filtering application using sendmail's milter interface
Name:          mimedefang
Version:       3.1
Release:       0
License:       GPL
Group:         Networking/Mail
Source0:       https://mimedefang.org/static/%{name}-%{version}%{?prerelease}.tar.gz
Source1:       https://mimedefang.org/static/%{name}-%{version}%{?prerelease}.tar.gz.asc
Url:           https://mimedefang.org
Vendor:        MIMEDefang
Buildroot:     %{_tmppath}/%{name}-root
Requires:      perl-Digest-SHA1 perl-MIME-tools perl-MailTools perl-Unix-Syslog
BuildRequires: sendmail-milter-devel >= 8.12.0
BuildRequires: autoconf > 2.55

%description
MIMEDefang is an e-mail filter program which works with Sendmail 8.11
and later.  MIMEDefang filters all e-mail messages sent via SMTP.
MIMEDefang splits multi-part MIME messages into their components and
potentially deletes or modifies the various parts.  It then
reassembles the parts back into an e-mail message and sends it on its
way.

There are some caveats you should be aware of before using MIMEDefang.
MIMEDefang potentially alters e-mail messages.  This breaks a "gentleman's
agreement" that mail transfer agents do not modify message bodies.  This
could cause problems, for example, with encrypted or signed messages.

Deleting attachments could cause a loss of information.  Recipients must
be aware of this possibility, and must be willing to explain to senders
exactly why they cannot mail certain types of files.  You must have the
willingness of your e-mail users to commit to security, or they will
complain loudly about MIMEDefang.

%prep
%setup -q -n %{name}-%{version}%{?prerelease}
autoconf
%configure --prefix=%{_prefix} \
            --mandir=%{_mandir} \
	    --with-milterlib=%{_libdir} \
	    --sysconfdir=/etc   \
	    --disable-check-perl-modules \
            --with-spooldir=%{dir_spool} \
            --with-quarantinedir=%{dir_quarantine} \
%if %{with_antivirus}
	    --with-user=%{user}
%else
	    --with-user=%{user} \
	    --disable-anti-virus
%endif

%build
make DONT_STRIP=1

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{dir_log}
make DESTDIR=$RPM_BUILD_ROOT \
     INSTALL='install -p' INSTALL_STRIP_FLAG='' install-redhat
# Turn off execute bit on scripts in contrib
find contrib -type f -print0 | xargs -0 chmod a-x

%clean
HERE=`pwd`
cd ..
rm -rf $HERE
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc Changelog README* examples SpamAssassin
%dir %{dir_spool}
%dir %{dir_log}
%dir %{dir_quarantine}
%{_bindir}/*
%{perl_vendorlib}/*
%{_mandir}/*
%config(noreplace) /etc/mail/mimedefang-filter
%config(noreplace) /etc/mail/sa-mimedefang.cf
%config(noreplace) /etc/mail/sa-mimedefang.cf.example
%config(noreplace) /etc/sysconfig/%{name}
/etc/rc.d/init.d/%{name}
/etc/logrotate.d/%{name}

%pre
# Backward-compatibility
if test -d /var/spool/mimedefang -a ! -d /var/spool/MIMEDefang ; then
	mv /var/spool/mimedefang /var/spool/MIMEDefang || true
fi

if test -d /var/spool/quarantine -a ! -d /var/spool/MD-Quarantine ; then
	mv /var/spool/quarantine /var/spool/MD-Quarantine || true
fi

# Add user
useradd -M -r -d %{dir_spool} -s /bin/false -c "MIMEDefang User" %{user} > /dev/null 2>&1 || true

%post
# Tighten permissions
chown %{user} %{dir_spool}
chgrp %{user} %{dir_spool}
chmod 750 %{dir_spool}
chown %{user} %{dir_quarantine}
chgrp %{user} %{dir_quarantine}
chmod 750 %{dir_quarantine}
chown %{user} %{dir_log}
chgrp %{user} %{dir_log}
chmod 755 %{dir_log}

cat << EOF

In order to complete the installation of mimedefang, you will need to add the 
following line to your sendmail mc file:

   INPUT_MAIL_FILTER(\`mimedefang', \`S=unix:/var/spool/MIMEDefang/mimedefang.sock, F=T, T=S:1m;R:1m;E:5m')

Use the sendmail-cf package to rebuild your /etc/mail/sendmail.cf file and 
restart your sendmail daemon.

EOF
%if 0%{?rhel} > 6 || 0%{?fedora} > 23
%systemd_preun %{name}.service
%else
/sbin/chkconfig --add mimedefang
%endif

%preun
%if 0%{?rhel} > 6 || 0%{?fedora} > 23
%systemd_preun %{name}.service
%else
if [ $1 -eq 0 ]; then
  /sbin/service %{name} stop > /dev/null 2>&1 || :
  /sbin/chkconfig --del %{name}
fi
%endif

%package contrib
Summary:	Contributed software that works with MIMEDefang
Version:	3.1
Release:	0
Group:          Networking/Mail

%description contrib
This package contains contributed software that works with MIMEDefang,
such as the graphdefang graphing package and a sample filter.

%files contrib
%defattr(-,root,root)
%doc contrib

%changelog
* Wed May 29 2002 Dianne Skoll <dfs@roaringpenguin.com>
- Put pid files and sockets in /var/spool/MIMEDefang so we can
  drop privileges early.
* Wed May 15 2002 Dianne Skoll <dfs@roaringpenguin.com>
- Change log directory to /var/log/mimedefang/ to more easily accommodate
  -U flag.
* Tue May 14 2002 Michael McLagan <Michael.McLagan@linux.org>
- Fixed preinstall script
* Thu May 09 2002 Dianne Skoll <dfs@roaringpenguin.com>
- Install SpamAssassin config file
- Changed spool dir to /var/spool/MIMEDefang and quarantine dir
  to /var/spool/MD-Quarantine
* Thu May 09 2002 Michael McLagan <Michael.McLagan@linux.org>
- Modified to build beta releases
* Fri May 03 2002 Michael McLagan <Michael.McLagan@linux.org>
- Updated to 2.9
* Tue Apr 30 2002 Michael McLagan <Michael.McLagan@linux.org>
  Initial version 2.8
