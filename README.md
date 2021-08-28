# MIMEDefang

1. INTRODUCTION
---------------

MIMEDefang is an e-mail filter program which works with Sendmail 8.12
and later or Postfix.  MIMEDefang filters all e-mail messages sent via SMTP.
MIMEDefang splits multi-part MIME messages into their components and
potentially deletes or modifies the various parts.  It then
reassembles the parts back into an e-mail message and sends it on its
way.

MIMEDefang is written (mostly) in Perl, and the filter actions are
expressed in Perl.  This makes MIMEDefang highly flexible and
configurable.  As a simple example, you can delete all *.exe and *.com
files, convert all Word documents to HTML, and allow other attachments
through.

MIMEDefang uses the "milter" feature of Sendmail to "listen in" to
SMTP connections.  It runs a scan once for each message, not once for
each recipient (as simpler procmail-based systems do.)  Therefore, it
is more CPU-friendly than procmail-based systems.  In addition,
because MIMEDefang can participate in the SMTP connection, you can
bounce messages (something impossible to do with procmail-based
systems.)

2. WARNINGS
-----------

There are some caveats you should be aware of before using MIMEDefang.
MIMEDefang potentially alters e-mail messages.  This breaks a "gentleman's
agreement" that mail transfer agents do not modify message bodies.  This
could cause problems, for example, with encrypted or signed messages.

Deleting attachments could cause a loss of information.  Recipients must
be aware of this possibility, and must be willing to explain to senders
exactly why they cannot mail certain types of files.  You must have the
willingness of your e-mail users to commit to security, or they will
complain loudly about MIMEDefang.

3. PREREQUISITES
----------------

MIMEDefang has the following software requirements:

1) A UNIX-like operating system (MIMEDefang is developed and tested on Linux)
2) Perl 5.8.0 or higher
3) Required Perl modules:

	MIME::tools 5.413 or higher
	MIME::Base64 3.03 or higher
	MailTools 1.1401  or higher
	Digest::SHA1 2.00 or higher

	These modules are available from http://www.cpan.org

4) Optional Perl modules:

	Mail::SpamAssassin (http://www.spamassassin.org/) - spam detector
	HTML::Parser (CPAN) - Needed for append_html_boilerplate function
	Crypt::OpenSSL::Random - Needed to generate a truly random ipheader file
	Test::Class, Test::Most and tzdata files - Needed to run regression tests

4) Sendmail 8.12.x, 8.13.x or Postfix.  Get the latest version.

5. INSTALLATION
---------------

There's an excellent MIMEDefang-HOWTO contributed by Mickey Hill
at http://www.rudolphtire.com/mimedefang-howto/.  It explains
everything in this README in much greater detail.  Anyway, on with it:

1) Sendmail

You must be using Sendmail 8.12.x or 8.13.x
-------------------------------------------

Obtain the latest Sendmail 8.12.x or 8.13.x source release from
http://www.sendmail.org.  Unpack it.  If you are building 8.12.x,
add the following lines to devtools/Site/site.config.m4:

        dnl Milter
	APPENDDEF(`conf_sendmail_ENVDEF', `-DMILTER')

This enables the mail filter feature.  (For 8.13.x, Milter is enabled
by default.)

Go ahead and build Sendmail following the instructions in the Sendmail
documentation.  Install and configure Sendmail.

You *MUST* run a client-queue runner, because MIMEDefang now uses deferred
mode to deliver internally-generated messages.  We recommend running this
command as part of the Sendmail startup:

	sendmail -Ac -q5m

Compile and Install Sendmail:
-----------------------------

Next, you need to make the Sendmail headers and libraries visible for
compiling and linking MIMEDefang.  The most reliable way to do this
is to run these commands from the main Sendmail directory:

	mkdir -p /usr/local/include/sendmail
	cp -R include/* /usr/local/include/sendmail
	cp -R sendmail/*.h /usr/local/include/sendmail
	mkdir -p /usr/local/lib
	cp obj.Linux.2.2.14-5.0.i686/*/*.a /usr/local/lib

NOTE: On the last "cp" command, replace "obj.Linux.2.2.14-5.0.i686" with
the appropriate "obj.*" directory created by the Sendmail build script.

2) Obtain and install the necessary Perl modules.  These generally build and
install as follows:

	perl Makefile.PL
	make install

If you are using any of the optional Perl modules, install them before
starting to build MIMEDefang.

3) Optionally, obtain and install the "wv" library.  Install the wvHtml
program in your favourite bin directory (/usr/bin or /usr/local/bin).

4) Configure, build and install the MIMEDefang software:

	./configure
	make
	make install

NOTE: Unlike most autoconf scripts, the default --sysconfdir for this
version of ./configure is "/etc".  You can change it to /usr/local/etc
as follows:

	./configure --sysconfdir=/usr/local/etc

Also, the actual configuration files go in the subdirectory "mail" under
--sysconfdir.  You can put them elsewhere (eg, /usr/local/etc/mimedefang)
like this:

	./configure --sysconfdir=/usr/local/etc --with-confsubdir=mimedefang

If you want them right in /usr/local/etc, you'd say:

	./configure --sysconfdir=/usr/local/etc --with-confsubdir=

By default, MIMEDefang processes incoming messages in the directory
/var/spool/MIMEDefang.  You can change this by typing:

	./configure --with-spooldir=DIRNAME

By default, MIMEDefang quarantines mail in the directory
/var/spool/MD-Quarantine.  You can change this by typing:

	./configure --with-quarantinedir=DIR2

You should create the spool and quarantine directories with mode 700,
owned by the user you run MIMEDefang as.

Summary of useful ./configure options:

  --with-sendmail=PATH    specify location of Sendmail binary
  --with-user=LOGIN       use LOGIN as the MIMEDefang user
  --with-milterinc=PATH   specify alternative location of milter includes
  --with-milterlib=PATH   specify alternative location of milter libraries

  --with-ipheader         install /etc/mail/mimedefang-ip-key
  --with-confsubdir=DIR   specify configuration subdirectory
                          (mail)
  --with-spooldir=DIR     specify location of spool directory
                          (/var/spool/MIMEDefang)
  --with-quarantinedir=DIR
                          specify location of quarantine directory
                          (/var/spool/MD-Quarantine)

  --enable-poll           Use poll(2) instead of select(2) in multiplexor

  --disable-check-perl-modules
                          Disable compile-time checks for Perl modules
  --disable-embedded-perl Disable embedded Perl interpreter

  --enable-debugging      Add debugging messages to syslog

  --disable-anti-virus    Do not search for ANY anti-virus programs

  --disable-antivir       Do not include support for H+BEDV antivir
  --disable-vexira        Do not include support for Central Command Vexira
  --disable-uvscan        Do not include support for NAI uvscan
  --disable-sweep         Do not include support for Sophos sweep
  --disable-trend         Do not include support for Trend Filescanner/Interscan
  --disable-AvpLinux      Do not include support for AVP AvpLinux
  --disable-clamav        Do not include support for clamav
  --disable-csav          Do not include support for Command Anti-Virus
  --disable-fsav          Do not include support for F-Secure Anti-Virus
  --disable-fprot         Do not include support for F-prot Anti-Virus
  --disable-fpscan        Do not include support for F-prot Anti-Virus v6
  --disable-sophie        Do not include support for Sophie
  --disable-nvcc          Do not include support for Nvcc

5) Add the following line to your Sendmail "m4" configuration file.  (You
DO use the m4 configuration method, right?)

INPUT_MAIL_FILTER(`mimedefang', `S=unix:/var/spool/MIMEDefang/mimedefang.sock, F=T, T=S:360s;R:360s;E:15m')

(If you keep your spool directory elsewhere, use its location instead of
/var/spool/MIMEDefang/mimedefang.sock)

The "T=..." equate increases the default timeouts for milter, which are
way too small.

6) Ensure that mimedefang starts when Sendmail does.  In whatever shell script
starts sendmail at boot time, add the lines:

	rm -f /var/spool/MIMEDefang/mimedefang.sock
	/usr/local/bin/mimedefang -p /var/spool/MIMEDefang/mimedefang.sock &

before the line which actually starts Sendmail.  When you shut down Sendmail,
remember to kill the mimedefang processes.  A sample /etc/rc.d/init.d script
for Red Hat Linux is in the redhat directory.  A sample generic init script
which should work on most UNIXes is in the examples directory.

CONFIGURATION
-------------

To configure your filter, you have to edit the file
`/etc/mail/mimedefang-filter'.  This is a Perl source file, so you have
to know Perl.  Go ahead and read the man pages mimedefang(8),
mimedefang.pl(8) and mimedefang-filter(5).  There are some sample
filters in the examples directory.

THE MULTIPLEXOR
---------------

On a busy mail server, it is too expensive to start a new Perl process
for each incoming e-mail.  MIMEDefang includes a multiplexor which
manages a pool of long-lived Perl processes and reuses them for
successive e-mails.  Read the mimedefang-multiplexor(8) man page for
details.  A sample start/stop script is shown in examples/init-script;
this script is generic and should work on most flavours of UNIX.
