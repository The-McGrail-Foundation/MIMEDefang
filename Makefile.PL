#!/usr/bin/env perl
# =============================================================================
# Makefile.PL  -  MIMEDefang
#
# Supported options:
#
#   SENDMAIL=/path/to/sendmail        Path to sendmail binary      [auto-detect]
#   DEFANGUSER=login                  MIMEDefang run-as user       [defang]
#   MILTERINC=/path/to/milter/inc     Milter header directory      [auto-detect]
#   MILTERLIB=/path/to/milter/lib     Milter library directory     [auto-detect]
#   SPOOLDIR=/var/spool/MIMEDefang    Spool directory
#   QUARANTINEDIR=/var/spool/MD-Quarantine
#   CONFSUBDIR=mail                   Subdirectory under sysconfdir
#   SYSCONFDIR=/etc                   System configuration root
#   ENABLE_EMBEDDED_PERL=1|0          Build embedded Perl interpreter  [1]
#   ENABLE_POLL=0|1                   Use poll(2) instead of select(2) [0]
#   ENABLE_DEBUGGING=0|1              Enable syslog debug messages     [0]
#   ENABLE_ANTI_VIRUS=1|0             Probe for AV scanners            [1]
#   ENABLE_CHECK_PERL_MODULES=1|0     Verify Perl deps at build time   [1]
#   ENABLE_PTHREAD_FLAG=0|1           Pass -pthread to the C compiler  [0]
#   IPHEADER=0|1                      Install IP-header config file    [0]
# =============================================================================

use strict;
use warnings;
use 5.008009;

use Config;
use ExtUtils::MakeMaker;
use File::Spec;
use File::Basename qw(dirname);
use POSIX          qw(uname);

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
my $VERSION = '3.6';

# ---------------------------------------------------------------------------
# AV scanner table  (name => Makefile variable)
# ---------------------------------------------------------------------------
my @AV_SCANNERS = (
    [ clamscan   => 'CLAMSCAN'   ],
    [ clamdscan  => 'CLAMDSCAN'  ],
    [ uvscan     => 'UVSCAN'     ],
    [ sweep      => 'SWEEP'      ],
    [ trend      => 'TREND'      ],
    [ AvpLinux   => 'AVPLINUX'   ],
    [ antivir    => 'ANTIVIR'    ],
    [ fsav       => 'FSAV'       ],
    [ 'f-prot'   => 'FPROT'      ],
    [ fpscan     => 'FPSCAN'     ],
    [ sophie     => 'SOPHIE'     ],
    [ nvcc       => 'NVCC'       ],
    [ savscan    => 'SAVSCAN'    ],
);

# ---------------------------------------------------------------------------
# Required Perl modules  (module => minimum version, '' = any version)
# ---------------------------------------------------------------------------
my %REQUIRED_MODULES = (
    'MIME::Tools'    => '5.412',
    'MIME::Words'    => 0,
    'MIME::Parser'   => 0,
    'MIME::Entity'   => 0,
    'Digest::SHA'    => 0,
    'IO::Socket'     => 0,
    'IO::File'       => 0,
    'File::Spec'     => 0,
    'Sys::Hostname'  => 0,
    'Time::Local'    => 0,
    'Carp'           => 0,
    'Socket'         => 0,
    'Errno'          => 0,
);

# Optional (one of these must be present for syslog support)
my @SYSLOG_MODULES = qw(Unix::Syslog Sys::Syslog);

# ---------------------------------------------------------------------------
# Grab command-line knobs (OPTION=value pairs after "perl Makefile.PL")
# ---------------------------------------------------------------------------
sub arg {
    my ($name, $default) = @_;
    # ExtUtils::MakeMaker parses KEY=VALUE from @ARGV before WriteMakefile
    return $ENV{"MIMEDEFANG_$name"} // $default;
}

# Parse KEY=VALUE pairs from @ARGV ourselves for keys we care about,
# leaving unknown ones for EUMM to handle (INSTALL_BASE, PREFIX, etc.).
my %ARGS;
my @remaining_argv;
for my $a (@ARGV) {
    if ($a =~ /^([A-Z_]+)=(.*)$/) {
        $ARGS{$1} = $2;
    } else {
        push @remaining_argv, $a;
    }
}
@ARGV = @remaining_argv;

sub opt {
    my ($name, $default) = @_;
    return exists $ARGS{$name} ? $ARGS{$name} : $default;
}

# ---------------------------------------------------------------------------
# Resolve all configuration values
# ---------------------------------------------------------------------------

print "\n=== MIMEDefang $VERSION  -  perl Makefile.PL ===\n\n";

# --- Perl interpreter -------------------------------------------------------
my $PERL = $Config{perlpath};
print "Perl interpreter     : $PERL\n";

# --- Perl install-path variables --------------------------------------------
my %perl_vars;
for my $v (qw(
    prefix siteprefix vendorprefix
    vendorlib installarchlib installprivlib
    installbin installman1dir installman3dir installscript
    installsitearch installsitelib
)) {
    $perl_vars{$v} = $Config{$v} // '';
}

my $MANDIR = do {
    my $man1 = $perl_vars{installman1dir} || '/usr/share/man/man1';
    (my $base = $man1) =~ s{/man\d+$}{};
    $base || '/usr/share/man';
};

my $MIMEDEFANG_PL = opt('MIMEDEFANG_PL',  $Config{prefix} . "/bin/mimedefang.pl");
# --- User-supplied paths ---------------------------------------------------
my $DEFANGUSER    = opt('DEFANGUSER',    'defang');
my $SPOOLDIR      = opt('SPOOLDIR',      '/var/spool/MIMEDefang');
my $QUARANTINEDIR = opt('QUARANTINEDIR', '/var/spool/MD-Quarantine');
my $CONFSUBDIR    = opt('CONFSUBDIR',    'mail');
my $SYSCONFDIR    = opt('SYSCONFDIR',    '/etc');
my $CONFDIR       = $CONFSUBDIR ne ''
                    ? File::Spec->catdir($SYSCONFDIR, $CONFSUBDIR)
                    : $SYSCONFDIR;
my $IPHEADER      = opt('IPHEADER', 0) ? 'yes' : 'no';

printf "Run-as user          : %s\n",  $DEFANGUSER;
printf "Spool directory      : %s\n",  $SPOOLDIR;
printf "Quarantine directory : %s\n",  $QUARANTINEDIR;
printf "Config directory     : %s\n",  $CONFDIR;
printf "Filter file          : %s\n",  $MIMEDEFANG_PL;

# --- Sendmail binary -------------------------------------------------------
my $SENDMAILPROG = do {
    my $given = opt('SENDMAIL', '');
    if ($given && -x $given) {
        $given;
    } else {
        my $found;
        for my $p (qw(
            /usr/sbin/sendmail
            /usr/lib/sendmail
            /usr/local/sbin/sendmail
        )) {
            if (-x $p) { $found = $p; last }
        }
        $found // '/usr/sbin/sendmail';
    }
};
print "Sendmail binary      : $SENDMAILPROG\n";

# --- Milter includes and library -------------------------------------------
my $MILTERINC = do {
    my @candidates = grep { $_ ne '' } (
        opt('MILTERINC', ''),
        '/usr/include/libmilter',
        '/usr/local/include/libmilter',
        '/usr/include/sendmail',
        '/usr/local/include/sendmail',
    );
    my $found;
    for my $d (@candidates) {
        if (-f File::Spec->catfile($d, 'libmilter', 'mfapi.h') ||
            -f File::Spec->catfile($d, 'mfapi.h')) {
            $found = $d; last;
        }
    }
    $found or die <<END;
ERROR: Cannot find milter header (libmilter/mfapi.h).
       Install sendmail-devel / libmilter-dev, or pass MILTERINC=/path
END
};

my $MILTERLIB = do {
    my @candidates = grep { $_ ne '' } (
        opt('MILTERLIB', ''),
        '/usr/lib',   '/usr/lib64',
        '/usr/local/lib', '/usr/local/lib64',
    );
    my $found;
    for my $d (@candidates) {
        if (-f File::Spec->catfile($d, 'libmilter.a')  ||
            -f File::Spec->catfile($d, 'libmilter.so') ||
            glob(File::Spec->catfile($d, 'libmilter.so.*'))) {
            $found = $d; last;
        }
    }
    $found or die <<END;
ERROR: Cannot find libmilter.
       Install sendmail-devel / libmilter-dev, or pass MILTERLIB=/path
END
};

print "Milter include dir   : $MILTERINC\n";
print "Milter library dir   : $MILTERLIB\n";

# --- Feature flags ---------------------------------------------------------
my $ENABLE_EMBEDDED_PERL     = opt('ENABLE_EMBEDDED_PERL',     1);
my $ENABLE_POLL              = opt('ENABLE_POLL',              0);
my $ENABLE_DEBUGGING         = opt('ENABLE_DEBUGGING',         0);
my $ENABLE_ANTI_VIRUS        = opt('ENABLE_ANTI_VIRUS',        1);
my $ENABLE_CHECK_PERL_MODULES= opt('ENABLE_CHECK_PERL_MODULES',1);
my $ENABLE_PTHREAD_FLAG      = opt('ENABLE_PTHREAD_FLAG',      0);

# --- Required Perl module check --------------------------------------------
if ($ENABLE_CHECK_PERL_MODULES) {
    print "\nChecking required Perl modules:\n";
    my $all_ok = 1;
    for my $mod (sort keys %REQUIRED_MODULES) {
        my $minver = $REQUIRED_MODULES{$mod};
        my $ok;
        eval "use $mod" . ($minver ? " $minver" : '') . '; $ok = 1';
        printf "  %-35s %s\n", $mod, $ok ? 'ok' : 'MISSING';
        $all_ok = 0 unless $ok;
    }
    die "\nERROR: One or more required Perl modules are missing.\n"
      . "       Install them from CPAN, then re-run perl Makefile.PL\n"
      unless $all_ok;

    # Syslog: need at least one
    print "\nChecking syslog Perl module (need one of):\n";
    my $have_syslog = 0;
    for my $mod (@SYSLOG_MODULES) {
        my $ok;
        eval "use $mod; \$ok = 1";
        printf "  %-35s %s\n", $mod, $ok ? 'found' : 'not found';
        $have_syslog = 1 if $ok;
    }
    warn "\nWARNING: Neither Unix::Syslog nor Sys::Syslog is installed.\n"
       . "         MIMEDefang will not be able to log to syslog.\n"
       unless $have_syslog;
}

# MIME::Tools version advisory
{
    my $mt_ver = eval { require MIME::Tools; $MIME::Tools::VERSION } // 'unknown';
    print "\nMIME::Tools version  : $mt_ver\n";
    if ($mt_ver ne 'unknown') {
        (my $numeric = $mt_ver) =~ s/\.//g;
        $numeric = sprintf('%05d', $numeric + 0);
        warn "WARNING: MIME::Tools >= 5.412 is strongly recommended (found $mt_ver)\n"
            if $numeric < 54120;
    }
}

# --- DEFANGUSER existence check -------------------------------------------
{
    my $uid = getpwnam($DEFANGUSER);
    unless (defined $uid) {
        print "\nNote: The MIMEDefang user '$DEFANGUSER' does not seem to exist.\n";
        print "      Please create this user before running 'make install'.\n";
    }
}

# --- AV scanner detection --------------------------------------------------
my %AV_PATHS;
print "\nAV scanner detection:\n";
if (!$ENABLE_ANTI_VIRUS) {
    print "  (disabled by ENABLE_ANTI_VIRUS=0)\n";
    for my $pair (@AV_SCANNERS) {
        $AV_PATHS{ $pair->[1] } = '/bin/false';
    }
} else {
    for my $pair (@AV_SCANNERS) {
        my ($prog, $key) = @$pair;
        my $path = find_in_path($prog);
        $AV_PATHS{$key} = $path // '/bin/false';
        printf "  %-20s %s\n", $prog, ($path ? $path : 'not found');
    }
}

# --- C compiler (needed by probes below) -----------------------------------
my $CC = $Config{cc} // 'cc';
my $INSTALL_PROGRAM = $Config{install_program} // 'install';
my $INSTALL_DATA = $Config{install_data} // 'install';

# --- clock_gettime(CLOCK_MONOTONIC) probe ----------------------------------
my $HAVE_CLOCK_MONOTONIC = probe_clock_monotonic();
print "\nclock_gettime(CLOCK_MONOTONIC): " . ($HAVE_CLOCK_MONOTONIC ? 'yes' : 'no') . "\n";

# --- inet_ntop probe --------------------------------------------------------
my $HAVE_INET_NTOP = probe_inet_ntop();
print "inet_ntop             : " . ($HAVE_INET_NTOP ? 'yes' : 'no') . "\n";

# --- socklen probe --------------------------------------------------------
my $HAVE_SOCKLEN_T = probe_socklen();
print "socklen_t             : " . ($HAVE_SOCKLEN_T ? 'yes' : 'no') . "\n";

# --- Embedded Perl C/LD flags ----------------------------------------------
my ($EMBPERL_CFLAGS, $EMBPERL_LDFLAGS) = ('', '');
if ($ENABLE_EMBEDDED_PERL) {
    chomp($EMBPERL_CFLAGS  = `$PERL -MExtUtils::Embed -e ccopts  2>/dev/null`);
    chomp($EMBPERL_LDFLAGS = `$PERL -MExtUtils::Embed -e ldopts  2>/dev/null`);
    print "Embedded Perl        : enabled\n";
} else {
    print "Embedded Perl        : disabled\n";
}

# Base CFLAGS: use the compiler's defaults plus mandatory defines
my $CFLAGS = join(' ',
    '-I.',
    "-I$MILTERINC",
    "-std=c89 -D_BSD_SOURCE -D_DEFAULT_SOURCE",
    ($ENABLE_DEBUGGING         ? '-DENABLE_DEBUGGING'    : ()),
    ($ENABLE_POLL              ? '-DUSE_POLL'             : ()),
    ($ENABLE_PTHREAD_FLAG      ? '-pthread'               : ()),
    ($HAVE_CLOCK_MONOTONIC     ? '-DHAVE_CLOCK_MONOTONIC' : ()),
    ($ENABLE_EMBEDDED_PERL     ? ('-DWITH_EMBEDDED_PERL', $EMBPERL_CFLAGS) : ()),
);

my $LDFLAGS_MILTER  = "-L$MILTERLIB -lmilter";
my $LDFLAGS_PTHREAD = $ENABLE_PTHREAD_FLAG ? '-lpthread' : '';
my $LDFLAGS_EMBPERL = $ENABLE_EMBEDDED_PERL ? $EMBPERL_LDFLAGS : '';
my $LDFLAGS_COMMON  = join(' ', '-lresolv',
                            $LDFLAGS_PTHREAD, $LDFLAGS_EMBPERL);

my $HAVE_MILTER = probe_milter($CC, $CFLAGS);
print "\nmilter.h: " . ($HAVE_MILTER ? 'found' : 'not found') . "\n";

print "\nCC                   : $CC\n";
print "CFLAGS (extra)       : $CFLAGS\n\n";

# --- Write config.h --------------------------------------------------------
write_config_h(
    DEFANGUSER        => $DEFANGUSER,
    SPOOLDIR          => $SPOOLDIR,
    QUARANTINEDIR     => $QUARANTINEDIR,
    CONFDIR           => $CONFDIR,
    SENDMAILPROG      => $SENDMAILPROG,
    VERSION           => $VERSION,
    MIMEDEFANG_PL     => $MIMEDEFANG_PL,
    HAVE_CLOCK_MONOTONIC => $HAVE_CLOCK_MONOTONIC,
    HAVE_INET_NTOP    => $HAVE_INET_NTOP,
    HAVE_SOCKLEN_T    => $HAVE_SOCKLEN_T,
    HAVE_MILTER       => $HAVE_MILTER,
    ENABLE_DEBUGGING  => $ENABLE_DEBUGGING,
    ENABLE_POLL       => $ENABLE_POLL,
    WITH_EMBEDDED_PERL=> $ENABLE_EMBEDDED_PERL,
);

# ---------------------------------------------------------------------------
# Substitution map for .in template files
# ---------------------------------------------------------------------------
my %SUBST = (
    PERL             => $PERL,
    VERSION          => $VERSION,
    PACKAGE          => 'mimedefang',
    DEFANGUSER       => $DEFANGUSER,
    SPOOLDIR         => $SPOOLDIR,
    QUARANTINEDIR    => $QUARANTINEDIR,
    CONFSUBDIR       => $CONFSUBDIR,
    SYSCONFDIR       => $SYSCONFDIR,
    CONFDIR          => $CONFDIR,
    IPHEADER         => $IPHEADER,
    SENDMAILPROG     => $SENDMAILPROG,
    MILTERINC        => $MILTERINC,
    MILTERLIB        => $MILTERLIB,
    CC               => $CC,
    CFLAGS           => $CFLAGS,
    INSTALL_PROGRAM  => $INSTALL_PROGRAM,
    INSTALL_DATA     => $INSTALL_DATA,
    (map { (uc("PERLINSTALL$_") => $perl_vars{$_}) } keys %perl_vars),
    %AV_PATHS,
);

# ---------------------------------------------------------------------------
# WriteMakefile
# ---------------------------------------------------------------------------

# Collect every .in source file so make knows about them
my @IN_FILES        = map { chomp; $_ } `find . -name '*.in' -not -path './.git/*' 2>/dev/null`;
my @GENERATED_FILES = map { (my $f = $_) =~ s/\.in$//; $f } @IN_FILES;

# Perl modules live under modules/lib/
my @PM_FILES = map { chomp; $_ } `find modules/lib -name '*.pm' 2>/dev/null`;
my %PM = map {
    my $dest = $_;
    $dest =~ s{^modules/lib/}{};   # strip the local lib/ prefix
    my $install_path = File::Spec->catfile('$(INST_LIB)', $dest);
    ($_ => $install_path)
} @PM_FILES;

WriteMakefile(
    NAME             => 'Mail::MIMEDefang',
    INSTALLDIRS      => 'vendor',
    DISTNAME         => "mimedefang",
    VERSION          => $VERSION,
    MIN_PERL_VERSION => '5.008009',
    AUTHOR           => 'The McGrail Foundation <https://mimedefang.org>',
    ABSTRACT         => 'E-mail filtering with Sendmail Milter',
    
    META_MERGE => {
        'meta-spec' => { version => 2 },
        license     => [ 'GPL-2.0-only' ],
    },

    # Perl module sources
    PM               => \%PM,
    PM_FILTER        => '',

    # man-page sections
    MAN3PODS         => {},

    PREREQ_PM        => \%REQUIRED_MODULES,

    macro            => {
        MD_CC              => $CC,
        MD_INSTALL_PROGRAM => $INSTALL_PROGRAM,
        MD_INSTALL_DATA    => $INSTALL_DATA,
        MD_CFLAGS          => $CFLAGS,
        MD_LDFLAGS_MILTER  => $LDFLAGS_MILTER,
        MD_LDFLAGS_EMBPERL => $LDFLAGS_EMBPERL,
        MD_LDFLAGS_PTHREAD => $LDFLAGS_PTHREAD,
        MD_LDFLAGS_COMMON  => $LDFLAGS_COMMON,
        MD_SPOOLDIR        => $SPOOLDIR,
        MD_QUARANTINEDIR   => $QUARANTINEDIR,
        MD_CONFDIR         => $CONFDIR,
        MD_DEFANGUSER      => $DEFANGUSER,
        MD_SYSCONFDIR      => $SYSCONFDIR,
        MD_CONFSUBDIR      => $CONFSUBDIR,
        MD_IPHEADER        => $IPHEADER,
        MD_SENDMAILPROG    => $SENDMAILPROG,
        MD_VERSION         => $VERSION,
        MD_MANDIR          => $MANDIR,
        (map { ("MD_$_" => $AV_PATHS{$_}) } keys %AV_PATHS),
    },

    clean  => { FILES => join(' ',
        'config.h',
        @GENERATED_FILES,
        'mimedefang mimedefang-multiplexor md-mx-ctrl',
        '*.o',
    )},

    postamble => {
      'custom' =>  <<"MAKE",
'MD_INSTALL_PROGRAM' = $INSTALL_PROGRAM
'MD_INSTALL_DATA' = $INSTALL_DATA
MAKE
    }
);

# ---------------------------------------------------------------------------
# MY package overrides
# ---------------------------------------------------------------------------

{
    package MY;

    # Pure-Perl: suppress all XS/dynamic-loading rules.
    sub dlsyms      { '' }
    sub dynamic_bs  { '' }
    sub dynamic_lib { '' }
    sub dynamic     { "dynamic ::\n\t\$(NOECHO) \$(NOOP)\n" }

    sub c_o {
        return <<'MAKE';
.c.o:
	$(MD_CC) $(MD_CFLAGS) -c -o $@ $<
MAKE
    }

    # postamble: add rules for C binaries, .in processing, and extra install
    sub postamble {
        my $self = shift;

        # ----------------------------------------------------------------
        # List every .in file as a dependency of "all" so "make" processes
        # them automatically.
        # ----------------------------------------------------------------
        my $generated = join(' ', @GENERATED_FILES);

        # ----------------------------------------------------------------
        # Per-target object lists and link flags
        # ----------------------------------------------------------------
        my $md_objs = join(' ', qw(
            mimedefang.o
            drop_privs.o
            dynbuf.o
            gen_id.o
            milter_cap.o
            rm_r.o
            syslog-fac.o
            utils.o
        ));
        my $md_ldflags = '$(MD_LDFLAGS_MILTER) $(MD_LDFLAGS_COMMON)';

        # mimedefang-multiplexor
        my $mux_objs = join(' ', qw(
            mimedefang-multiplexor.o
            drop_privs.o
            dynbuf.o
            embperl.o
            event.o
            event_tcp.o
            gen_id.o
            notifier.o
            rm_r.o
            syslog-fac.o
            utils.o
        ));
        my $mux_ldflags = '$(MD_LDFLAGS_COMMON)';

        # md-mx-ctrl
        my $ctrl_objs = join(' ', qw(
            md-mx-ctrl.o
            utils.o
        ));
        my $ctrl_ldflags = '$(MD_LDFLAGS_COMMON)';

        for my $mdfile ( 'mimedefang.pl.in', 'mimedefang-release.pl.in', 'script/mimedefang-util.in' ) {
            open my $in, '<', $mdfile;
            local $/;
            my $content = <$in>;
            close $in;
            $content =~ s/\@PERL\@/$PERL/g;
            $content =~ s/\@PERLINSTALLSITELIB\@/$perl_vars{installsitelib}/g;
            $content =~ s/\@SENDMAILPROG\@/$SENDMAILPROG/g;
            $content =~ s/\@QDIR\@/$QUARANTINEDIR/g;

            my $outf = $mdfile;
            $outf =~ s/\.in$//;
            open my $out, '>', $outf;
            print $out $content;
            close $out;
        }

        # ----------------------------------------------------------------
        # Extra install targets (spool dirs, config, man pages, scripts)
        # ----------------------------------------------------------------
        return <<MAKE;

# ============================================================
# Generated files from .in templates
# ============================================================
all :: $generated c_binaries

# Pattern rule: substitute \@TOKEN\@ in each .in file
%: %.in
\t\$(PERL) -e 'BEGIN { %m = \$(SUBST_ARGS) }' \\
\t    -pe 's{\@([A-Z0-9_]+)\@}{ \$\$m{"\$\$1"} // \$\$& }ge' \$< > \$\@
\tchmod --reference=\$< \$\@ 2>/dev/null || true

# ============================================================
# Substitution helper: build the %m hash for the pattern rule
# ============================================================
SUBST_ARGS = \\
    PERL            => q(\$(FULLPERL)),             \\
    VERSION         => q(\$(MD_VERSION)),            \\
    PACKAGE         => q(mimedefang),               \\
    DEFANGUSER      => q(\$(MD_DEFANGUSER)),         \\
    SPOOLDIR        => q(\$(MD_SPOOLDIR)),           \\
    QUARANTINEDIR   => q(\$(MD_QUARANTINEDIR)),      \\
    CONFDIR         => q(\$(MD_CONFDIR)),            \\
    CONFDIR_EVAL    => q(\$(MD_CONFDIR)),            \\
    SYSCONFDIR      => q(\$(MD_SYSCONFDIR)),         \\
    CONFSUBDIR      => q(\$(MD_CONFSUBDIR)),         \\
    SENDMAILPROG    => q(\$(MD_SENDMAILPROG)),       \\
    CLAMSCAN        => q(\$(MD_CLAMSCAN)),           \\
    CLAMDSCAN       => q(\$(MD_CLAMDSCAN)),          \\
    UVSCAN          => q(\$(MD_UVSCAN)),             \\
    SWEEP           => q(\$(MD_SWEEP)),              \\
    TREND           => q(\$(MD_TREND)),              \\
    AVPLINUX        => q(\$(MD_AVPLINUX)),           \\
    ANTIVIR         => q(\$(MD_ANTIVIR)),            \\
    FSAV            => q(\$(MD_FSAV)),               \\
    FPROT           => q(\$(MD_FPROT)),              \\
    FPSCAN          => q(\$(MD_FPSCAN)),             \\
    SOPHIE          => q(\$(MD_SOPHIE)),             \\
    NVCC            => q(\$(MD_NVCC)),               \\
    SAVSCAN         => q(\$(MD_SAVSCAN))

# ============================================================
# C binaries
# ============================================================
c_binaries: mimedefang mimedefang-multiplexor md-mx-ctrl

mimedefang: $md_objs
\t\$(MD_CC) -o \$\@ $md_objs $md_ldflags

mimedefang-multiplexor: $mux_objs
\t\$(MD_CC) -o \$\@ $mux_objs $mux_ldflags

md-mx-ctrl: $ctrl_objs
\t\$(MD_CC) -o \$\@ $ctrl_objs $ctrl_ldflags

# ============================================================
# Extra install targets (run after the standard EUMM install)
# ============================================================
install :: install_bins install_scripts install_man install_conf install_spool
\t\@echo ""
\t\@echo "=== MIMEDefang \$(MD_VERSION) installation complete ==="
\t\@echo ""
\t\@echo "Next steps:"
\t\@echo "  1. Edit \$(MD_CONFDIR)/mimedefang-filter"
\t\@echo "  2. Add the SOCKETMAP entry to sendmail.mc"
\t\@echo "  3. Start mimedefang-multiplexor, then mimedefang"
\t\@echo ""

install_bins:
\t\$(MKPATH) \$(DESTDIR)\$(INSTALLBIN)
\tfor b in mimedefang mimedefang-multiplexor md-mx-ctrl; do \\
\t    \$(MD_INSTALL_PROGRAM) \$\$b \$(DESTDIR)\$(INSTALLBIN)/\$\$b; \\
\tdone

install_scripts:
\t\$(MKPATH) \$(DESTDIR)\$(INSTALLSCRIPT)
\tfor s in mimedefang.pl mimedefang-release.pl watch-mimedefang; do \\
\t    test -f \$\$s && \$(MD_INSTALL_PROGRAM) \$\$s \$(DESTDIR)\$(INSTALLSCRIPT)/\$\$s || true; \\
\tdone
\ttest -f script/mimedefang-util && \\
\t    \$(MD_INSTALL_PROGRAM) script/mimedefang-util \$(DESTDIR)\$(INSTALLSCRIPT)/mimedefang-util || true

install_man:
\t\$(MKPATH) \$(DESTDIR)\$(MD_MANDIR)/man5 \$(DESTDIR)\$(MD_MANDIR)/man7 \$(DESTDIR)\$(MD_MANDIR)/man8
\tfor m in mimedefang-filter.5; do \\
\t    test -f \$\$m && \$(MD_INSTALL_DATA) \$\$m \$(DESTDIR)\$(MD_MANDIR)/man5/\$\$m || true; \\
\tdone
\tfor m in mimedefang-protocol.7 mimedefang-notify.7; do \\
\t    test -f \$\$m && \$(MD_INSTALL_DATA) \$\$m \$(DESTDIR)\$(MD_MANDIR)/man7/\$\$m || true; \\
\tdone
\tfor m in mimedefang.8 mimedefang.pl.8 mimedefang-multiplexor.8 md-mx-ctrl.8; do \\
\t    test -f \$\$m && \$(MD_INSTALL_DATA) \$\$m \$(DESTDIR)\$(MD_MANDIR)/man8/\$\$m || true; \\
\tdone

install_conf:
\t\$(MKPATH) \$(DESTDIR)\$(MD_CONFDIR)
\tif test -f \$(DESTDIR)\$(MD_CONFDIR)/mimedefang-filter; then \\
\t    \$(MD_INSTALL_DATA) examples/suggested-minimum-filter-for-windows-clients \\
\t        \$(DESTDIR)\$(MD_CONFDIR)/mimedefang-filter.example; \\
\telse \\
\t    \$(MD_INSTALL_DATA) examples/suggested-minimum-filter-for-windows-clients \\
\t        \$(DESTDIR)\$(MD_CONFDIR)/mimedefang-filter; \\
\tfi
\tif test -f \$(DESTDIR)\$(MD_CONFDIR)/sa-mimedefang.cf; then \\
\t    \$(MD_INSTALL_DATA) SpamAssassin/spamassassin.cf \\
\t        \$(DESTDIR)\$(MD_CONFDIR)/sa-mimedefang.cf.example; \\
\telse \\
\t    \$(MD_INSTALL_DATA) SpamAssassin/spamassassin.cf \\
\t        \$(DESTDIR)\$(MD_CONFDIR)/sa-mimedefang.cf; \\
\tfi
\tif test "\$(MD_IPHEADER)" = "yes"; then \\
\t    test -f mimedefang-ip-key.sample && \\
\t        \$(MD_INSTALL_DATA) mimedefang-ip-key.sample \\
\t            \$(DESTDIR)\$(MD_CONFDIR)/mimedefang-ip-key || true; \\
\tfi

install_spool:
\t\$(MKPATH) \$(DESTDIR)\$(MD_SPOOLDIR) \$(DESTDIR)\$(MD_QUARANTINEDIR)
\tchown \$(MD_DEFANGUSER) \$(DESTDIR)\$(MD_SPOOLDIR) 2>/dev/null || true
\tchown \$(MD_DEFANGUSER) \$(DESTDIR)\$(MD_QUARANTINEDIR) 2>/dev/null || true
\tchmod 0700 \$(DESTDIR)\$(MD_SPOOLDIR)
\tchmod 0700 \$(DESTDIR)\$(MD_QUARANTINEDIR)

install-redhat: install
\t\$(MKPATH) \$(DESTDIR)\$(MD_SYSCONFDIR)/rc.d/init.d
\t\$(MKPATH) \$(DESTDIR)\$(MD_SYSCONFDIR)/sysconfig
\t\$(MKPATH) \$(DESTDIR)\$(MD_SYSCONFDIR)/logrotate.d
\t\$(MD_INSTALL_PROGRAM) redhat/mimedefang-init \\
\t    \$(DESTDIR)\$(MD_SYSCONFDIR)/rc.d/init.d/mimedefang
\t\$(MD_INSTALL_DATA) redhat/mimedefang-sysconfig \\
\t    \$(DESTDIR)\$(MD_SYSCONFDIR)/sysconfig/mimedefang
\t\$(MD_INSTALL_DATA) examples/redhat-logrotate-file \\
\t    \$(DESTDIR)\$(MD_SYSCONFDIR)/logrotate.d/mimedefang
\t\$(MD_INSTALL_DATA) SpamAssassin/spamassassin.cf \\
\t    \$(DESTDIR)\$(MD_CONFDIR)/sa-mimedefang.cf
\t\$(MD_INSTALL_DATA) SpamAssassin/spamassassin.cf \\
\t    \$(DESTDIR)\$(MD_CONFDIR)/sa-mimedefang.cf.example
\t\$(MD_INSTALL_DATA) examples/suggested-minimum-filter-for-windows-clients \\
\t    \$(DESTDIR)\$(MD_CONFDIR)/mimedefang-filter

MAKE
    }
}

# ===========================================================================
# Helper subroutines (run at "perl Makefile.PL" time)
# ===========================================================================

sub find_in_path {
    my ($prog) = @_;
    my @dirs = split /:/, ($ENV{PATH} // '/usr/bin:/usr/local/bin:/usr/sbin:/usr/local/sbin');
    for my $d (@dirs) {
        my $p = File::Spec->catfile($d, $prog);
        return $p if -x $p;
    }
    return undef;
}

# Probe for clock_gettime(CLOCK_MONOTONIC) by compiling a tiny C snippet.
sub probe_clock_monotonic {
    my $tmpdir = File::Spec->tmpdir();
    my $src    = File::Spec->catfile($tmpdir, "conftest_$$.c");
    my $exe    = File::Spec->catfile($tmpdir, "conftest_$$");

    open my $fh, '>', $src or return 0;
    print $fh <<'C';
#include <time.h>
int main(void) {
    struct timespec s;
    clock_gettime(CLOCK_MONOTONIC, &s);
    return 0;
}
C
    close $fh;
    my $rc = system("$CC -o $exe $src -lrt 2>/dev/null") == 0
          || system("$CC -o $exe $src        2>/dev/null") == 0;
    unlink $src, $exe;
    return $rc ? 1 : 0;
}

sub probe_inet_ntop {
    my $tmpdir = File::Spec->tmpdir();
    my $src    = File::Spec->catfile($tmpdir, "conftest_inet_$$.c");
    my $exe    = File::Spec->catfile($tmpdir, "conftest_inet_$$");
    open my $fh, '>', $src or return 0;
    print $fh <<'C';
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
int main(void) {
    char buf[64];
    struct in_addr a;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return 0;
}
C
    close $fh;
    my $rc = system("$CC -o $exe $src 2>/dev/null") == 0;
    unlink $src, $exe;
    return $rc ? 1 : 0;
}

sub probe_milter {
    my ($cc, $cflags) = @_;
    my $ok = 0;
    open my $fh, '>', 'tst.c' or die $!;
    print $fh <<'C';
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>
#include <libmilter/mfapi.h>
int main() {
    return 0;
}
C
    close $fh;
    $ok = (system("$cc $cflags tst.c -o tst 2>/dev/null") == 0);
    unlink 'tst.c', 'tst';
    unless ($ok) {
        die "Missing required system development files for sendmail"
          . " (e.g. package sendmail-dev). Please install the OS package and retry.\n";
    }
    return $ok;
}

sub probe_socklen {    
    my $tmpdir = File::Spec->tmpdir();
    my $src    = File::Spec->catfile($tmpdir, "conftest_inet_$$.c");
    my $exe    = File::Spec->catfile($tmpdir, "conftest_inet_$$");
    open my $fh, '>', 'tst.c' or die $!;
    print $fh <<'C';
#include <sys/types.h>
#include <sys/socket.h>

int
main (void)
{
socklen_t x;
  ;
  return 0;
}
C
    close $fh;
    my $rc = system("$CC -o $exe $src 2>/dev/null") == 0;
    unlink $src, $exe;
    return $rc ? 1 : 0;
}

# Write config.h from the collected values.
sub write_config_h {
    my %v = @_;
    open my $fh, '>', 'config.h' or die "Cannot write config.h: $!\n";
    print $fh "/* config.h - generated by perl Makefile.PL - do not edit */\n\n";
    print $fh '#define VERSION           "' . $v{VERSION}      . "\"\n";
    print $fh '#define DEFANG_USER       "' . $v{DEFANGUSER}   . "\"\n";
    print $fh '#define SPOOLDIR          "' . $v{SPOOLDIR}     . "\"\n";
    print $fh '#define QUARANTINEDIR     "' . $v{QUARANTINEDIR}. "\"\n";
    print $fh '#define CONFDIR           "' . $v{CONFDIR}      . "\"\n";
    print $fh '#define SENDMAIL_PROG     "' . $v{SENDMAILPROG} . "\"\n";
    print $fh "#ifndef HAVE_CLOCK_MONOTONIC\n#define HAVE_CLOCK_MONOTONIC\n#endif\n" if $v{HAVE_CLOCK_MONOTONIC};
    print $fh '#define MIMEDEFANG_PL     "' . $v{MIMEDEFANG_PL} . "\"\n";
    print $fh "#define HAVE_INET_NTOP\n"       if $v{HAVE_INET_NTOP};
    print $fh "#define HAVE_SOCKLEN_T\n"       if not $v{HAVE_SOCKLEN_T};
    print $fh "#define HAVE_MILTER\n"           if $v{HAVE_MILTER};
    print $fh "#define ENABLE_DEBUGGING\n"     if $v{ENABLE_DEBUGGING};
    print $fh "#define USE_POLL\n"              if $v{ENABLE_POLL};
    print $fh "#ifndef WITH_EMBEDDED_PERL\n#define WITH_EMBEDDED_PERL\n#endif\n" if $v{WITH_EMBEDDED_PERL};
    print $fh "#define STDC_HEADERS 1\n";
    close $fh;
    print "config.h written.\n";
}
