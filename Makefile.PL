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
# AV scanner table  (binary => template token)
# Keys must match the @TOKEN@ names used in mimedefang.pl.in
# ---------------------------------------------------------------------------
my @AV_SCANNERS = (
    [ clamscan   => 'CLAMSCAN'   ],
    [ clamdscan  => 'CLAMDSCAN'  ],
    [ clamd      => 'CLAMD'      ],
    [ uvscan     => 'NAI'        ],  # NAI/McAfee uvscan
    [ sweep      => 'SOPHOS'     ],  # Sophos sweep
    [ trend      => 'TREND'      ],
    [ AvpLinux   => 'AVP'        ],  # Kaspersky AvpLinux
    [ aveclient  => 'AVP5'       ],  # Kaspersky AVP5
    [ kavscanner => 'KAVSCANNER' ],
    [ antivir    => 'HBEDV'      ],  # H+BEDV / Avira antivir
    [ vascan     => 'VEXIRA'     ],  # Vexira vascan
    [ bdc        => 'BDC'        ],  # BitDefender
    [ fsav       => 'FSAV'       ],
    [ 'f-prot'   => 'FPROT'      ],
    [ fpscan     => 'FPSCAN'     ],
    [ sophie     => 'SOPHIE'     ],
    [ nvcc       => 'NVCC'       ],
    [ savscan    => 'SAVSCAN'    ],
    [ trophie    => 'TROPHIE'    ],
    [ csav       => 'CSAV'       ],
    [ nod32cli   => 'NOD32'      ],
    [ rspamc     => 'RSPAMC'     ],
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

my $BINDIR_DEFAULT = ($Config{siteprefix} || '/usr/local') . '/bin';
my $MIMEDEFANG_PL = opt('MIMEDEFANG_PL', "$BINDIR_DEFAULT/mimedefang.pl");
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

# --- libresolv probe -------------------------------------------------------
my $HAVE_LIBRESOLV = probe_libresolv();
print "libresolv             : " . ($HAVE_LIBRESOLV ? 'yes' : 'no (using libc)') . "\n";

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
    ($ENABLE_EMBEDDED_PERL     ? ('-DEMBED_PERL', $EMBPERL_CFLAGS) : ()),
);

my $LDFLAGS_MILTER  = "-L$MILTERLIB -lmilter";
my $LDFLAGS_PTHREAD = $ENABLE_PTHREAD_FLAG ? '-lpthread' : '';
my $LDFLAGS_EMBPERL = $ENABLE_EMBEDDED_PERL ? $EMBPERL_LDFLAGS : '';
my $LDFLAGS_COMMON  = join(' ', ($HAVE_LIBRESOLV ? '-lresolv' : ()),
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

# Collect .in source files, excluding autoconf templates that are not processed here
my @IN_FILES = grep { $_ !~ m{\b(Makefile|config\.h)\.in$} }
               map  { chomp; $_ }
               `find . -name '*.in' -not -path './.git/*' 2>/dev/null`;
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
    INSTALLDIRS      => 'site',
    DISTNAME         => "mimedefang",
    VERSION          => $VERSION,
    MIN_PERL_VERSION => '5.008009',
    AUTHOR           => 'The McGrail Foundation <https://mimedefang.org>',
    ABSTRACT         => 'E-mail filtering with Sendmail Milter',

    META_MERGE => {
        'meta-spec' => { version => 2 },
        license     => [ 'GPL-2.0-only' ],
        resources => {
            repository => {
                type => 'git',
                url  => 'https://github.com/The-McGrail-Foundation/MIMEDefang.git',
                web  => 'https://mimedefang.org',
            },
            bugtracker => {
                web => 'https://github.com/The-McGrail-Foundation/MIMEDefang/issues'
            },
         },

    },

    # Perl module sources
    PM               => \%PM,
    PM_FILTER        => '',

    # man-page sections
    MAN1PODS              => {},
    MAN3PODS              => {},
    INSTALLVENDORMAN1DIR  => $MANDIR . '/man1',
    INSTALLVENDORMAN3DIR  => $MANDIR . '/man3',

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
        sysconfdir         => $CONFDIR,
        MD_CONFDIR         => '$(sysconfdir)',
        MD_DEFANGUSER      => $DEFANGUSER,
        MD_SYSCONFDIR      => $SYSCONFDIR,
        MD_CONFSUBDIR      => $CONFSUBDIR,
        MD_IPHEADER        => $IPHEADER,
        MD_SENDMAILPROG    => $SENDMAILPROG,
        MD_VERSION         => $VERSION,
        MD_MANDIR          => $MANDIR,
        BINDIR             => $BINDIR_DEFAULT,
        SBINDIR            => ($Config{siteprefix} || '/usr/local') . '/sbin',
        MANDIR             => ($Config{siteprefix} || '/usr/local') . '/man',
        LIBDIR             => ($Config{siteprefix} || '/usr/local') . '/lib',
        PERL_SITELIB       => $Config{installsitelib} || ($Config{siteprefix} || '/usr/local') . '/lib/perl5',
        (map { ("MD_$_" => $AV_PATHS{$_}) } keys %AV_PATHS),
    },

    clean    => { FILES => join(' ',
        'config.h',
        @GENERATED_FILES,
        'mimedefang mimedefang-multiplexor md-mx-ctrl',
        '*.o',
        'xs_init.c',
        'mimedefang-release.8',
        'script/mimedefang-util.1',
        'modules/man',
    )},
    realclean => { FILES => 'mimedefang-*.tar.gz mimedefang-*.tar.gz.sig' },

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
        my @mux_obj_list = qw(
            mimedefang-multiplexor.o
            drop_privs.o
            dynbuf.o
            event.o
            event_tcp.o
            gen_id.o
            notifier.o
            rm_r.o
            syslog-fac.o
            utils.o
        );
        push @mux_obj_list, 'embperl.o', 'xs_init.o' if $ENABLE_EMBEDDED_PERL;
        my $mux_objs = join(' ', @mux_obj_list);
        my $mux_ldflags = '$(MD_LDFLAGS_COMMON)';

        # md-mx-ctrl
        my $ctrl_objs = join(' ', qw(
            md-mx-ctrl.o
            utils.o
        ));
        my $ctrl_ldflags = '$(MD_LDFLAGS_COMMON)';

        # Substitute @TOKEN@ placeholders in all .in templates at perl Makefile.PL time.
        # This avoids relying on make pattern rules, which differ between GNU make and BSD make.
        my %subst = (
            PERL               => $PERL,
            PERLINSTALLSITELIB => $perl_vars{installsitelib},
            VERSION            => $VERSION,
            PACKAGE            => 'mimedefang',
            DEFANGUSER         => $DEFANGUSER,
            SPOOLDIR           => $SPOOLDIR,
            QUARANTINEDIR      => $QUARANTINEDIR,
            QDIR               => $QUARANTINEDIR,
            CONFDIR            => $CONFDIR,
            CONFDIR_EVAL       => $CONFDIR,
            SYSCONFDIR         => $SYSCONFDIR,
            CONFSUBDIR         => $CONFSUBDIR,
            IPHEADER           => $IPHEADER,
            SENDMAILPROG       => $SENDMAILPROG,
            MILTERINC          => $MILTERINC,
            MILTERLIB          => $MILTERLIB,
            CC                 => $CC,
            MIMEDEFANG_PL      => $MIMEDEFANG_PL,
            %AV_PATHS,
        );
        for my $mdfile (@IN_FILES) {
            open my $in, '<', $mdfile or do { warn "Cannot open $mdfile: $!\n"; next };
            local $/;
            my $content = <$in>;
            close $in;
            $content =~ s{\@([A-Z0-9_]+)\@}{ exists $subst{$1} ? $subst{$1} : '/bin/false' }ge;
            (my $outf = $mdfile) =~ s/\.in$//;
            open my $out, '>', $outf or do { warn "Cannot write $outf: $!\n"; next };
            print $out $content;
            close $out;
            my $mode = (stat $mdfile)[2] & 0777;
            chmod $mode, $outf;
        }

        # Generate xs_init.c for embedded Perl support
        if ($ENABLE_EMBEDDED_PERL) {
            print "Generating xs_init.c for embedded Perl...\n";
            system($PERL, '-MExtUtils::Embed', '-e', 'xsinit', '--', '-o', 'xs_init.c') == 0
                or warn "WARNING: Failed to generate xs_init.c\n";
        }

        # ----------------------------------------------------------------
        # Extra install targets (spool dirs, config, man pages, scripts)
        # ----------------------------------------------------------------
        return <<MAKE;

# ============================================================
# Generated files from .in templates (created by perl Makefile.PL)
# ============================================================
all :: $generated c_binaries pod2man

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
# pod2man: generate man pages from POD in scripts and modules
# ============================================================
pod2man: mimedefang-release.8 script/mimedefang-util.1 md_module_manpages

mimedefang-release.8: mimedefang-release.pl
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=8 --perm_rw=644 \\
\t\t--center="mimedefang-release Documentation" \\
\t\t--name="mimedefang-release" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmimedefang-release.pl mimedefang-release.8

script/mimedefang-util.1: script/mimedefang-util
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=1 --perm_rw=644 \\
\t\t--center="MIMEDefang Documentation" \\
\t\t--release=\$(MD_VERSION) \\
\t\tscript/mimedefang-util script/mimedefang-util.1

md_module_manpages:
\t\$(MKPATH) modules/man
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang Documentation" \\
\t\t--name="Mail::MIMEDefang" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang.pm "modules/man/Mail::MIMEDefang.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::Actions Documentation" \\
\t\t--name="Mail::MIMEDefang::Actions" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/Actions.pm "modules/man/Mail::MIMEDefang::Actions.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::Antispam Documentation" \\
\t\t--name="Mail::MIMEDefang::Antispam" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/Antispam.pm "modules/man/Mail::MIMEDefang::Antispam.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::Antivirus Documentation" \\
\t\t--name="Mail::MIMEDefang::Antivirus" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/Antivirus.pm "modules/man/Mail::MIMEDefang::Antivirus.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::Authres Documentation" \\
\t\t--name="Mail::MIMEDefang::Authres" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/Authres.pm "modules/man/Mail::MIMEDefang::Authres.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::DKIM Documentation" \\
\t\t--name="Mail::MIMEDefang::DKIM" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/DKIM.pm "modules/man/Mail::MIMEDefang::DKIM.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::DKIM::ARC Documentation" \\
\t\t--name="Mail::MIMEDefang::DKIM::ARC" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/DKIM/ARC.pm "modules/man/Mail::MIMEDefang::DKIM::ARC.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::Mail Documentation" \\
\t\t--name="Mail::MIMEDefang::Mail" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/Mail.pm "modules/man/Mail::MIMEDefang::Mail.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::MIME Documentation" \\
\t\t--name="Mail::MIMEDefang::MIME" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/MIME.pm "modules/man/Mail::MIMEDefang::MIME.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::Net Documentation" \\
\t\t--name="Mail::MIMEDefang::Net" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/Net.pm "modules/man/Mail::MIMEDefang::Net.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::RFC2822 Documentation" \\
\t\t--name="Mail::MIMEDefang::RFC2822" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/RFC2822.pm "modules/man/Mail::MIMEDefang::RFC2822.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::SPF Documentation" \\
\t\t--name="Mail::MIMEDefang::SPF" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/SPF.pm "modules/man/Mail::MIMEDefang::SPF.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::Unit Documentation" \\
\t\t--name="Mail::MIMEDefang::Unit" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/Unit.pm "modules/man/Mail::MIMEDefang::Unit.3"
\t\$(FULLPERL) "-MExtUtils::Command::MM" -e pod2man "--" --section=3 --perm_rw=644 \\
\t\t--center="Mail::MIMEDefang::Utils Documentation" \\
\t\t--name="Mail::MIMEDefang::Utils" \\
\t\t--release=\$(MD_VERSION) \\
\t\tmodules/lib/Mail/MIMEDefang/Utils.pm "modules/man/Mail::MIMEDefang::Utils.3"

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
\t\$(MKPATH) \$(DESTDIR)\$(SBINDIR)
\tfor b in mimedefang mimedefang-multiplexor md-mx-ctrl; do \\
\t    \$(MD_INSTALL_PROGRAM) \$\$b \$(DESTDIR)\$(BINDIR)/\$\$b; \\
\tdone

install_scripts:
\t\$(MKPATH) \$(DESTDIR)\$(BINDIR)
\tfor s in mimedefang.pl watch-mimedefang; do \\
\t    test -f \$\$s && \$(MD_INSTALL_PROGRAM) \$\$s \$(DESTDIR)\$(BINDIR)/\$\$s || true; \\
\tdone
\ttest -f mimedefang-release.pl && \\
\t    \$(MD_INSTALL_PROGRAM) mimedefang-release.pl \$(DESTDIR)\$(BINDIR)/mimedefang-release || true
\ttest -f watch-multiple-mimedefangs.tcl && \\
\t    \$(MD_INSTALL_PROGRAM) watch-multiple-mimedefangs.tcl \$(DESTDIR)\$(BINDIR)/watch-multiple-mimedefangs.tcl || true
\ttest -f script/mimedefang-util && \\
\t    \$(MD_INSTALL_PROGRAM) script/mimedefang-util \$(DESTDIR)\$(BINDIR)/mimedefang-util || true

install_man:
\t\$(MKPATH) \$(DESTDIR)\$(MANDIR)/man1 \$(DESTDIR)\$(MANDIR)/man3 \$(DESTDIR)\$(MANDIR)/man5 \$(DESTDIR)\$(MANDIR)/man7 \$(DESTDIR)\$(MANDIR)/man8
\ttest -f script/mimedefang-util.1 && \\
\t    \$(MD_INSTALL_DATA) script/mimedefang-util.1 \$(DESTDIR)\$(MANDIR)/man1/mimedefang-util.1 || true
\tfor m in \\
\t    Mail::MIMEDefang.3 \\
\t    Mail::MIMEDefang::Actions.3 \\
\t    Mail::MIMEDefang::Antispam.3 \\
\t    Mail::MIMEDefang::Antivirus.3 \\
\t    Mail::MIMEDefang::Authres.3 \\
\t    Mail::MIMEDefang::DKIM.3 \\
\t    Mail::MIMEDefang::DKIM::ARC.3 \\
\t    Mail::MIMEDefang::Mail.3 \\
\t    Mail::MIMEDefang::MIME.3 \\
\t    Mail::MIMEDefang::Net.3 \\
\t    Mail::MIMEDefang::RFC2822.3 \\
\t    Mail::MIMEDefang::SPF.3 \\
\t    Mail::MIMEDefang::Unit.3 \\
\t    Mail::MIMEDefang::Utils.3; do \\
\t    test -f "modules/man/\$\$m" && \$(MD_INSTALL_DATA) "modules/man/\$\$m" \$(DESTDIR)\$(MANDIR)/man3/\$\$m || true; \\
\tdone
\tfor m in mimedefang-filter.5; do \\
\t    test -f \$\$m && \$(MD_INSTALL_DATA) \$\$m \$(DESTDIR)\$(MANDIR)/man5/\$\$m || true; \\
\tdone
\tfor m in mimedefang-protocol.7 mimedefang-notify.7; do \\
\t    test -f \$\$m && \$(MD_INSTALL_DATA) \$\$m \$(DESTDIR)\$(MANDIR)/man7/\$\$m || true; \\
\tdone
\tfor m in mimedefang.8 mimedefang.pl.8 mimedefang-multiplexor.8 md-mx-ctrl.8 \\
\t         mimedefang-release.8 watch-mimedefang.8 watch-multiple-mimedefangs.8; do \\
\t    test -f \$\$m && \$(MD_INSTALL_DATA) \$\$m \$(DESTDIR)\$(MANDIR)/man8/\$\$m || true; \\
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
\tif test "\$(MD_IPHEADER)" = "yes" && test ! -f "\$(DESTDIR)\$(MD_CONFDIR)/mimedefang-ip-key"; then \\
\t    \$(FULLPERL) ./gen-ip-validator.pl > "\$(DESTDIR)\$(MD_CONFDIR)/mimedefang-ip-key"; \\
\t    chmod 600 "\$(DESTDIR)\$(MD_CONFDIR)/mimedefang-ip-key" 2>/dev/null || true; \\
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

sub probe_libresolv {
    my $tmpdir = File::Spec->tmpdir();
    my $src    = File::Spec->catfile($tmpdir, "conftest_resolv_$$.c");
    my $exe    = File::Spec->catfile($tmpdir, "conftest_resolv_$$");
    open my $fh, '>', $src or return 0;
    print $fh <<'C';
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
int main(void) { res_init(); return 0; }
C
    close $fh;
    my $rc = system("$CC -o $exe $src -lresolv 2>/dev/null") == 0;
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
    print $fh "#define HAVE_UNISTD_H 1\n";
    print $fh "#ifndef HAVE_INET_NTOP\n#define HAVE_INET_NTOP\n#endif\n"   if $v{HAVE_INET_NTOP};
    print $fh "#define HAVE_SOCKLEN_T\n"       if not $v{HAVE_SOCKLEN_T};
    print $fh "#define HAVE_MILTER\n"           if $v{HAVE_MILTER};
    print $fh "#ifndef ENABLE_DEBUGGING\n#define ENABLE_DEBUGGING\n#endif\n" if $v{ENABLE_DEBUGGING};
    print $fh "#ifndef USE_POLL\n#define USE_POLL\n#endif\n"                 if $v{ENABLE_POLL};
    print $fh "#ifndef EMBED_PERL\n#define EMBED_PERL\n#endif\n" if $v{WITH_EMBEDDED_PERL};
    print $fh "#define STDC_HEADERS 1\n";
    close $fh;
    print "config.h written.\n";
}
