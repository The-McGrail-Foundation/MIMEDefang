#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

# Integration tests for the -k autoscaling flag in mimedefang-multiplexor.

package Mail::MIMEDefang::Unit::Autoscale;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use File::Temp qw(tempdir);
use POSIX      qw(SIGTERM);

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub _binary {
    return -x './mimedefang-multiplexor' ? './mimedefang-multiplexor' : undef;
}

sub _ctrl {
    return -x './md-mx-ctrl' ? './md-mx-ctrl' : undef;
}

# Start multiplexor in the background; returns ($pid, $sockpath, $spooldir).
sub _start_multiplexor {
    my (%flags) = @_;

    my $spooldir = tempdir(CLEANUP => 1);
    my $sockpath = "$spooldir/mimedefang-multiplexor.sock";

    my @cmd = (_binary(), '-D');    # foreground
    # -k comes first, so that the tests also check that it does not take
    # the option after it as its settings
    if (defined $flags{spec}) {
        push @cmd, '-k', $flags{spec};
    } elsif ($flags{autoscaling}) {
        push @cmd, '-k';
    }
    push @cmd,
        '-s', $sockpath,
        '-z', $spooldir,
        '-m', defined($flags{min}) ? $flags{min} : '0',
        '-x', defined($flags{max}) ? $flags{max} : '4';
    push @cmd, '-w', $flags{slew}   if defined $flags{slew};
    push @cmd, '-f', $flags{worker} if defined $flags{worker};

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        # Redirect stdout/stderr to /dev/null in child.
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';
        exec @cmd;
        exit 1;
    }

    # Give the multiplexor a moment to create its socket.
    my $deadline = time() + 5;
    while (!-S $sockpath && time() < $deadline) {
        select undef, undef, undef, 0.1;
    }

    return ($pid, $sockpath, $spooldir);
}

sub _stop_multiplexor {
    my ($pid) = @_;
    kill SIGTERM, $pid;
    waitpid($pid, 0);
}

sub _ctrl_cmd {
    my ($sockpath, $cmd) = @_;
    my $out = `./md-mx-ctrl -s '$sockpath' $cmd 2>/dev/null`;
    return $out;
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

sub t_autoscale_disabled : Test(3) {
    SKIP: {
        skip 'mimedefang-multiplexor not built', 3
            unless _binary() && _ctrl();
        skip 'mimedefang-multiplexor cannot run as root', 3
            if $> == 0;

        my ($pid, $sock) = _start_multiplexor();

        my $out = _ctrl_cmd($sock, 'autoscale');
        like($out,   qr/enabled=0/,     'autoscale disabled: enabled=0');
        like($out,   qr/interval=15\b/, 'autoscale disabled: default interval');
        like($out,   qr/window=600\b/,  'autoscale disabled: default window');

        _stop_multiplexor($pid);
    };
}

sub t_autoscale_enabled : Test(6) {
    SKIP: {
        skip 'mimedefang-multiplexor not built', 6
            unless _binary() && _ctrl();
        skip 'mimedefang-multiplexor cannot run as root', 6
            if $> == 0;

        my ($pid, $sock) = _start_multiplexor(autoscaling => 1);

        my $out = _ctrl_cmd($sock, 'autoscale');
        like($out, qr/enabled=1/,        'autoscale enabled: enabled=1');
        like($out, qr/spare=0\b/,        'autoscale enabled: default spare');
        like($out, qr/min_age=60\b/,     'autoscale enabled: min_age reported');
        like($out, qr/demand=0\b/,       'autoscale enabled: no demand yet');
        like($out, qr/window_peak=0\b/,  'autoscale enabled: empty window');
        my ($states) = split ' ', _ctrl_cmd($sock, 'rawstatus');
        is(length($states // ''), 4, 'autoscale enabled: -k does not take the next option');

        _stop_multiplexor($pid);
    };
}

sub t_autoscale_tuning : Test(5) {
    SKIP: {
        skip 'mimedefang-multiplexor not built', 5
            unless _binary() && _ctrl();
        skip 'mimedefang-multiplexor cannot run as root', 5
            if $> == 0;

        # -k with settings
        my ($pid, $sock) = _start_multiplexor(spec => 'interval=7,window=120,spare=1');

        my $out = _ctrl_cmd($sock, 'autoscale');
        like($out, qr/enabled=1/,      'autoscale -k settings: enabled');
        like($out, qr/interval=7\b/,   'autoscale -k settings: interval');
        like($out, qr/window=120\b/,   'autoscale -k settings: window');
        like($out, qr/spare=1\b/,      'autoscale -k settings: spare');

        _stop_multiplexor($pid);

        # An invalid specification must make the multiplexor refuse to start
        my $spooldir = tempdir(CLEANUP => 1);
        my $rc = system(_binary() . " -D -z '$spooldir' -s '$spooldir/s.sock' -k bogus=1 >/dev/null 2>&1");
        isnt($rc, 0, 'autoscale -k settings: invalid specification is rejected');
    };
}

# A stand-in for mimedefang.pl: it only has to stay alive.
sub _fake_worker {
    my $dir = tempdir(CLEANUP => 1);
    my $path = "$dir/worker.sh";
    open my $fh, '>', $path or die "$path: $!";
    print $fh "#!/bin/sh\ncat >/dev/null\n";
    close $fh;
    chmod 0755, $path;
    return ($path, $dir);
}

sub _count_workers {
    my ($sock) = @_;
    my $out = _ctrl_cmd($sock, 'workers');
    my @alive = $out =~ /^\d+ [IB] /mg;
    return scalar @alive;
}

sub t_autoscale_guard_status : Test(2) {
    SKIP: {
        skip 'mimedefang-multiplexor not built', 2
            unless _binary() && _ctrl();
        skip 'mimedefang-multiplexor cannot run as root', 2
            if $> == 0;

        my ($pid, $sock) = _start_multiplexor(spec => 'max_load=6.5,min_mem=1024');

        my $out = _ctrl_cmd($sock, 'autoscale');
        like($out, qr/max_load=6\.50/,     'autoscale: max_load');
        like($out, qr/min_mem=1024\b/,     'autoscale: min_mem');

        _stop_multiplexor($pid);
    };
}

sub t_autoscale_prewarm : Test(6) {
    SKIP: {
        skip 'mimedefang-multiplexor not built', 6
            unless _binary() && _ctrl();
        skip 'mimedefang-multiplexor cannot run as root', 6
            if $> == 0;

        my ($worker) = _fake_worker();
        # No traffic at all: spare=3 must make the autoscaler pre-warm the
        # pool (one worker every slew time).
        my ($pid, $sock) = _start_multiplexor(
            min => 0, max => 6, slew => 1, worker => $worker,
            spec => 'interval=1,spare=3');

        my $n = 0;
        my $deadline = time() + 12;
        while (time() < $deadline) {
            $n = _count_workers($sock);
            last if $n >= 3;
            select undef, undef, undef, 0.5;
        }
        is($n, 3, 'autoscale: spare=3 pre-warms three workers');

        # ... and no more than that
        select undef, undef, undef, 3;
        is(_count_workers($sock), 3, 'autoscale: pre-warming stops at the headroom');

        my $st = _ctrl_cmd($sock, 'autoscale');
        like($st, qr/started=3\b/,       'autoscale: started counter');
        like($st, qr/desired=3\b/,       'autoscale: desired pool size');
        my $json = _ctrl_cmd($sock, 'jsonautoscale');
        like($json, qr/"started":\s*3\b/, 'jsonautoscale: started counter');
        like($json, qr/"blocked":\s*0\b/, 'jsonautoscale: same key names as autoscale');

        _stop_multiplexor($pid);
    };
}

sub t_autoscale_guard : Test(1) {
    SKIP: {
        skip 'mimedefang-multiplexor not built', 1
            unless _binary() && _ctrl();
        skip 'mimedefang-multiplexor cannot run as root', 1
            if $> == 0;
        skip 'the available memory cannot be read on this system', 1
            unless $^O =~ /^(linux|freebsd|dragonfly|openbsd|netbsd)$/;

        my ($worker) = _fake_worker();
        # Same as the pre-warming test, but demanding 4 TiB of free memory
        # before the autoscaler may start a worker: nothing may be started.
        my ($pid, $sock) = _start_multiplexor(
            min => 0, max => 6, slew => 1, worker => $worker,
            spec => 'interval=1,spare=3,min_mem=4194304');

        select undef, undef, undef, 5;
        my $n = _count_workers($sock);
        cmp_ok($n, '<', 2, 'autoscale: min_mem blocks the pre-warming');

        _stop_multiplexor($pid);
    };
}

Mail::MIMEDefang::Unit::Autoscale->runtests() unless caller;

1;
