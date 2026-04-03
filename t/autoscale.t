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

    my @cmd = (
        _binary(),
        '-D',                   # foreground
        '-s', $sockpath,
        '-z', $spooldir,
        '-m', defined($flags{min}) ? $flags{min} : '0',
        '-x', defined($flags{max}) ? $flags{max} : '4',
    );
    push @cmd, '-k' if $flags{autoscaling};

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

        my ($pid, $sock) = _start_multiplexor();

        my $out = _ctrl_cmd($sock, 'autoscale');
        like($out,   qr/enabled=0/,    'autoscale disabled: enabled=0');
        like($out,   qr/interval=15/,  'autoscale disabled: default interval');
        like($out,   qr/ema_busy=/,    'autoscale disabled: ema_busy field present');

        _stop_multiplexor($pid);
    };
}

sub t_autoscale_enabled : Test(4) {
    SKIP: {
        skip 'mimedefang-multiplexor not built', 4
            unless _binary() && _ctrl();

        my ($pid, $sock) = _start_multiplexor(autoscaling => 1);

        my $out = _ctrl_cmd($sock, 'autoscale');
        like($out, qr/enabled=1/,       'autoscale enabled: enabled=1');
        like($out, qr/scale_out=0\.80/, 'autoscale enabled: default scale_out threshold');
        like($out, qr/scale_in=0\.30/,  'autoscale enabled: default scale_in threshold');
        like($out, qr/ema_alpha=0\.25/, 'autoscale enabled: default ema_alpha');

        _stop_multiplexor($pid);
    };
}

sub t_autoscale_initial_ema : Test(1) {
    SKIP: {
        skip 'mimedefang-multiplexor not built', 1
            unless _binary() && _ctrl();

        my ($pid, $sock) = _start_multiplexor(autoscaling => 1);

        my $out = _ctrl_cmd($sock, 'autoscale');
        like($out, qr/ema_busy=0\.0000/, 'autoscale: initial EMA busy ratio is 0');

        _stop_multiplexor($pid);
    };
}

Mail::MIMEDefang::Unit::Autoscale->runtests() unless caller;

1;
