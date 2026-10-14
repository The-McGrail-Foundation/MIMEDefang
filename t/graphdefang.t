package Mail::MIMEDefang::Unit::graphdefang;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use File::Temp ();
use Socket;

# Helper: run a md_graphdefang_log_array call and collect the syslog lines emitted.
sub _collect_log {
    my ($cb) = @_;
    my @lines;
    no warnings qw(redefine once);
    local *Mail::MIMEDefang::md_syslog = sub { push @lines, $_[1] };
    use warnings qw(redefine once);
    $cb->();
    return @lines;
}

sub _setup {
    init_globals();
    $InMessageContext        = 1;
    $GraphDefangSyslogFacility = 'mail';
    $MsgID                   = 'TESTID';
    $Sender                  = 'sender@example.com';
    $Subject                 = 'test subject';
}

# With EnumerateRecipients=1 and two recipients, a normal (per-recipient)
# event should produce two MDLOG lines.
sub t_enumerate_two_recipients : Test(3)
{
    _setup();
    @Recipients        = ('a@example.com', 'b@example.com');
    $EnumerateRecipients = 1;

    my @lines = _collect_log(sub {
        md_graphdefang_log('spam', '5.0', '1.2.3.4');
    });

    is(scalar @lines, 2, 'spam: one line per recipient when EnumerateRecipients=1');
    like($lines[0], qr/a\@example\.com/, 'first line contains first recipient');
    like($lines[1], qr/b\@example\.com/, 'second line contains second recipient');
}

# With EnumerateRecipients=1 and two recipients, a per_message=1 event
# should produce exactly one MDLOG line.
sub t_per_message_flag_suppresses_enumeration : Test(2)
{
    _setup();
    @Recipients        = ('a@example.com', 'b@example.com');
    $EnumerateRecipients = 1;

    my @lines = _collect_log(sub {
        md_graphdefang_log('mail_in', '', '', 0, 1);
    });

    is(scalar @lines, 1, 'mail_in: single line when per_message=1, even with EnumerateRecipients=1');
    like($lines[0], qr/rcpts=2/, 'line contains recipient count summary');
}

# With per_message=1 and a single recipient, we should still get the actual
# recipient address.
sub t_per_message_single_recipient_shows_address : Test(2)
{
    _setup();
    @Recipients        = ('only@example.com');
    $EnumerateRecipients = 1;

    my @lines = _collect_log(sub {
        md_graphdefang_log('mail_in', '', '', 0, 1);
    });

    is(scalar @lines, 1, 'single recipient: one line');
    like($lines[0], qr/only\@example\.com/, 'single recipient address shown, not rcpts=1');
}

# md_graphdefang_log_array also accepts per_message as its 4th argument.
sub t_log_array_per_message : Test(2)
{
    _setup();
    @Recipients        = ('x@example.com', 'y@example.com');
    $EnumerateRecipients = 1;

    my @lines = _collect_log(sub {
        my @info = ('extra');
        md_graphdefang_log_array('mail_out', 0, \@info, 1);
    });

    is(scalar @lines, 1, 'md_graphdefang_log_array per_message=1: single line');
    like($lines[0], qr/rcpts=2/, 'line contains recipient count summary');
}

# Omitting per_message (undef) test.
sub t_per_message_default_preserves_enumeration : Test(1)
{
    _setup();
    @Recipients        = ('p@example.com', 'q@example.com');
    $EnumerateRecipients = 1;

    my @lines = _collect_log(sub {
        md_graphdefang_log('non-spam', '0.1', '1.2.3.4');
    });

    is(scalar @lines, 2, 'omitting per_message still enumerates recipients');
}

# ---- Dashboard feed (md_graphdefang_feed_enable) ----

# Create a receiving datagram socket in a temp dir; returns ($sock, $path)
# or an empty list when the path would exceed the sun_path limit.
sub _feed_listener {
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $path = "$dir/feed.sock";
    return () if length($path) > 100;
    socket(my $sock, PF_UNIX, SOCK_DGRAM, 0) or die "socket: $!";
    bind($sock, pack_sockaddr_un($path)) or die "bind: $!";
    return ($sock, $path);
}

sub _feed_read {
    my ($sock) = @_;
    my @got;
    my $rin = '';
    vec($rin, fileno($sock), 1) = 1;
    while (select(my $rout = $rin, undef, undef, 0.2)) {
        my $buf;
        last unless defined recv($sock, $buf, 65536, 0);
        push @got, $buf;
    }
    return @got;
}

sub t_feed_only : Test(4)
{
    my ($sock, $path) = _feed_listener();
    SKIP: {
        skip 'temp dir path too long for a UNIX socket', 4 unless $sock;
        _setup();
        undef $GraphDefangSyslogFacility;
        undef $EnumerateRecipients;
        @Recipients = ('a@example.com', 'b@example.com');
        md_graphdefang_feed_enable($path);
        is($EnumerateRecipients, 1, 'feed enable defaults EnumerateRecipients to 1');

        my @lines = _collect_log(sub {
            md_graphdefang_log('spam', '5.0', '1.2.3.4');
        });
        is(scalar @lines, 0, 'nothing sent to syslog when only the feed is enabled');

        my @got = _feed_read($sock);
        is(scalar @got, 2, 'one datagram per recipient');
        is($got[0], 'MDLOG,TESTID,spam,5.0,1.2.3.4,sender@example.com,a@example.com,test subject',
           'datagram carries the MDLOG line');
        undef $GraphDefangFeedSocket;
    }
}

sub t_feed_missing_socket_is_harmless : Test(2)
{
    _setup();
    undef $GraphDefangSyslogFacility;
    @Recipients = ('a@example.com');
    md_graphdefang_feed_enable('/nonexistent-dir/feed.sock');
    my $ok = eval { md_graphdefang_log('virus', 'EICAR'); 1 };
    ok($ok, 'no die when the dashboard socket does not exist') or diag $@;
    is(Mail::MIMEDefang::_graphdefang_feed_send('x'), 0, 'send reports failure');
    undef $GraphDefangFeedSocket;
}

sub t_feed_and_syslog_identical : Test(2)
{
    my ($sock, $path) = _feed_listener();
    SKIP: {
        skip 'temp dir path too long for a UNIX socket', 2 unless $sock;
        _setup();
        @Recipients = ('only@example.com');
        md_graphdefang_feed_enable($path);
        my @lines = _collect_log(sub {
            md_graphdefang_log('mail_in');
        });
        my @got = _feed_read($sock);
        is(scalar @got, 1, 'one datagram');
        is($got[0], $lines[0], 'feed and syslog receive the same line');
        undef $GraphDefangFeedSocket;
    }
}

# md_graphdefang_feed_enable('mail', 1) mirrors md_graphdefang_log_enable:
# a facility is not a socket path, so the default must be used.
sub t_feed_relative_path_uses_default : Test(3)
{
    my @logged;
    no warnings qw(redefine once);
    local *Mail::MIMEDefang::md_syslog = sub { push @logged, $_[1] };
    use warnings qw(redefine once);
    local $Features{'Path:SPOOLDIR'} = '/var/spool/MIMEDefang';
    md_graphdefang_feed_enable('mail', 1);
    is($GraphDefangFeedSocket, '/var/spool/MIMEDefang/mimedefang-dashboard.sock',
       'relative path replaced by the default socket');
    like($logged[0] // '', qr/not an absolute socket path/, 'the mistake is logged');
    md_graphdefang_feed_enable('/tmp/x.sock');
    is($GraphDefangFeedSocket, '/tmp/x.sock', 'absolute path kept');
    undef $GraphDefangFeedSocket;
}

__PACKAGE__->runtests();
