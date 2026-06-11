package Mail::MIMEDefang::Unit::graphdefang;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;

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

__PACKAGE__->runtests();
