package Mail::MIMEDefang::Unit::filter_recipient;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Cwd;
use Test::Most;

sub create_filter : Test(setup)
{
	no warnings qw(once);
	*::main::filter_recipient = sub {
		my($recipient, $sender, $ip, $name, $firstRecip, $helo, $rcpt_mailer, $rcpt_host, $rcpt_addr) = @_;

		# $response can be:
		#
		# 'REJECT'
		#      if the connection should be rejected.
		#
		# 'CONTINUE'
		#      if the connection should be accepted.
		#
		# 'TEMPFAIL'
		#      if a temporary failure code should be returned.
		#
		# 'DISCARD'
		#      if the message should be accepted and silently discarded.
		#
		# 'ACCEPT_AND_NO_MORE_FILTERING'
		#      if the connection should be accepted and no further filtering done.
		#

		my $response = "";
		my $message = "";
		my $code = "";
		my $dsn = "";
		my $delay = 0;

		if ($recipient =~ m/^reject/) {
			$response = 'REJECT';
			$message = "reject";

			if ($ip =~ m/^192/) {
				$code = 555;
				$dsn = "5.5.5";
			}
		}

		if ($recipient =~ m/^continue/) {
			$response = 'CONTINUE';
			$message = "continue";

			if ($ip =~ m/^192/) {
				$code = 222;
				$dsn = "2.2.2";
			}
		}

		if ($recipient =~ m/^tempfail/) {
			$response = 'TEMPFAIL';
			$message = "tempfail";

			if ($ip =~ m/^192/) {
				$code = 444;
				$dsn = "4.4.4";
			}
		}

		if ($recipient =~ m/^discard/) {
			$response = 'DISCARD';
			$message = "discard";

			if ($ip =~ m/^192/) {
				$code = 299;
				$dsn = "2.99.99";
			}
		}

		if ($recipient =~ m/^accept/) {
			$response = 'ACCEPT_AND_NO_MORE_FILTERING';
			$message = "accept";

			if ($ip =~ m/^192/) {
				$code = 288;
				$dsn = "2.8.8";
			}
		}

		if (!($ip =~ m/^192/)) {
			$code = 999;
			$dsn = "9.9.9";
			$delay = 9;
		}

		return ($response, $message, $code, $dsn, $delay);
	};
}

sub reject : Test(4)
{
	my ($self) = @_;

	$self->recipient_test('reject@foo.com', 'sender@foo.com', "192.168.1.1", "foo.com",
		0, "reject", 555, "5.5.5", 0);
	$self->recipient_test('reject@foo.com', 'sender@foo.com', "10.10.10.10", "foo.com",
		0, "reject", 554, "5.7.1", 9);
}

sub tempfail : Test(4)
{
	my ($self) = @_;

	$self->recipient_test('tempfail@foo.com', 'sender@foo.com', "192.168.1.1", "foo.com",
		-1, "tempfail", 444, "4.4.4", 0);
	$self->recipient_test('tempfail@foo.com', 'sender@foo.com', "10.10.10.10", "foo.com",
		-1, "tempfail", 451, "4.3.0", 9);
}

sub continue : Test(4)
{
	my ($self) = @_;

	$self->recipient_test('continue@foo.com', 'sender@foo.com', "192.168.1.1", "foo.com",
		1, "continue", 222, "2.2.2", 0);
	$self->recipient_test('continue@foo.com', 'sender@foo.com', "10.10.10.10", "foo.com",
		1, "continue", 250, "2.1.0", 9);
}

sub discard : Test(4)
{
	my ($self) = @_;

	$self->recipient_test('discard@foo.com', 'sender@foo.com', "192.168.1.1", "foo.com",
		3, "discard", 299, "2.99.99", 0);
	$self->recipient_test('discard@foo.com', 'sender@foo.com', "10.10.10.10", "foo.com",
		3, "discard", 250, "2.1.0", 9);
}

sub accept_and_no_more_filtering : Test(4)
{
	my ($self) = @_;

	$self->recipient_test('accept@foo.com', 'sender@foo.com', "192.168.1.1", "foo.com",
		2, "accept", 288, "2.8.8", 0);
	$self->recipient_test('accept@foo.com', 'sender@foo.com', "10.10.10.10", "foo.com",
		2, "accept", 250, "2.1.0", 9);
}

sub recipient_test
{
	my ($self, $recipient, $sender, $ip, $name, $action, $msg, $code, $dsn, $delay) = @_;

	my @answer;
	no warnings qw(redefine once);
	local *::md_syslog = sub { note $_[1] };
	local *::main::print_and_flush = sub { @answer = split(/\s+/,$_[0]); };
	use warnings qw(redefine once);

	lives_ok { ::main::handle_recipok( $recipient, $sender, $ip, $name, 1, 'test.org',
		Cwd::cwd(), '242', 'esmtp', $name, $recipient ) } 'handle_recipok lives';

	cmp_deeply( \@answer,
		[
			'ok',
			$action,
			$msg,
			$code,
			$dsn,
			$delay
		],
		'handle_recipok called send_filter_answer with expected arguments') or diag(explain(\@answer));
}

__PACKAGE__->runtests();
