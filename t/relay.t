package MIMEDefang::Unit::filter_relay;
use strict;
use warnings;
use lib qw(lib);
use base qw(MIMEDefang::Unit);
use Test::Most;

sub create_filter : Test(setup)
{
	no warnings qw(once);
	*::main::filter_relay = sub {
		my($hostip, $hostname) = @_;

		# $response can be:
		#
		# ’REJECT’
		#      if the connection should be rejected.
		#
		# ’CONTINUE’
		#      if the connection should be accepted.
		#
		# ’TEMPFAIL’
		#      if a temporary failure code should be returned.
		#
		# ’DISCARD’
		#      if the message should be accepted and silently discarded.
		#
		# ’ACCEPT_AND_NO_MORE_FILTERING’
		#      if the connection should be accepted and no further filtering done.
		#
		# Earlier  versions of MIMEDefang used -1 for TEMPFAIL, 0 for REJECT and 1 for CONTINUE.  These values still
		# work, but are deprecated.
		#
		# In the case of REJECT or TEMPFAIL, $msg specifies the text part of the SMTP reply.  $msg must not  contain
		# newlines.
		#
		#

		my $response = "";
		my $message = "";
		my $code = "";
		my $dsn = "";
		my $delay = 0;

		if ($hostname =~ m/^reject/) {
			$response = 'REJECT';
			$message = "reject";

			if ($hostip =~ m/^192/) {
				$code = 555;
				$dsn = "5.5.5";
			}
		}

		if ($hostname =~ m/^continue/) {
			$response = 'CONTINUE';
			$message = "continue";

			if ($hostip =~ m/^192/) {
				$code = 222;
				$dsn = "2.2.2";
			}
		}

		if ($hostname =~ m/^tempfail/) {
			$response = 'TEMPFAIL';
			$message = "tempfail";

			if ($hostip =~ m/^192/) {
				$code = 444;
				$dsn = "4.4.4";
			}
		}

		if ($hostname =~ m/^discard/) {
			$response = 'DISCARD';
			$message = "discard";

			if ($hostip =~ m/^192/) {
				$code = 299;
				$dsn = "2.99.99";
			}
		}

		if ($hostname =~ m/^accept/) {
			$response = 'ACCEPT_AND_NO_MORE_FILTERING';
			$message = "accept";

			if ($hostip =~ m/^192/) {
				$code = 288;
				$dsn = "2.8.8";
			}
		}

		if (!($hostip =~ m/^192/)) {
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

	$self->relay_test("192.168.1.1", 0, "reject", 555, "5.5.5", 0);
	$self->relay_test("10.10.10.10", 0, "reject", 554, "5.7.1", 9);
}

sub continue : Test(4)
{
	my ($self) = @_;

	$self->relay_test("192.168.1.1", 1, "continue", 222, "2.2.2", 0);
	$self->relay_test("10.10.10.10", 1, "continue", 250, "2.1.0", 9);
}

sub tempfail : Test(4)
{
	my ($self) = @_;

	$self->relay_test("192.168.1.1", -1, "tempfail", 444, "4.4.4", 0);
	$self->relay_test("10.10.10.10", -1, "tempfail", 451, "4.3.0", 9);
}

sub discard : Test(4)
{
	my ($self) = @_;

	$self->relay_test("192.168.1.1", 3, "discard", 299, "2.99.99", 0);
	$self->relay_test("10.10.10.10", 3, "discard", 250, "2.1.0", 9);
}

sub accept_and_no_more_filtering : Test(4)
{
	my ($self) = @_;

	$self->relay_test("192.168.1.1", 2, "accept", 288, "2.8.8", 0);
	$self->relay_test("10.10.10.10", 2, "accept", 250, "2.1.0", 9);
}

sub relay_test
{
	my ($self, $ip, $action, $msg, $code, $dsn, $delay) = @_;

	my @answer;
	no warnings qw(redefine once);
	local *::md_syslog = sub { note $_[1] };
	local *::main::print_and_flush = sub { @answer = split(/\s+/,$_[0]); };
	use warnings qw(redefine once);

	lives_ok { ::main::handle_relayok( $ip, "$msg.com" ) } 'handle_relayok lives';

	cmp_deeply( \@answer,
		[
			'ok',
			$action,
			$msg,
			$code,
			$dsn,
			$delay
		],
		'handle_relayok called send_filter_answer with expected arguments') or diag(explain(\@answer));
}

__PACKAGE__->runtests();
