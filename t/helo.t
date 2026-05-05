package Mail::MIMEDefang::Unit::filter_helo;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

sub create_filter : Test(setup)
{
	no warnings qw(once);
	*::main::filter_helo = sub {
		my($ip, $name, $helo, $port, $myip, $myport, $qid) = @_;

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

		if ($helo =~ m/^reject/) {
			$response = 'REJECT';
			$message = "reject";

			if ($ip =~ m/^192/) {
				$code = 555;
				$dsn = "5.5.5";
			}
		}

		if ($helo =~ m/^continue/) {
			$response = 'CONTINUE';
			$message = "continue";

			if ($ip =~ m/^192/) {
				$code = 222;
				$dsn = "2.2.2";
			}
		}

		if ($helo =~ m/^tempfail/) {
			$response = 'TEMPFAIL';
			$message = "tempfail";

			if ($ip =~ m/^192/) {
				$code = 444;
				$dsn = "4.4.4";
			}
		}

		if ($helo =~ m/^discard/) {
			$response = 'DISCARD';
			$message = "discard";

			if ($ip =~ m/^192/) {
				$code = 299;
				$dsn = "2.99.99";
			}
		}

		if ($helo =~ m/^accept/) {
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

	$self->helo_test("192.168.1.1", "foo.com", "reject.org", 0, "reject", 555, "5.5.5", 0);
	$self->helo_test("10.10.10.10", "foo.com", "reject.org", 0, "reject", 554, "5.7.1", 9);
}

sub tempfail : Test(4)
{
	my ($self) = @_;

	$self->helo_test("192.168.1.1", "foo.com", "tempfail.org", -1, "tempfail", 444, "4.4.4", 0);
	$self->helo_test("10.10.10.10", "foo.com", "tempfail.org", -1, "tempfail", 451, "4.3.0", 9);
}

sub continue : Test(4)
{
	my ($self) = @_;

	$self->helo_test("192.168.1.1", "foo.com", "continue.org", 1, "continue", 222, "2.2.2", 0);
	$self->helo_test("10.10.10.10", "foo.com", "continue.org", 1, "continue", 250, "2.1.0", 9);
}

sub discard : Test(4)
{
	my ($self) = @_;

	$self->helo_test("192.168.1.1", "foo.com", "discard.org", 3, "discard", 299, "2.99.99", 0);
	$self->helo_test("10.10.10.10", "foo.com", "discard.org", 3, "discard", 250, "2.1.0", 9);
}

sub accept_and_no_more_filtering : Test(4)
{
	my ($self) = @_;

	$self->helo_test("192.168.1.1", "foo.com", "accept.org", 2, "accept", 288, "2.8.8", 0);
	$self->helo_test("10.10.10.10", "foo.com", "accept.org", 2, "accept", 250, "2.1.0", 9);
}

sub helo_test
{
	my ($self, $ip, $name, $helo, $action, $msg, $code, $dsn, $delay) = @_;

	my @answer;
	no warnings qw(redefine once);
	local *::md_syslog = sub { note $_[1] };
	local *::main::print_and_flush = sub { @answer = split(/\s+/,$_[0]); };
	use warnings qw(redefine once);

	lives_ok { ::main::handle_helook( $ip, $name, $helo, 25, '127.0.0.1', 25, '242' ) } 'handle_helook lives';

	cmp_deeply( \@answer,
		[
			'ok',
			$action,
			$msg,
			$code,
			$dsn,
			$delay
		],
		'handle_helook called send_filter_answer with expected arguments') or diag(explain(\@answer));
}

__PACKAGE__->runtests();
