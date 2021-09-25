package Mail::MIMEDefang::Unit::filter_sender;
use strict;
use warnings;
use lib qw(lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

sub create_filter : Test(setup)
{
	no warnings qw(once);
	*::main::filter_sender = sub {
		my($sender, $hostip, $hostname, $helo) = @_;

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

		if ($sender =~ m/^reject/) {
			$response = 'REJECT';
			$message = "reject";

			if ($helo =~ m/^test/) {
				$code = 555;
				$dsn = "5.5.5";
			}
		}

		if ($sender =~ m/^continue/) {
			$response = 'CONTINUE';
			$message = "continue";

			if ($helo =~ m/^test/) {
				$code = 222;
				$dsn = "2.2.2";
			}
		}

		if ($sender =~ m/^tempfail/) {
			$response = 'TEMPFAIL';
			$message = "tempfail";

			if ($helo =~ m/^test/) {
				$code = 444;
				$dsn = "4.4.4";
			}
		}

		if ($sender =~ m/^discard/) {
			$response = 'DISCARD';
			$message = "discard";

			if ($helo =~ m/^test/) {
				$code = 299;
				$dsn = "2.99.99";
			}
		}

		if ($sender =~ m/^accept/) {
			$response = 'ACCEPT_AND_NO_MORE_FILTERING';
			$message = "accept";

			if ($helo =~ m/^test/) {
				$code = 288;
				$dsn = "2.8.8";
			}
		}

		if ($helo =~ m/^default/) {
			$code = 999;
			$dsn = "9.9.9";
			$delay = 9;
		}

		if ($::main::ESMTPArgs[1] ne 'esmtp2') {
			$message = "ESMTP args failed.";
		}

		return ($response, $message, $code, $dsn, $delay);
	};
}

sub reject : Test(4)
{
	my ($self) = @_;

	$self->sender_test('reject@foo.com', "192.168.1.1", "foo2.com", "test.org",
		0, "reject", 555, "5.5.5", 0);
	$self->sender_test('reject@foo.com', "10.10.10.10", "foo2.com", "default.org",
		0, "reject", 554, "5.7.1", 9);
}

sub tempfail : Test(4)
{
	my ($self) = @_;

	$self->sender_test('tempfail@foo.com', "192.168.1.1", "foo2.com", "test.org",
		-1, "tempfail", 444, "4.4.4", 0);
	$self->sender_test('tempfail@foo.com', "10.10.10.10", "foo2.com", "default.org",
		-1, "tempfail", 451, "4.3.0", 9);
}


sub continue : Test(4)
{
	my ($self) = @_;

	$self->sender_test('continue@foo.com', "192.168.1.1", "foo2.com", "test.org",
		1, "continue", 222, "2.2.2", 0);
	$self->sender_test('continue@foo.com', "10.10.10.10", "foo2.com", "default.org",
		1, "continue", 250, "2.1.0", 9);
}

sub discard : Test(4)
{
	my ($self) = @_;

	$self->sender_test('discard@foo.com', "192.168.1.1", "foo2.com", "test.org",
		3, "discard", 299, "2.99.99", 0);
	$self->sender_test('discard@foo.com', "10.10.10.10", "foo2.com", "default.org",
		3, "discard", 250, "2.1.0", 9);
}

sub accept_and_no_more_filtering : Test(4)
{
	my ($self) = @_;

	$self->sender_test('accept@foo.com', "192.168.1.1", "foo2.com", "test.org",
		2, "accept", 288, "2.8.8", 0);
	$self->sender_test('accept@foo.com', "10.10.10.10", "foo2.com", "default.org",
		2, "accept", 250, "2.1.0", 9);
}

sub sender_test
{
	my ($self, $sender, $ip, $host, $helo, $action, $msg, $code, $dsn, $delay) = @_;

	my @answer;
	no warnings qw(redefine once);
	local *::md_syslog = sub { note $_[1] };
	local *::main::print_and_flush = sub { @answer = split(/\s+/,$_[0]); };
	use warnings qw(redefine once);

	lives_ok { ::main::handle_senderok( $sender, $ip, $host, $helo, Cwd::cwd(), '242', qw( esmtp1 esmtp2 ) ) } 'handle_senderok lives';

	cmp_deeply( \@answer,
		[
			'ok',
			$action,
			$msg,
			$code,
			$dsn,
			$delay
		],
		'handle_senderok called send_filter_answer with expected arguments') or diag(explain(\@answer));
}

__PACKAGE__->runtests();
