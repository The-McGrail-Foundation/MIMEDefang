package Mail::MIMEDefang::Unit::dates;
use strict;
use warnings;
use lib qw(lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;
use POSIX;

sub header_timezone_works : Test(3)
{
	local $ENV{TZ} = 'UTC';
	is(::main::header_timezone(time), '+0000', 'Got header timezone for TZ=UTC');

	# Note: we use America/Regina here as the province of Saskatchewan does
	# not observe DST.
	$::main::CachedTimezone = '';
	local $ENV{TZ} = 'America/Regina';
	is(::main::header_timezone(time), '-0600', 'Got header timezone for TZ=America/Regina');
	$::main::CachedTimezone = '-1000';
	is(::main::header_timezone(time), '-1000', 'cache gets used');

	$::main::CachedTimezone = '';
}

sub rfc2822_date_works : Test(1)
{
	my $now = time();
	no warnings 'redefine';
	no warnings 'once';
	local *time = sub { return $now; };

	my $want = strftime('%a, %d %b %Y %H:%M:%S %z', localtime($now));
	is(::main::rfc2822_date(), $want, 'Got correct RFC 2822 date');
}

sub gen_msgid_header_works : Test(1)
{
	no warnings 'once';
	local $::main::QueueID = 'wookie';
	like(::main::gen_msgid_header(), qr/Message-ID: <\d{12}\.wookie\@[-a-zA-Z0-9\.]+>\n/, 'Got Message-ID header in correct format');
}

__PACKAGE__->runtests();
