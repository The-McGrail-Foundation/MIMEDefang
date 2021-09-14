package Mail::MIMEDefang::Unit::headers;
use strict;
use warnings;
use lib qw(lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

sub delete_header_ok : Test(2)
{
	my @results;

	no warnings qw(redefine once );
	local *::main::write_result_line = sub { push @results, [ @_ ] };

	# Lie about being in message context so these tests can work
	local $::main::InMessageContext = 1;
	use warnings qw(redefine once );

	::main::action_delete_header('X-Header');
	cmp_deeply( \@results, [ ['J', 'X-Header', 1 ] ], 'action_delete_header() wrote correct J line');

	@results = ();
	::main::action_delete_header('X-Header', 2);
	cmp_deeply( \@results, [[ 'J', 'X-Header', 2 ]], 'action_delete_header() wrote correct J line');
}

sub add_header_ok : Test(2)
{
	my @results;

	no warnings qw(redefine once );
	local *::main::write_result_line = sub { push @results, [ @_ ] };

	# Lie about being in message context so these tests can work
	local $::main::InMessageContext = 1;
	use warnings qw(redefine once );

	::main::action_add_header('X-Header', 'some content');
	cmp_deeply( \@results, [ ['H', 'X-Header', 'some content' ] ], 'action_add_header() wrote correct H line');

	::main::action_add_header('X-Other', '42');
	cmp_deeply( \@results, [ ['H', 'X-Header', 'some content' ], ['H', 'X-Other', 42] ], 'action_add_header() wrote correct H line');
}

sub change_header_ok : Test(2)
{
	my @results;

	no warnings qw(redefine once );
	local *::main::write_result_line = sub { push @results, [ @_ ] };

	# Lie about being in message context so these tests can work
	local $::main::InMessageContext = 1;
	use warnings qw(redefine once );

	::main::action_change_header('X-Header', 'some content');
	cmp_deeply( \@results, [ ['I', 'X-Header', 1, 'some content' ] ], 'action_change_header() wrote correct I line');

	::main::action_change_header('Received', 'position 3', 3);
	cmp_deeply( \@results, [ ['I', 'X-Header', 1, 'some content' ], ['I', 'Received', 3, 'position 3'] ], 'action_add_header() wrote correct I line');
}


__PACKAGE__->runtests();
