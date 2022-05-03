package Mail::MIMEDefang::Unit::headers;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Actions;
use Mail::MIMEDefang::Utils;

sub delete_header_ok : Test(2)
{
	my @results;

	# Lie about being in message context so these tests can work
	$InMessageContext = 1;

	action_delete_header('X-Header');
        undef $results_fh;
        @results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ ['J', 'X-Header', 1 ] ], 'action_delete_header() wrote correct J line');
        unlink('./RESULTS') if -f './RESULTS';

	action_delete_header('X-Header', 2);
        undef $results_fh;
        @results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ [ 'J', 'X-Header', 2 ] ], 'action_delete_header() wrote correct J line');
        unlink('./RESULTS') if -f './RESULTS';
}

sub add_header_ok : Test(2)
{
	my @results;

	# Lie about being in message context so these tests can work
	$InMessageContext = 1;

	action_add_header('X-Header', 'some content');
        undef $results_fh;
        @results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ ['H', 'X-Header', 'some content' ] ], 'action_add_header() wrote correct H line');

	action_add_header('X-Other', '42');
        undef $results_fh;
        @results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ ['H', 'X-Header', 'some content' ], ['H', 'X-Other', 42] ], 'action_add_header() wrote correct H line');
        unlink('./RESULTS') if -f './RESULTS';
}

sub change_header_ok : Test(2)
{
	my @results;

	# Lie about being in message context so these tests can work
	$InMessageContext = 1;

	action_change_header('X-Header', 'some content');
        undef $results_fh;
        @results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ ['I', 'X-Header', 1, 'some content' ] ], 'action_change_header() wrote correct I line');

	action_change_header('Received', 'position 3', 3);
        undef $results_fh;
        @results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ ['I', 'X-Header', 1, 'some content' ], ['I', 'Received', 3, 'position 3'] ], 'action_add_header() wrote correct I line');
        unlink('./RESULTS') if -f './RESULTS';
}

__PACKAGE__->runtests();
