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

sub change_header_ok : Test(3)
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

	undef @results;
        unlink('./RESULTS') if -f './RESULTS';
	action_change_header('Subject', '🌸👀 OK');
        undef $results_fh;
        @results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ ['I', 'Subject', 1, '🌸👀 OK' ] ], 'action_change_header() wrote correct I line');
        unlink('./RESULTS') if -f './RESULTS';
}

sub insert_header_ok : Test(2)
{
	my @results;

	$InMessageContext = 1;

	action_insert_header('X-Test', 'val', 2);
	undef $results_fh;
	@results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ ['N', 'X-Test', 2, 'val'] ], 'action_insert_header() wrote correct N line with explicit position');
	unlink('./RESULTS') if -f './RESULTS';

	action_insert_header('X-Other', 'foo');
	undef $results_fh;
	@results = Mail::MIMEDefang::Utils::read_results();
	cmp_deeply( \@results, [ ['N', 'X-Other', 0, 'foo'] ], 'action_insert_header() defaults to position 0');
	unlink('./RESULTS') if -f './RESULTS';
}

sub delete_all_headers_ok : Test(2)
{
	$InMessageContext = 1;

	# Create a HEADERS file with two X-Spam lines
	open(my $h, '>', './HEADERS') or die "Cannot create HEADERS: $!";
	print $h "X-Spam: yes\n";
	print $h "X-Spam: maybe\n";
	close($h);

	unlink('./RESULTS') if -f './RESULTS';
	undef $results_fh;
	action_delete_all_headers('X-Spam');

	undef $results_fh;
	my @results = Mail::MIMEDefang::Utils::read_results();
	# Deletes in reverse order: index 2 first, then index 1
	cmp_deeply( \@results, [ ['J', 'X-Spam', 2], ['J', 'X-Spam', 1] ], 'action_delete_all_headers() deletes all instances in reverse order');
	unlink('./RESULTS') if -f './RESULTS';
	unlink('./HEADERS') if -f './HEADERS';

	# Returns 0 outside message context
	$InMessageContext = 0;
	my $ret = action_delete_all_headers('X-Spam');
	is($ret, 0, 'action_delete_all_headers() returns 0 outside message context');
}

__PACKAGE__->runtests();
