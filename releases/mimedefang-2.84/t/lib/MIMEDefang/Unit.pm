package MIMEDefang::Unit;
use strict;
use warnings;
use Test::Class;
use base qw( Test::Class );

use Test::Most;

# This bit of evil is how we pull in MIMEDefang's .pl code without running anything.
sub include_mimedefang : Test(startup)
{
	no warnings 'redefine';
	local *CORE::GLOBAL::exit = sub { };
	local @ARGV = ();
	do 'mimedefang.pl.in';
	use warnings 'redefine';
}
1;
