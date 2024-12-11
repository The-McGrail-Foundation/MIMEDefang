use strict;
use warnings;
use Test::More;

if (not $ENV{TEST_AUTHOR}) {
    my $msg = 'Author test.  Set $ENV{TEST_AUTHOR} to a true value to run.';
    plan( skip_all => $msg );
}
eval { require Test::Perl::Critic; };
if ($@) {
   my $msg = 'Test::Perl::Critic required to criticise code';
   plan( skip_all => $msg );
} else {
  Test::Perl::Critic->import;
}
all_critic_ok('modules');
