package MIMEDefang::Unit::dates;
use strict;
use warnings;
use lib qw(lib);
use base qw(MIMEDefang::Unit);
use Test::Most;
use MIMEDefang::Core;

sub init_globals1 : Test(1)
{
  $::main::Changed = 1;
  is($::main::Changed, 1);
}

sub init_globals2 : Test(2)
{
  $::main::Changed = 1;
  is($::main::Changed, 1);
  MIMEDefang::Core::init_globals();
  is($::main::Changed, 0);
}

__PACKAGE__->runtests();
