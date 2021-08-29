package MIMEDefang::Unit::core;
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
  MIMEDefang::Core::init_globals();
  is($::main::Changed, 0);
}

sub read_config : Test(3)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub { note $_[1] };
  use warnings qw(redefine once);
  ::main::read_config("t/data/md.conf");
  is($SALocalTestsOnly, 0);
}

__PACKAGE__->runtests();
