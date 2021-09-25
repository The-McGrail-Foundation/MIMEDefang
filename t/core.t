package Mail::MIMEDefang::Unit::core;
use strict;
use warnings;
use lib qw(lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang::Core;

sub t_init_globals1 : Test(1)
{
  $::main::Changed = 1;
  is($::main::Changed, 1);
}

sub t_init_globals2 : Test(2)
{
  $::main::Changed = 1;
  init_globals();
  is($::main::Changed, 0);
}

sub t_read_config : Test(3)
{
  init_globals();
  no warnings qw(redefine once);
  local *::md_syslog = sub { note $_[1] };
  use warnings qw(redefine once);
  Mail::MIMEDefang::Core::read_config("t/data/md.conf");
  is($SALocalTestsOnly, 0);
}

sub t_detect_and_load_perl_modules : Test(4)
{
  my $dnsver;
  my %Features;
  $Features{"Net::DNS"} = 1;
  detect_and_load_perl_modules();
  $dnsver = Net::DNS->version;
  like($dnsver, qr/([0-9]+)\.([0-9]+)/, "Net::DNS correctly loaded, version is $dnsver");
}

__PACKAGE__->runtests();
