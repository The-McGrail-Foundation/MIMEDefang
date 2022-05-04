package Mail::MIMEDefang::Unit::core;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;

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

sub t_read_config : Test(1)
{
  init_globals();
  no warnings qw(redefine once);
  local *::md_syslog = sub { note $_[1] };
  use warnings qw(redefine once);
  SKIP: {
    skip "read_config test must be run as root", 1 unless ($< eq 0);
    ::main::read_config("t/data/md.conf");
    is($SALocalTestsOnly, 0);
  };
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

sub t_mimedefang_version : Test(1)
{
  like(md_version(), qr/[0-9]\.[0-9]{1,2}/);
}

__PACKAGE__->runtests();
