package Mail::MIMEDefang::Unit::core;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;

use File::Copy;

sub t_init_globals1 : Test(1)
{
  $::main::Changed = 1;
  is($::main::Changed, 1);
}

sub t_init_globals2 : Test(1)
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
  my $conf_fname = "t/data/md.conf";
  SKIP: {
    skip "read_config test must be run as root", 1 unless ($< eq 0);
    my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
        $atime,$mtime,$ctime,$blksize,$blocks)
        = stat($conf_fname);
    # Set correct owner to config file
    chown(0, 0, $conf_fname);
    read_config($conf_fname);
    is($SALocalTestsOnly, 0);
    # Set back original owner
    chown($uid, $gid, $conf_fname);
  };
}

sub t_detect_and_load_perl_modules : Test(1)
{
  my $dnsver;
  detect_and_load_perl_modules();
  $dnsver = Net::DNS->version;
  like($dnsver, qr/([0-9]+)\.([0-9]+)/, "Net::DNS correctly loaded, version is $dnsver");
}

sub t_mimedefang_version : Test(1)
{
  like(md_version(), qr/[0-9]\.[0-9]{1,2}/);
}

sub t_read_commands_file : Test(5)
{
  copy('t/data/COMMANDS', './COMMANDS');
  init_globals();
  read_commands_file();
  is($Sender, '<15522-813-61658-597@mail.example.com>');
  is($RelayAddr, '1.2.3.4');
  is($Subject, 'Subject');
  is($QueueID, '46QDY4CT972760');
  is($SendmailMacros{load_avg}, 1);
  unlink('./COMMANDS');
}

__PACKAGE__->runtests();
