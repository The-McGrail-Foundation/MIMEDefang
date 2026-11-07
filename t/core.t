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
    ::main::read_config($conf_fname);
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

# Runs $code in a fresh perl with modules/lib in @INC and returns its
# standard output.  The list form of open() keeps the shell out of it.
sub _in_new_perl
{
  my ($code) = @_;
  open(my $fh, '-|', $^X, '-Imodules/lib', '-e', $code) or die "Cannot run $^X: $!";
  local $/;
  my $out = <$fh> // '';
  close($fh);
  chomp $out;
  return $out;
}

sub t_disabled_feature_not_loaded : Test(2)
{
  SKIP: {
    skip 'Mail::SpamAssassin not installed', 2
      unless eval { require Mail::SpamAssassin; 1 };
    # The filter disables SpamAssassin and calls detect_and_load_perl_modules(),
    # then mimedefang.pl calls it again: it must stay disabled.
    my $out = _in_new_perl(q{
      use Mail::MIMEDefang;
      init_globals();
      $Features{"SpamAssassin"} = 0;
      detect_and_load_perl_modules();
      detect_and_load_perl_modules();
      print join(",", $Features{"SpamAssassin"} // "undef",
                 exists $INC{"Mail/SpamAssassin.pm"} ? "loaded" : "not loaded");
    });
    is($out, '0,not loaded', '$Features{"SpamAssassin"} = 0 survives a second detect_and_load_perl_modules()');
    $out = _in_new_perl(q{
      use Mail::MIMEDefang;
      init_globals();
      detect_and_load_perl_modules();
      print exists $INC{"Mail/SpamAssassin.pm"} ? "loaded" : "not loaded";
    });
    is($out, 'loaded', 'SpamAssassin is still loaded by default');
  }
}

sub t_io_socket_ssl_not_loaded_at_startup : Test(1)
{
  my $out = _in_new_perl(q{
    use Mail::MIMEDefang::Mail;
    print exists $INC{"IO/Socket/SSL.pm"} ? "loaded" : "not loaded";
  });
  is($out, 'not loaded', 'Mail::MIMEDefang::Mail does not load IO::Socket::SSL');
}

sub t_smtp_check_without_io_socket_ssl : Test(1)
{
  # IO::Socket::SSL can't be loaded: md_check_against_smtp_server()
  # must TEMPFAIL without connecting, and log the error only once
  my $out = _in_new_perl(q{
    BEGIN { unshift @INC, sub { die "blocked\n" if $_[1] eq "IO/Socket/SSL.pm"; return } }
    use Mail::MIMEDefang::Mail;
    my $logs = 0;
    { no warnings; *Mail::MIMEDefang::Mail::md_syslog = sub { $logs++ if $_[0] eq "err" }; }
    my @r1 = md_check_against_smtp_server('a@example.com', 'b@example.com', "helo", "127.0.0.1");
    my @r2 = md_check_against_smtp_server('a@example.com', 'b@example.com', "helo", "127.0.0.1");
    print join(",", $r1[0], $r2[0], $logs);
  });
  is($out, 'TEMPFAIL,TEMPFAIL,1', 'TEMPFAIL when IO::Socket::SSL is missing, error logged once');
}

sub t_mimedefang_version : Test(1)
{
  like(md_version(), qr/[0-9]\.[0-9]{1,2}/);
}

sub t_md_get_processing_time : Test(2)
{
  init_globals();
  cmp_ok(md_get_processing_time(), '<', 2, 'elapsed time is near 0 right after init_globals()');
  sleep 1;
  cmp_ok(md_get_processing_time(), '>=', 1, 'elapsed time reflects time passed since init_globals()');
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

sub t_read_commands_file_twice : Test(3)
{
  copy('t/data/COMMANDS', './COMMANDS');
  init_globals();
  read_commands_file();
  copy('t/data/COMMANDS', './COMMANDS');
  my @warnings;
  no warnings qw(redefine once);
  local *::md_syslog = sub { push @warnings, $_[1] if $_[0] eq 'warning' };
  use warnings qw(redefine once);
  read_commands_file();
  is($SubjectCount, 1,   'SubjectCount is 1 after second call');
  is($Subject, 'Subject','Subject is correct after second call');
  is(scalar @warnings, 0,'no spurious Subject warning on second call');
  unlink('./COMMANDS');
}

__PACKAGE__->runtests();
