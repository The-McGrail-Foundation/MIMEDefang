package Mail::MIMEDefang::Unit::Antivirus;

use strict;
use warnings;
use lib qw(modules/lib);

# Scanner modules are compiled on first use, when MIMEDefang has already
# changed to the message's work directory (and these tests do too), so
# @INC must not contain relative paths.
use File::Spec;
BEGIN { @INC = map { ref($_) ? $_ : File::Spec->rel2abs($_) } @INC; }

use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Cwd qw(getcwd);
use File::Temp qw(tempdir);
use MIME::Entity;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus;

# Every routine that Mail::MIMEDefang::Antivirus provided before the
# scanner code was split into modules that are loaded on demand.
my @API = qw(
    entity_contains_virus_avp entity_contains_virus_avp5
    entity_contains_virus_bdc entity_contains_virus_carrier_scan
    entity_contains_virus_clamav entity_contains_virus_clamd
    entity_contains_virus_clamdscan entity_contains_virus_csav
    entity_contains_virus_fprot entity_contains_virus_fprotd
    entity_contains_virus_fprotd_v6 entity_contains_virus_fpscan
    entity_contains_virus_fsav entity_contains_virus_hbedv
    entity_contains_virus_kavscanner entity_contains_virus_nai
    entity_contains_virus_nod32 entity_contains_virus_nvcc
    entity_contains_virus_savscan entity_contains_virus_sophie
    entity_contains_virus_sophos entity_contains_virus_trend
    entity_contains_virus_trophie entity_contains_virus_vexira
    interpret_avp5_code interpret_avp_code interpret_bdc_code
    interpret_clamav_code interpret_csav_code interpret_fprot_code
    interpret_fpscan_code interpret_fsav_code interpret_hbedv_code
    interpret_kavscanner_code interpret_nai_code interpret_nod32_code
    interpret_nvcc_code interpret_savscan_code interpret_sweep_code
    interpret_trend_code interpret_vexira_code
    item_contains_virus_fprotd message_contains_virus_avp
    message_contains_virus_avp5 message_contains_virus_bdc
    message_contains_virus_carrier_scan message_contains_virus_clamav
    message_contains_virus_clamd message_contains_virus_clamdscan
    message_contains_virus_csav message_contains_virus_fprot
    message_contains_virus_fprotd message_contains_virus_fprotd_v6
    message_contains_virus_fpscan message_contains_virus_fsav
    message_contains_virus_hbedv message_contains_virus_kavscanner
    message_contains_virus_nai message_contains_virus_nod32
    message_contains_virus_nvcc message_contains_virus_savscan
    message_contains_virus_sophie message_contains_virus_sophos
    message_contains_virus_trend message_contains_virus_trophie
    message_contains_virus_vexira scan_file_using_carrier_scan
    scan_file_using_fprotd_v6
);

my $NS = 'Mail/MIMEDefang/Antivirus/';

sub _loaded
{
  my ($name) = @_;
  return exists $INC{"$NS$name.pm"} ? 1 : 0;
}

sub _routine_suffixes
{
  my ($routines, $prefix) = @_;
  my @out;
  foreach my $r (@$routines) {
    my $found = '?';
    foreach my $name (@API) {
      next unless $name =~ /^\Q$prefix\E(.+)$/;
      my $code = Mail::MIMEDefang::Antivirus->can($name);
      if ($code && $code == $r) { $found = $1; last; }
    }
    push @out, $found;
  }
  return @out;
}

sub _init_with
{
  my (@features) = @_;
  init_globals();
  %Features = map { $_ => 1 } @features;
  @VirusScannerMessageRoutines = ();
  @VirusScannerEntityRoutines = ();
  $VirusScannerRoutinesInitialized = 0;
  initialize_virus_scanner_routines();
  return;
}

sub t_api_is_unchanged : Test(2)
{
  my @missing = grep { !Mail::MIMEDefang::Antivirus->can($_) } @API;
  is_deeply(\@missing, [], 'every original routine is still provided');

  my $modules = Mail::MIMEDefang::Antivirus::_scanner_modules();
  my @provided = sort map { @$_ } values %$modules;
  is_deeply(\@provided,
            [ sort grep { !/^(?:message|entity)_contains_virus$|^initialize_virus_scanner_routines$|^run_virus_scanner$/ } @API ],
            'scanner modules provide exactly the original scanner routines');
}

sub t_modules_provide_their_routines : Test(28)
{
  my $modules = Mail::MIMEDefang::Antivirus::_scanner_modules();
  foreach my $module (sort keys %$modules) {
    (my $file = "$module.pm") =~ s{::}{/}g;
    ok(eval { require $file; 1 }, "$module compiles") or diag($@);
    my @missing = grep { !$module->can($_) } @{ $modules->{$module} };
    is_deeply(\@missing, [], "$module defines all the routines it provides");
  }
}

sub t_no_scanner_loads_nothing : Test(3)
{
  # Runs before any scanner module has been required by another test
  # method only if executed first, so check the module list instead of %INC.
  _init_with();
  is(scalar(@VirusScannerMessageRoutines), 0);
  is(scalar(@VirusScannerEntityRoutines), 0);
  my @r = message_contains_virus();
  is_deeply(\@r, [0, 'ok', 'ok']);
}

sub t_order : Test(2)
{
  # Daemons first, then command-line scanners, regardless of feature order.
  _init_with(qw(Virus:NOD32 Virus:CLAMAV Virus:NAI Virus:SOPHIE Virus:CLAMDSCAN));
  is_deeply([ _routine_suffixes(\@VirusScannerMessageRoutines, 'message_contains_virus_') ],
            [qw(clamdscan sophie clamav nai nod32)]);
  is_deeply([ _routine_suffixes(\@VirusScannerEntityRoutines, 'entity_contains_virus_') ],
            [qw(clamdscan sophie clamav nai nod32)]);
}

sub t_redundant_cli_scanners : Test(4)
{
  _init_with(qw(Virus:CLAMD Virus:CLAMAV));
  is_deeply([ _routine_suffixes(\@VirusScannerMessageRoutines, 'message_contains_virus_') ], ['clamd']);

  _init_with(qw(Virus:FPROTD Virus:FPROT Virus:FPROTD6 Virus:FPSCAN));
  is_deeply([ _routine_suffixes(\@VirusScannerMessageRoutines, 'message_contains_virus_') ],
            [qw(fprotd fprotd_v6)]);

  _init_with(qw(Virus:SOPHIE Virus:SOPHOS));
  is_deeply([ _routine_suffixes(\@VirusScannerMessageRoutines, 'message_contains_virus_') ], ['sophie']);

  _init_with(qw(Virus:TROPHIE Virus:TREND));
  is_deeply([ _routine_suffixes(\@VirusScannerMessageRoutines, 'message_contains_virus_') ], ['trophie']);
}

sub t_discontinued_scanner_notice : Test(7)
{
  my @log;
  no warnings 'redefine';
  local *Mail::MIMEDefang::Antivirus::md_syslog = sub { push @log, [@_] };

  _init_with(qw(Virus:CLAMD Virus:CLAMDSCAN Virus:NAI));
  is(scalar(@log), 0, 'no warning for scanners that are still available');

  @log = ();
  _init_with(qw(Virus:FPROT Virus:FPSCAN));
  is(scalar(@log), 2, 'one warning per enabled discontinued scanner');
  is($log[0][0], 'warning', 'logged as a warning');
  like($log[0][1], qr/^Virus:FPROT: F-Prot reached end of life on 2021-07-31/, 'F-Prot');

  @log = ();
  _init_with(qw(Virus:FPROTD Virus:FPROT));
  is(scalar(@log), 1, 'a scanner skipped as redundant is not reported');

  @log = ();
  _init_with(qw(Virus:FSAV Virus:SOPHOS Virus:SAVSCAN Virus:HBEDV));
  is(scalar(@log), 4, 'F-Secure, Sophos and Avira are reported');

  @log = ();
  _init_with(qw(Virus:FPROT));
  initialize_virus_scanner_routines();
  is(scalar(@log), 1, 'reported once, not on every call');
}

# These checks need a pristine interpreter, so run them in a child process.
sub t_lazy_loading : Test(7)
{
  my $script = <<'PERL';
use strict; use warnings;
use lib 'modules/lib';
use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus;
my $ns = 'Mail/MIMEDefang/Antivirus/';
sub n { scalar grep { index($_, $ns) == 0 } keys %INC }
print "after use: ", n(), "\n";
%Features = ('Virus:CLAMAV' => '/bin/true');
initialize_virus_scanner_routines();
print "after init clamav: ", n(), " clamav=", (exists $INC{"${ns}ClamAV.pm"} ? 1 : 0),
      " nai=", (exists $INC{"${ns}NAI.pm"} ? 1 : 0), "\n";
my @r = Mail::MIMEDefang::Antivirus::interpret_nai_code(0);
print "after call nai: nai=", (exists $INC{"${ns}NAI.pm"} ? 1 : 0),
      " bdc=", (exists $INC{"${ns}Legacy/BDC.pm"} ? 1 : 0), " result=@r\n";
PERL
  my $dir = tempdir(CLEANUP => 1);
  my $file = "$dir/lazy.pl";
  open my $fh, '>', $file or die "open: $!";
  print $fh $script;
  close $fh;
  my $out = `$^X $file 2>&1`;
  like($out, qr/^after use: 0$/m, 'no scanner code is compiled just by loading the module');
  like($out, qr/^after init clamav: 1 clamav=1 nai=0$/m, 'only the enabled scanner is compiled at initialization');
  like($out, qr/^after call nai: nai=1 bdc=0 result=0 ok ok$/m, 'a legacy scanner is compiled on its first use, through the original name');
  unlike($out, qr/Cannot load|Undefined|Can't/, 'no errors');

  # Failing to compile a scanner module must never let mail through unscanned.
  my @l = Mail::MIMEDefang::Antivirus::_dispatch_to_scanner('Legacy::DoesNotExist', 'entity_contains_virus_x');
  is_deeply(\@l, [1, 'not-installed', 'tempfail'], 'list context');
  my $s = Mail::MIMEDefang::Antivirus::_dispatch_to_scanner('Legacy::DoesNotExist', 'entity_contains_virus_x');
  is($s, 1, 'scalar context');
  my @same = Mail::MIMEDefang::Antivirus::_dispatch_to_scanner('Legacy::DoesNotExist', 'entity_contains_virus_x');
  is_deeply(\@same, \@l, 'repeated calls do not try to load it again');
}

sub t_end_to_end_with_fake_scanners : Test(8)
{
  my $cwd = getcwd();
  my $dir = tempdir(CLEANUP => 1);
  chdir $dir or die "chdir: $!";
  mkdir 'Work';

  my $fake = "$dir/fake-scanner";
  open my $fh, '>', $fake or die;
  print $fh "#!/bin/sh\nprintf '%s\\n' \"\$FAKE_MSG\"\nexit \$FAKE_CODE\n";
  close $fh;
  chmod 0755, $fake;

  open my $data, '>', "$dir/Work/body.txt" or die;
  print $data "hello\n";
  close $data;
  my $entity = MIME::Entity->build(Type => 'text/plain', Path => "$dir/Work/body.txt");

  my @cases = (
    # feature   suffix  exit  output                        expected                         VirusName
    [ 'CLAMAV', 'clamav', 1,  'Work/x: Eicar-Test FOUND',    [1, 'virus', 'quarantine'],      'Eicar-Test' ],
    [ 'CLAMAV', 'clamav', 0,  '',                            [0, 'ok', 'ok'],                 '' ],
    [ 'NAI',    'nai',    13, 'Found: EICAR test file',      [13, 'virus', 'quarantine'],     'EICAR-Test' ],
    [ 'NAI',    'nai',    2,  '',                            [2, 'swerr', 'tempfail'],        '' ],
  );
  foreach my $c (@cases) {
    my ($feature, $suffix, $code, $output, $expected, $virus) = @$c;
    init_globals();
    $InMessageContext = 1;
    %Features = ("Virus:$feature" => $fake);
    $ENV{FAKE_CODE} = $code;
    $ENV{FAKE_MSG} = $output;
    $VirusName = '';
    my $msg_sub = Mail::MIMEDefang::Antivirus->can("message_contains_virus_$suffix");
    my @got = $msg_sub->();
    is_deeply(\@got, $expected, "message_contains_virus_$suffix, exit $code");
    my $ent_sub = Mail::MIMEDefang::Antivirus->can("entity_contains_virus_$suffix");
    my @got_e = $ent_sub->($entity);
    is_deeply(\@got_e, $expected, "entity_contains_virus_$suffix, exit $code");
  }
  chdir $cwd or die "chdir: $!";
}

__PACKAGE__->runtests();
