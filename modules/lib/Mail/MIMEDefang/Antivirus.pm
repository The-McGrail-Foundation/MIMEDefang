#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus - Antivirus interface methods for email filters

=head1 DESCRIPTION

Mail::MIMEDefang::Antivirus are a set of methods that can be called
from F<mimedefang-filter> to scan with installed antivirus
software the email message.

The C<message_contains_virus*> methods scan the F<Work> directory, which
normally contains only the unpacked, decoded parts of the message.
To have the original, undecoded message scanned as well, call
C<md_copy_orig_msg_to_work_dir_as_mbox_file> (see L<Mail::MIMEDefang::Utils>)
B<before> calling C<message_contains_virus> or any
C<message_contains_virus_*> method. It copies the message into the
F<Work> directory as a UNIX-style mbox file, which some scanners
(such as ClamAV) need in order to recognise it as an e-mail message.

    sub filter_end {
      my ($entity) = @_;
      md_copy_orig_msg_to_work_dir_as_mbox_file();
      my ($code, $category, $action) = message_contains_virus();
      ...
    }

Scanner support is loaded on demand.  This module only holds the dispatch
logic and the list of known scanners; the code that talks to each scanner
lives in L<Mail::MIMEDefang::Antivirus::ClamAV>, L<Mail::MIMEDefang::Antivirus::NAI>
and in the C<Mail::MIMEDefang::Antivirus::Legacy::*> modules, and is compiled the
first time that scanner is initialized or used.  The original function
names (C<message_contains_virus_clamd>, C<interpret_nai_code>, ...) are
still provided by this module, so filters do not need to change.

=back

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Antivirus;

use strict;
use warnings;

use Mail::MIMEDefang;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(message_contains_virus entity_contains_virus
             initialize_virus_scanner_routines run_virus_scanner
             entity_contains_virus_avp entity_contains_virus_bdc
             entity_contains_virus_nai entity_contains_virus_avp5
             entity_contains_virus_csav entity_contains_virus_fsav
             entity_contains_virus_clamd entity_contains_virus_fprot
             entity_contains_virus_hbedv entity_contains_virus_clamav
             entity_contains_virus_fprotd entity_contains_virus_fpscan
             entity_contains_virus_clamdscan entity_contains_virus_fprotd_v6
             entity_contains_virus_kavscanner entity_contains_virus_carrier_scan
             message_contains_virus_avp message_contains_virus_bdc
             message_contains_virus_nai message_contains_virus_avp5
             message_contains_virus_csav message_contains_virus_fsav
             message_contains_virus_clamd message_contains_virus_fprot
             message_contains_virus_hbedv message_contains_virus_nod32
             message_contains_virus_clamav message_contains_virus_fprotd
             message_contains_virus_fpscan message_contains_virus_clamdscan
             message_contains_virus_fprotd_v6 message_contains_virus_kavscanner
             interpret_avp_code interpret_bdc_code
             interpret_nai_code interpret_avp5_code
             interpret_csav_code interpret_fsav_code
             interpret_nvcc_code interpret_fprot_code
             interpret_hbedv_code interpret_nod32_code
             interpret_sweep_code interpret_trend_code
             interpret_clamav_code interpret_clamav_code
             interpret_fpscan_code interpret_vexira_code
             interpret_savscan_code
             scan_file_using_fprotd_v6 scan_file_using_carrier_scan
            );

# Scanners, in the order in which they are run.  Each row is
# [ $feature, $suffix, $redundant_if, $module ]: the scan routines are
# message_contains_virus_$suffix and entity_contains_virus_$suffix, and
# $module is the part of the implementing module's name that follows
# "Mail::MIMEDefang::Antivirus::".  The scanner is skipped if
# $Features{$redundant_if} is set (a command-line scanner is redundant
# when its daemonized counterpart is available).  Daemonized scanners come
# first, then the command-line ones.
my @SCANNERS = (
  [ 'Virus:CLAMD',       'clamd',         undef,            'ClamAV' ],
  [ 'Virus:CLAMDSCAN',   'clamdscan',     undef,            'ClamAV' ],
  [ 'Virus:SOPHIE',      'sophie',        undef,            'Legacy::Sophos' ],
  [ 'Virus:TROPHIE',     'trophie',       undef,            'Legacy::Trend' ],
  [ 'Virus:SymantecCSS', 'carrier_scan',  undef,            'Legacy::CarrierScan' ],
  [ 'Virus:FPROTD',      'fprotd',        undef,            'Legacy::FProt' ],
  [ 'Virus:FPROTD6',     'fprotd_v6',     undef,            'Legacy::FProt' ],
  [ 'Virus:AVP5',        'avp5',          undef,            'Legacy::Kaspersky' ],
  [ 'Virus:KAVSCANNER',  'kavscanner',    undef,            'Legacy::Kaspersky' ],
  [ 'Virus:CLAMAV',      'clamav',        'Virus:CLAMD',    'ClamAV' ],
  [ 'Virus:AVP',         'avp',           undef,            'Legacy::Kaspersky' ],
  [ 'Virus:NAI',         'nai',           undef,            'NAI' ],
  [ 'Virus:FPROT',       'fprot',         'Virus:FPROTD',   'Legacy::FProt' ],
  [ 'Virus:FPSCAN',      'fpscan',        'Virus:FPROTD6',  'Legacy::FProt' ],
  [ 'Virus:CSAV',        'csav',          undef,            'Legacy::CSAV' ],
  [ 'Virus:FSAV',        'fsav',          undef,            'Legacy::FSAV' ],
  [ 'Virus:HBEDV',       'hbedv',         undef,            'Legacy::HBEDV' ],
  [ 'Virus:BDC',         'bdc',           undef,            'Legacy::BDC' ],
  [ 'Virus:NVCC',        'nvcc',          undef,            'Legacy::NVCC' ],
  [ 'Virus:VEXIRA',      'vexira',        undef,            'Legacy::Vexira' ],
  [ 'Virus:SOPHOS',      'sophos',        'Virus:SOPHIE',   'Legacy::Sophos' ],
  [ 'Virus:SAVSCAN',     'savscan',       undef,            'Legacy::Sophos' ],
  [ 'Virus:TREND',       'trend',         'Virus:TROPHIE',  'Legacy::Trend' ],
  [ 'Virus:NOD32',       'nod32',         undef,            'Legacy::NOD32' ],
);

# The routines provided by each scanner module.  A stub with the original
# name is installed in this package for each of them, so that the names in
# @EXPORT, and calls such as Mail::MIMEDefang::Antivirus::interpret_nai_code(),
# keep working although the code is only compiled when it is first needed.
my %PROVIDES = (
  'ClamAV' => [qw(
     entity_contains_virus_clamav message_contains_virus_clamav
     interpret_clamav_code entity_contains_virus_clamdscan
     message_contains_virus_clamdscan entity_contains_virus_clamd
     message_contains_virus_clamd
  )],
  'Legacy::BDC' => [qw(
     entity_contains_virus_bdc message_contains_virus_bdc
     interpret_bdc_code
  )],
  'Legacy::CSAV' => [qw(
     entity_contains_virus_csav message_contains_virus_csav
     interpret_csav_code
  )],
  'Legacy::CarrierScan' => [qw(
     scan_file_using_carrier_scan entity_contains_virus_carrier_scan
     message_contains_virus_carrier_scan
  )],
  'Legacy::FProt' => [qw(
     scan_file_using_fprotd_v6 entity_contains_virus_fprotd_v6
     message_contains_virus_fprotd_v6 item_contains_virus_fprotd
     entity_contains_virus_fprotd message_contains_virus_fprotd
     entity_contains_virus_fprot message_contains_virus_fprot
     interpret_fprot_code entity_contains_virus_fpscan
     message_contains_virus_fpscan interpret_fpscan_code
  )],
  'Legacy::FSAV' => [qw(
     entity_contains_virus_fsav message_contains_virus_fsav
     interpret_fsav_code
  )],
  'Legacy::HBEDV' => [qw(
     entity_contains_virus_hbedv message_contains_virus_hbedv
     interpret_hbedv_code
  )],
  'Legacy::Kaspersky' => [qw(
     entity_contains_virus_avp5 message_contains_virus_avp5
     interpret_avp5_code entity_contains_virus_kavscanner
     message_contains_virus_kavscanner interpret_kavscanner_code
     entity_contains_virus_avp message_contains_virus_avp
     interpret_avp_code
  )],
  'Legacy::NOD32' => [qw(
     entity_contains_virus_nod32 message_contains_virus_nod32
     interpret_nod32_code
  )],
  'Legacy::NVCC' => [qw(
     entity_contains_virus_nvcc message_contains_virus_nvcc
     interpret_nvcc_code
  )],
  'Legacy::Sophos' => [qw(
     entity_contains_virus_sophos entity_contains_virus_savscan
     message_contains_virus_sophos message_contains_virus_savscan
     interpret_sweep_code interpret_savscan_code
     entity_contains_virus_sophie message_contains_virus_sophie
  )],
  'Legacy::Trend' => [qw(
     entity_contains_virus_trend message_contains_virus_trend
     interpret_trend_code entity_contains_virus_trophie
     message_contains_virus_trophie
  )],
  'Legacy::Vexira' => [qw(
     entity_contains_virus_vexira message_contains_virus_vexira
     interpret_vexira_code
  )],
  'NAI' => [qw(
     entity_contains_virus_nai message_contains_virus_nai
     interpret_nai_code
  )],
);

# Scanners that their vendor has discontinued.  A warning is logged once
# per process when one of them is enabled, because mail is then checked
# against signatures that are no longer updated.
my $NOTICE_FPROT = 'F-Prot reached end of life on 2021-07-31 and no longer receives signature updates';
my $NOTICE_SOPHOS = 'Sophos Anti-Virus for Linux (legacy) reached end of life on 2023-07-20 and no longer receives signature updates';
my %NOTICE = (
  'Virus:FPROT'   => $NOTICE_FPROT,
  'Virus:FPSCAN'  => $NOTICE_FPROT,
  'Virus:FPROTD'  => $NOTICE_FPROT,
  'Virus:FPROTD6' => $NOTICE_FPROT,
  'Virus:FSAV'    => 'F-Secure Linux Security 11 reached end of support on 2020-12-31, and its successor has no fsav command',
  'Virus:SOPHOS'  => $NOTICE_SOPHOS,
  'Virus:SAVSCAN' => $NOTICE_SOPHOS,
  'Virus:HBEDV'   => 'Avira discontinued its Linux products and stopped detection updates in June 2016',
);

my $MODULE_PREFIX = 'Mail::MIMEDefang::Antivirus::';
my %MODULE_LOADED;

# Returns a reference to the table of scanner modules and the routines they
# provide, keyed by full module name.  Used by the regression tests.
sub _scanner_modules {
  return { map { ($MODULE_PREFIX . $_ => [ @{ $PROVIDES{$_} } ]) } keys %PROVIDES };
}

# Compiles a scanner module the first time it is needed.  Returns 1 on
# success, 0 (after logging the error once) if the module cannot be loaded.
sub _load_scanner_module {
  my ($module) = @_;
  return $MODULE_LOADED{$module} if exists $MODULE_LOADED{$module};

  (my $file = "$MODULE_PREFIX$module.pm") =~ s{::}{/}g;
  my $ok = eval { require $file; 1 };
  if (!$ok) {
	  md_syslog('err', "Cannot load virus scanner module $MODULE_PREFIX$module: $@");
  }
  return $MODULE_LOADED{$module} = ($ok ? 1 : 0);
}

# Body of the stubs: load the scanner module, then continue in the real
# routine with the caller's arguments and context.  If the module cannot be
# loaded we fail safe and ask for a temporary failure instead of letting
# the mail through unscanned.
sub _dispatch_to_scanner {
  my ($module, $name) = splice(@_, 0, 2);
  my $code = _load_scanner_module($module) ? "$MODULE_PREFIX$module"->can($name) : undef;
  if (!$code) {
	  return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
  }
  goto &$code;
}

foreach my $scanner_module (sort keys %PROVIDES) {
  foreach my $scanner_sub (@{ $PROVIDES{$scanner_module} }) {
	  my ($module, $name) = ($scanner_module, $scanner_sub);
	  no strict 'refs';  ## no critic (ProhibitNoStrict)
	  *{ __PACKAGE__ . "::$name" } = sub { _dispatch_to_scanner($module, $name, @_) };
  }
}

=item message_contains_virus

Method that scans a message using every installed virus scanner.
C<md_copy_orig_msg_to_work_dir_as_mbox_file> should be called before this
method so that the original message is scanned too (see L</DESCRIPTION>).

=cut

#***********************************************************************
# %PROCEDURE: message_contains_virus
# %ARGUMENTS:
#  None
# %RETURNS:
#  ($code, $category, $action) -- standard virus-scanner return values.
# %DESCRIPTION:
#  Scans message using *every single* installed virus scanner.
#***********************************************************************
sub message_contains_virus {
  my($code, $category, $action);
  $code = 0;
  $category = 'ok';
  $action = 'ok';
  initialize_virus_scanner_routines();

  if (!@VirusScannerMessageRoutines) {
	  return (wantarray ? (0, 'ok', 'ok') : 0);
  }

  my ($scode, $scat, $sact);
  push_status_tag("Running virus scanner");
  foreach my $scanner (@VirusScannerMessageRoutines) {
	  ($scode, $scat, $sact) = &$scanner();
	  if ($scat eq "virus") {
	    pop_status_tag();
	    return (wantarray ? ($scode, $scat, $sact) : $scode);
	  }
	  if ($scat ne "ok") {
	    $code = $scode;
	    $category = $scat;
	    $action = $sact;
	  }
  }
  pop_status_tag();
  return (wantarray ? ($code, $category, $action) : $code);
}

=item entity_contains_virus

Method that scans a C<MIME::Entity> part using every installed virus scanner.

=cut

#***********************************************************************
# %PROCEDURE: entity_contains_virus
# %ARGUMENTS:
#  e -- a MIME::Entity
# %RETURNS:
#  ($code, $category, $action) -- standard virus-scanner return values.
# %DESCRIPTION:
#  Scans entity using *every single* installed virus scanner.
#***********************************************************************
sub entity_contains_virus {
  my($e) = @_;
  my($code, $category, $action);
  $code = 0;
  $category = 'ok';
  $action = 'ok';

  initialize_virus_scanner_routines();
  if (!@VirusScannerEntityRoutines) {
	  return (wantarray ? (0, 'ok', 'ok') : 0);
  }

  my ($scode, $scat, $sact);
  push_status_tag("Running virus scanner");
  foreach my $scanner (@VirusScannerEntityRoutines) {
	  ($scode, $scat, $sact) = &$scanner($e);
	  if ($scat eq "virus") {
	    pop_status_tag();
	    return (wantarray ? ($scode, $scat, $sact) : $scode);
	  }
	  if ($scat ne "ok") {
	    $code = $scode;
	    $category = $scat;
	    $action = $sact;
	  }
  }
  pop_status_tag();
  return (wantarray ? ($code, $category, $action) : $code);
}

=item initialize_virus_scanner_routines

Method that sets C<@VirusScannerMessageRoutines> and
C<@VirusScannerEntityRoutines> to arrays of virus-scanner routines to call,
based on installed scanners.

=cut

#***********************************************************************
# %PROCEDURE: initialize_virus_scanner_routines
# %ARGUMENTS:
#  None
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Sets @VirusScannerMessageRoutines and @VirusScannerEntityRoutines
#  to arrays of virus-scanner routines to call, based on installed
#  scanners.
#***********************************************************************
sub initialize_virus_scanner_routines {
  if ($VirusScannerRoutinesInitialized) {
	  return;
  }
  $VirusScannerRoutinesInitialized = 1;

  foreach my $scanner (@SCANNERS) {
	  my ($feature, $suffix, $redundant_if, $module) = @$scanner;
	  next unless $Features{$feature};
	  next if defined($redundant_if) && $Features{$redundant_if};

	  # Compile the scanner's code now, so that a module which cannot be
	  # loaded is reported at initialization.  The routines below are stubs
	  # that fail safe in that case.
	  _load_scanner_module($module);
	  md_syslog('warning', "$feature: $NOTICE{$feature}") if exists $NOTICE{$feature};
	  push @VirusScannerMessageRoutines, __PACKAGE__->can("message_contains_virus_$suffix");
	  push @VirusScannerEntityRoutines, __PACKAGE__->can("entity_contains_virus_$suffix");
  }
}

=item run_virus_scanner

Method that runs a virus scanner, collecting output in C<$VirusScannerMessages>.

=cut

#***********************************************************************
# %PROCEDURE: run_virus_scanner
# %ARGUMENTS:
#  cmdline -- command to run
#  match -- regular expression to match (default ".*")
# %RETURNS:
#  A three-element list: (exitcode, category, recommended_action)
#  exitcode is actual exit code from scanner
#  category is either "cannot-execute" or "ok"
#  recommended_action is either "tempfail" or "proceed"
# %DESCRIPTION:
#  Runs a virus scanner, collecting output in $VirusScannerMessages
#***********************************************************************
sub run_virus_scanner {
    my($cmd, $match) = @_;
    return (999, 'wrong-context', 'tempfail')
	if (!in_message_context("run_virus_scanner"));
    my($retcode);
    my($msg) = "";
    $CurrentVirusScannerMessage = "";

    $match = ".*" unless defined($match);
    my $scanner;
    unless (open($scanner, "-|", "$cmd")) {
	$msg = "Unable to execute $cmd: $!";
	md_syslog('err', "run_virus_scanner: $msg");
	$VirusScannerMessages .= "$msg\n";
	$CurrentVirusScannerMessage = $msg;
	return (999, 'cannot-execute', 'tempfail');
    }
    while(<$scanner>) {
	$msg .= $_ if /$match/i;
    }
    close($scanner);
    $retcode = $? / 256;

    # Some daemons are instructed to save output in a file
    my $report;
    if (open($report, "<", "DAEMON.RPT")) {
	while(<$report>) {
	    $msg .= $_ if /$match/i;
	}
	close($report);
	unlink("DAEMON.RPT");
    }

    $VirusScannerMessages .= $msg;
    $CurrentVirusScannerMessage = $msg;
    return ($retcode, 'ok', 'proceed');
}

=back

=cut

1;
