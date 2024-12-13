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

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Antivirus;

use strict;
use warnings;

use IO::Socket;

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

=item message_contains_virus

Method that scans a message using every installed virus scanner.

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

  # The daemonized scanners first
  if ($Features{'Virus:CLAMD'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_clamd;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_clamd;
  }

  if ($Features{'Virus:CLAMDSCAN'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_clamdscan;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_clamdscan;
  }

  if ($Features{'Virus:SOPHIE'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_sophie;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_sophie;
  }

  if ($Features{'Virus:TROPHIE'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_trophie;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_trophie;
  }

  if ($Features{'Virus:SymantecCSS'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_carrier_scan;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_carrier_scan;
  }

  if ($Features{'Virus:FPROTD'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_fprotd;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_fprotd;
  }

  if ($Features{'Virus:FPROTD6'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_fprotd_v6;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_fprotd_v6;
  }

  if ($Features{'Virus:AVP5'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_avp5;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_avp5;
  }

  if ($Features{'Virus:KAVSCANNER'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_kavscanner;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_kavscanner;
  }

  # Finally the command-line scanners
  if ($Features{'Virus:CLAMAV'} && ! $Features{'Virus:CLAMD'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_clamav;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_clamav;
  }

  if ($Features{'Virus:AVP'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_avp;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_avp;
  }

  if ($Features{'Virus:NAI'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_nai;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_nai;
  }

  if ($Features{'Virus:FPROT'} && !$Features{'Virus:FPROTD'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_fprot;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_fprot;
  }

  if ($Features{'Virus:FPSCAN'} && !$Features{'Virus:FPROTD6'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_fpscan;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_fpscan;
  }

  if ($Features{'Virus:CSAV'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_csav;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_csav;
  }

  if ($Features{'Virus:FSAV'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_fsav;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_fsav;
  }

  if ($Features{'Virus:HBEDV'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_hbedv;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_hbedv;
  }

  if ($Features{'Virus:BDC'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_bdc;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_bdc;
  }

  if ($Features{'Virus:NVCC'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_nvcc;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_nvcc;
  }

  if ($Features{'Virus:VEXIRA'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_vexira;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_vexira;
  }

  if ($Features{'Virus:SOPHOS'} && ! $Features{'Virus:SOPHIE'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_sophos;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_sophos;
  }

  if ($Features{'Virus:SAVSCAN'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_savscan;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_savscan;
  }

  if ($Features{'Virus:TREND'} && ! $Features{'Virus:TROPHIE'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_trend;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_trend;
  }

  if ($Features{'Virus:NOD32'}) {
	  push @VirusScannerMessageRoutines, \&message_contains_virus_nod32;
	  push @VirusScannerEntityRoutines, \&entity_contains_virus_nod32;
  }
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_nai
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by NAI uvscan; 0 otherwise.
# %DESCRIPTION:
#  Runs the NAI Virus Scan program on the entity. (http://www.nai.com)
#***********************************************************************
sub entity_contains_virus_nai {

    unless ($Features{'Virus:NAI'}) {
	md_syslog('err', "NAI Virus Scan not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run uvscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:NAI'} . " --mime --noboot --secure --allole $path 2>&1", "Found");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }

    # UVScan return codes
    return (wantarray ? interpret_nai_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_nai
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the NAI Virus Scan program on the working directory
#***********************************************************************
sub message_contains_virus_nai {

    unless ($Features{'Virus:NAI'}) {
	md_syslog('err', "NAI Virus Scan not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run uvscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:NAI'} . " --noboot --secure --mime --allole ./Work 2>&1", "Found");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    # UVScan return codes
    return (wantarray ? interpret_nai_code($code) : $code);
}

sub interpret_nai_code {
    # Info from Anthony Giggins
    my($code) = @_;
    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Driver integrity check failed
    return ($code, 'swerr', 'tempfail') if ($code == 2);

    # "A general problem occurred" -- idiot Windoze programmers...
    return ($code, 'swerr', 'tempfail') if ($code == 6);

    # Could not find a driver
    return ($code, 'swerr', 'tempfail') if ($code == 8);

    # Scanner tried to clean a file, but it failed
    return ($code, 'swerr', 'tempfail') if ($code == 12);

    # Virus found
    if ($code == 13) {
	# Sigh... stupid NAI can't have a standard message.  Go through
	# hoops to get virus name.
	my $cm = $CurrentVirusScannerMessage;
	$cm =~ s/ !+//;
	$cm =~ s/!+//;
	if ($VirusName eq "") {
	    $VirusName = "EICAR-Test"
		if ($cm =~ m/Found: EICAR test file/i);
	}
	if ($VirusName eq "") {
	    $VirusName = $1
		if ($cm =~ m/^\s+Found the (\S+) .*virus/i);
	}
	if ($VirusName eq "") {
	    $VirusName = $1
		if ($cm =~ m/Found the (.*) trojan/i);
	}
	if ($VirusName eq "") {
	    $VirusName = $1
		if ($cm =~ m/Found .* or variant (.*)/i);
	}
	$VirusName = "unknown-NAI-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Self-check failed
    return ($code, 'swerr', 'tempfail') if ($code == 19);

    # User quit using --exit-on-error
    return ($code, 'interrupted', 'tempfail') if ($code == 102);

    # Unknown exit code
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_bdc
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Bitdefender; 0 otherwise.
# %DESCRIPTION:
#  Runs the Bitdefender program on the entity. (http://www.bitdefender.com)
#***********************************************************************
sub entity_contains_virus_bdc {

    unless($Features{'Virus:BDC'}) {
	md_syslog('err', "Bitdefender not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;
    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    if (! ($path =~ m+^/+)) {
	$path = $CWD . "/" . $path;
    }

    # Run bdc
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:BDC'} . " $path --mail 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_bdc_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_bdc
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Bitdefender program on the working directory
#***********************************************************************
sub message_contains_virus_bdc {

    unless($Features{'Virus:BDC'}) {
	md_syslog('err', "Bitdefender not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run bdc
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:BDC'} . " $CWD/Work --mail --arc 2>&1");
    return (wantarray ? interpret_bdc_code($code) : $code);
}

sub interpret_bdc_code {
    my($code) = @_;

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # If code is not 0 or 1, it's an internal error
    return ($code, 'swerr', 'tempfail') if ($code != 1);

    # Code is 1 -- virus found.
    $VirusName = $1 if ($CurrentVirusScannerMessage =~ m/(?:suspected|infected)\: (\S+)/);
    $VirusName = "unknown-BDC-virus" if $VirusName eq "";

    return ($code, 'virus', 'quarantine');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_csav
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Command Anti-Virus
# %DESCRIPTION:
#  Runs the Command Anti-Virus program. (http://www.commandsoftware.com)
#***********************************************************************
sub entity_contains_virus_csav {

    unless($Features{'Virus:CSAV'}) {
	md_syslog('err', "Command Anti-Virus not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run csav
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CSAV'} . " $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }

    # csav return codes
    return (wantarray ? interpret_csav_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_csav
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Command Anti-Virus program on the working directory
#***********************************************************************
sub message_contains_virus_csav {

    unless($Features{'Virus:CSAV'}) {
	md_syslog('err', "Command Anti-Virus not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run csav
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CSAV'} . " ./Work 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    # csav return codes
    return (wantarray ? interpret_csav_code($code) : $code);
}

sub interpret_csav_code {
    my($code) = @_;
    # OK
    return ($code, 'ok', 'ok') if ($code == 50);

    # Interrupted
    return ($code, 'interrupted', 'tempfail') if ($code == 5);

    # Out of memory
    return ($code, 'swerr', 'tempfail') if ($code == 101);

    # Suspicious files found
    if ($code == 52) {
	$VirusName = 'suspicious';
	return ($code, 'suspicious', 'quarantine');
    }

    # Found a virus
    if ($code == 51) {
	$VirusName = $1 if ($CurrentVirusScannerMessage =~ m/infec.*\: (\S+)/i);
	$VirusName = "unknown-CSAV-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Found a virus and disinfected
    if ($code == 53) {
	$VirusName = "unknown-CSAV-virus disinfected";
	return ($code, 'virus', 'quarantine');
    }

    # Unknown exit code
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_fsav
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by F-Secure Anti-Virus
# %DESCRIPTION:
#  Runs the F-Secure Anti-Virus program. (http://www.f-secure.com)
#***********************************************************************
sub entity_contains_virus_fsav {

    unless($Features{'Virus:FSAV'}) {
	md_syslog('err', "F-Secure Anti-Virus not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run fsav
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:FSAV'} . " --dumb --mime $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }

    # fsav return codes
    return (wantarray ? interpret_fsav_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_fsav
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the F-Secure Anti-Virus program on the working directory
#***********************************************************************
sub message_contains_virus_fsav {

    unless($Features{'Virus:FSAV'}) {
	md_syslog('err', "F-Secure Anti-Virus not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run fsav
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:FSAV'} . " --dumb --mime ./Work 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    # fsav return codes
    return (wantarray ? interpret_fsav_code($code) : $code);
}

sub interpret_fsav_code {
    # Info from David Green
    my($code) = @_;
    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Abnormal termination
    return ($code, 'swerr', 'tempfail') if ($code == 1);

    # Self-test failed
    return ($code, 'swerr', 'tempfail') if ($code == 2);

    # Found a virus
    if ($code == 3 or $code == 6) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/infec.*\: (\S+)/i);
	$VirusName = "unknown-FSAV-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Interrupted
    return ($code, 'interrupted', 'tempfail') if ($code == 5);

    # Out of memory
    return ($code, 'swerr', 'tempfail') if ($code == 7);

    # Suspicious files found
    if ($code == 8) {
	$VirusName = 'suspicious';
	return ($code, 'suspicious', 'quarantine');
    }

    # Unknown exit code
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: scan_file_using_fprotd_v6
# %ARGUMENTS:
#  fname -- name of file to scan
#  host -- host and port on which FPROTD version 6 is listening,
#          eg 127.0.0.1:7777
# %RETURNS:
#  A (code, category, action) triplet.  Sets VirusName if virus found.
# %DESCRIPTION:
#  Asks FPROTD version 6 to scan a file.
#***********************************************************************
sub scan_file_using_fprotd_v6
{
    my($fname, $hname) = @_;

    $hname ||= $Fprotd6Host;
    my($host, $port) = split(/:/, $hname);
    $host ||= '127.0.0.1';
    $port ||= 10200;

    my $connect_timeout = 10;
    my $read_timeout = 60;

    # Convert path to absolute
    if (! ($fname =~ m+^/+)) {
	my($cwd);
	chomp($cwd = `pwd`);
	$fname = $cwd . "/" . $fname;
    }

    my $sock = IO::Socket::INET->new(
	PeerAddr => $host,
	PeerPort => $port,
	Timeout => $connect_timeout);

    unless (defined $sock) {
	md_syslog('warning', "Could not connect to FPROTD6 on $host: $!");
	return (999, 'cannot-execute', 'tempfail');
    }

    if (!$sock->print("SCAN --scanlevel=2 --archive=2 --heurlevel=2 --adware --applications FILE $fname\n") || !$sock->flush()) {
	md_syslog('warning', "Error writing to FPROTD6 on $host: $!");
	$sock->close();
	return (999, 'cannot-execute', 'tempfail');
    }

    my $s = IO::Select->new($sock);
    if (!$s->can_read($read_timeout)) {
	$sock->close();
	md_syslog('warning', "Timeout reading from FPROTD6 daemon on $host");
	return (999, 'cannot-execute', 'tempfail');
    }

    my $resp = $sock->getline();
    $sock->close();
    if (!$resp) {
	md_syslog('warning', "Did not get response from FPROTD6 on $host while scanning $fname");
	return (999, 'cannot-execute', 'tempfail');
    }

    my ($code, $desc, $name);
    unless (($code, $desc, $name) = $resp =~ /\A(\d+)\s<(.*?)>\s(.*)\Z/) {
	md_syslog('warning', "Failed to parse response from FPROTD6 for $fname: $resp");
	return (999, 'cannot-execute', 'tempfail');

    }

    # Clean up $desc
    $desc =~ s/\A(?:contains infected objects|infected):\s//i;

    # Our output should contain:
    # 1) A code.  The code is a bitmask of:
    # bit num Meaning
    #  0   1  At least one virus-infected object was found (and remains).
    #  1   2  At least one suspicious (heuristic match) object was found (and remains).
    #  2   4  Interrupted by user. (SIGINT, SIGBREAK).
    #  3   8  Scan restriction caused scan to skip files (maxdepth directories, maxdepth archives, exclusion list, etc).
    #  4  16  Platform error (out of memory, real I/O errors, insufficient file permission etc.).
    #  5  32  Internal engine error (whatever the engine fails at)
    #  6  64  At least one object was not scanned (encrypted file, unsupported/unknown compression method, corrupted or invalid file).
    #  7 128  At least one object was disinfected (clean now) (treat same as virus for File::VirusScan)
    #
    # 2) The description, including virus name
    #
    # 3) The item name, incl. member of archive etc.  We ignore
    # this for now.

    if($code & (1 | 2 | 128)) {
	$VirusName = $desc;
	$VirusName ||= 'unknown-FPROTD6-virus';
	return ($code, 'virus', 'quarantine');
    } elsif($code & 4) {
	md_syslog('warning', 'FPROTD6 scanning interrupted by user');
	return ($code, 'interrupted', 'tempfail');
    } elsif($code & 16) {
	md_syslog('warning', 'FPROTD6 platform error');
	return ($code, 'swerr', 'tempfail');
    } elsif($code & 32) {
	md_syslog('warning', 'FPROTD6 internal engine error');
	return ($code, 'swerr', 'tempfail');
    }

    return(0, 'ok', 'ok');
}

#***********************************************************************
# %PROCEDURE: scan_file_using_carrier_scan
# %ARGUMENTS:
#  fname -- name of file to scan
#  host -- host and port on which Carrier Scan is listening, eg 127.0.0.1:7777
#          Can optionally have :local or :nonlocal appended to force
#          AVSCANLOCAL or AVSCAN
# %RETURNS:
#  A (code, category, action) triplet.  Sets VirusName if virus found.
# %DESCRIPTION:
#  Asks Symantec CarrierScan Server to scan a file.
#***********************************************************************
sub scan_file_using_carrier_scan {
    my($fname, $hname) = @_;

    my($host, $port, $local) = split(/:/, $hname);
    # If not specified, use local scanning for 127.0.0.1, remote for
    # any other.
    unless(defined($local)) {
	if ($host =~ /^127\.0\.0\.1/) {
	    $local = 1;
	} else {
	    $local = 0;
	}
    }

    # Convert from strings
    if ($local eq "local") {
	$local = 1;
    }
    if ($local eq "nonlocal") {
	$local = 0;
    }

    $port = 7777 unless defined($port);

    # Convert path to absolute
    if (! ($fname =~ m+^/+)) {
	my($cwd);
	chomp($cwd = `pwd`);
	$fname = $cwd . "/" . $fname;
    }
    my $sock = IO::Socket::INET->new("$host:$port");
    my ($line);
    unless (defined $sock) {
	md_syslog('warning', "Could not connect to CarrierScan Server on $host: $!");
	return (999, 'cannot-execute', 'tempfail');
    }

    # Read first line of reply from socket
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    unless ($line =~ /^220/) {
	md_syslog('warning', "Unexpected reply $line from CarrierScan Server");
	$sock->close;
	return (999, 'swerr', 'tempfail');
    }

    # Next line must be version
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    unless ($line eq "2") {
	md_syslog('warning', "Unexpected version $line from CarrierScan Server");
	$sock->close;
	return(999, 'swerr', 'tempfail');
    }

    # Cool; send our stuff!
    my $in;
    if ($local) {
	if (!$sock->print("Version 2\nAVSCANLOCAL\n$fname\n")) {
	    $sock->close;
	    return (999, 'swerr', 'tempfail');
	}
    } else {
	my ($size);
	my ($chunk);
	my ($chunksize, $nread);
	$size = (stat($fname))[7];
	unless(defined($size)) {
	    md_syslog('warning', "Cannot stat $fname: $!");
	    $sock->close;
	    return(999, 'swerr', 'tempfail');
	}
	if (!$sock->print("Version 2\nAVSCAN\n$fname\n$size\n")) {
	    $sock->close;
	    return (999, 'swerr', 'tempfail');
	}
	unless(open($in, "<", "$fname")) {
	    md_syslog('warning', "Cannot open $fname: $!");
	    $sock->close;
	    return(999, 'swerr', 'tempfail');
	}
	while ($size > 0) {
	    if ($size < 8192) {
		$chunksize = $size;
	    } else {
		$chunksize = 8192;
	    }
	    $nread = read($in, $chunk, $chunksize);
	    unless(defined($nread)) {
		md_syslog('warning', "Error reading $fname: $!");
		$sock->close;
                close($in);
		return(999, 'swerr', 'tempfail');
	    }
	    last if ($nread == 0);
	    if (!$sock->print($chunk)) {
		$sock->close;
                close($in);
		return (999, 'swerr', 'tempfail');
	    }
	    $size -= $nread;
	}
	if ($size > 0) {
	    md_syslog('warning', "Error reading $fname: $!");
	    $sock->close;
            close($in);
	    return(999, 'swerr', 'tempfail');
	}
    }
    if (!$sock->flush) {
	$sock->close;
        close($in);
	return (999, 'swerr', 'tempfail');
    }

    # Get reply from server
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    unless ($line =~ /^230/) {
	md_syslog('warning', "Unexpected response to AVSCAN or AVSCANLOCAL command: $line");
	$sock->close;
        close($in);
	return(999, 'swerr', 'tempfail');
    }
    # Get infection status
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    if ($line == 0) {
	$sock->close;
        close($in);
	return (0, 'ok', 'ok');
    }

    # Skip definition date and version, infection count and filename
    chomp($line = $sock->getline); # Definition date
    chomp($line = $sock->getline); # Definition version
    chomp($line = $sock->getline); # Infection count (==1)
    chomp($line = $sock->getline); # Filename

    # Get virus name
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    close($in);
    $sock->close;

    $VirusName = $line;
    return (1, 'virus', 'quarantine');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_carrier_scan
# %ARGUMENTS:
#  entity -- a MIME entity
#  host (optional) -- Symantec CarrierScan host:port
# %RETURNS:
#  Usual virus status
# %DESCRIPTION:
#  Scans the entity using Symantec CarrierScan
#***********************************************************************
sub entity_contains_virus_carrier_scan {
    my($entity) = shift;
    my($host) = $CSSHost;
    $host = shift if (@_ > 0);
    $host = '127.0.0.1:7777:local' if (!defined($host));
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    return scan_file_using_carrier_scan($entity->bodyhandle->path,
					$host);
}

sub entity_contains_virus_fprotd_v6
{
    my($entity, $host) = @_;
    $host ||= $Fprotd6Host;
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    return scan_file_using_fprotd_v6($entity->bodyhandle->path,
				     $host);
}

sub message_contains_virus_fprotd_v6
{
    my($host) = @_;
    $host ||= $Fprotd6Host;

    my $dir;
    if (!opendir($dir, "./Work")) {
	md_syslog('err', "message_contains_virus_fprotd_v6: Could not open ./Work directory: $!");
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Scan all files in Work
    my(@files);
    @files = grep { -f "./Work/$_" } readdir($dir);
    closedir($dir);

    my($code, $category, $action);
    foreach my $file (@files) {
	($code, $category, $action) =
	    scan_file_using_fprotd_v6("Work/$file", $host);
	if ($code != 0) {
	    return (wantarray ? ($code, $category, $action) : $code);
	}
    }
    return (0, 'ok', 'ok');
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_carrier_scan
# %ARGUMENTS:
#  host (optional) -- Symantec CarrierScan host:port
# %RETURNS:
#  Usual virus status
# %DESCRIPTION:
#  Scans the entity using Symantec CarrierScan
#***********************************************************************
sub message_contains_virus_carrier_scan {
    my($host) = $CSSHost;
    $host = shift if (@_ > 0);
    $host = '127.0.0.1:7777:local' if (!defined($host));

    my $dir;
    if (!opendir($dir, "./Work")) {
	md_syslog('err', "message_contains_virus_carrier_scan: Could not open ./Work directory: $!");
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Scan all files in Work
    my(@files);
    @files = grep { -f "./Work/$_" } readdir($dir);
    closedir($dir);

    my($code, $category, $action);
    foreach my $file (@files) {
	($code, $category, $action) =
	    scan_file_using_carrier_scan("Work/$file", $host);
	if ($code != 0) {
	    return (wantarray ? ($code, $category, $action) : $code);
	}
    }
    return (0, 'ok', 'ok');
}

#***********************************************************************
# %PROCEDURE: item_contains_virus_fprotd
# %ARGUMENTS:
#  item -- a file or directory
#  host (optional) -- Fprotd host and base port.
# %RETURNS:
#  Usual virus status
# %DESCRIPTION:
#  Scans the entity using Fprotd scanning daemon
#***********************************************************************
sub item_contains_virus_fprotd {
    my $item = shift;
    my ($host) = $FprotdHost;
    $host = shift if (@_ > 0);
    $host = '127.0.0.1' if (!defined($host));
    my $baseport = 10200;
    if($host =~ /(.*):(.*)/ ) {
	$host = $1;
	$baseport = $2;
    }

    md_syslog('info', "Scan '$item' via F-Protd \@$host:$baseport");
    # The F-Prot demon cannot scan directories, but files only
    # hence, we recurse any directories manually
    if(-d $item) {
	my @result;
	$host .= ":$baseport";
	foreach my $entry (glob("$item/*")) {
	    @result = &item_contains_virus_fprotd($entry, $host);
	    last if $result[0] != 0;
	}
	return (wantarray ? @result : $result[0]);
    }

    # Default error message when reaching end of function
    my $errmsg = "Could not connect to F-Prot Daemon at $host:$baseport";

    # Try 5 ports in order to find an active scanner; they may change the port
    # when they find and spawn an updated demon executable
SEARCH_DEMON: foreach my $port ($baseport..($baseport+4)) {
    my $sock = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port);
    if (defined $sock) {

	# The arguments (following the '?' sign in the HTTP request)
	# are the same as for the command line F-Prot, the additional
	# -remote-dtd suppresses the useless XML DTD prefix
	if (!$sock->print("GET $item?-dumb%20-archive%20-packed%20-remote-dtd HTTP/1.0\n\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}

	# Fetch HTTP Header
	## Maybe dropped, if no validation checks are to be made
	while(my $output = $sock->getline) {
	    if($output =~ /^\s*$/) {
		last;	# break line for XML content
		#### Below here: Validating the protocol
		#### If the protocol is not recognized, it's assumed that the
		#### endpoint is not an F-Prot demon, hence,
		#### the next port is probed.
	    } elsif($output =~ /^HTTP(.*)/) {
		my $h = $1;
		next SEARCH_DEMON unless $h =~ m!/1\.0\s+200\s!;
	    } elsif($output =~ /^Server:\s*(\S*)/) {
		next SEARCH_DEMON if $1 !~ /^fprotd/;
	    }
	}

	# Parsing XML results
	my $xml = HTML::TokeParser->new($sock);
	my $t = $xml->get_tag('fprot-results');
	unless($t) {	# This is an essential tag --> assume a broken demon
	    $errmsg = 'Demon did not return <fprot-results> tag';
	    last SEARCH_DEMON;
	}

	if($t->[1]{'version'} ne '1.0') {
	    $errmsg = "Incompatible F-Protd results version: "
		. $t->[1]{'version'};
	    last SEARCH_DEMON;
	}

	my $curText;	# temporarily accumulated information
	my $virii = '';	# name(s) of virus(es) found
	my $code;	# overall exit code
	my $msg = '';	# accumulated message of virus scanner
	while( $t = $xml->get_token ) {
	    my $tag = $t->[1];
	    if($t->[0] eq 'S') {	# Start tag
		# Accumulate the information temporarily
		# into $curText until the </detected> tag is found
		my $text = $xml->get_trimmed_text;
		# $tag 'filename' of no use in MIMEDefang
		if($tag eq 'name') {
		    $virii .= (length $virii ? " " : "" ) . $text;
		    $curText .= "Found the virus: '$text'\n";
		} elsif($tag eq 'accuracy' || $tag eq 'disinfectable' ||
		        $tag eq 'message') {
		    $curText .= "\t$tag: $text\n";
		} elsif($tag eq 'error') {
		    $msg .= "\nError: $text\n";
		} elsif($tag eq 'summary') {
		    $code = $t->[2]{'code'}
		    if defined $t->[2]{'code'};
		}
	    } elsif($t->[0] eq 'E') {	# End tag
		if($tag eq 'detected') {
		    # move the cached information to the
		    # accumulated message
		    $msg .= "\n$curText" if $curText;
		    undef $curText;
		} elsif($tag eq 'fprot-results') {
		    last;	# security check
		}
	    }
	}
	$sock->close;

## Check the exit code (man f-protd)
## NOTE: These codes are different from the ones of the command line version!
#  0      Not scanned, unable to handle the object.
#  1      Not scanned due to an I/O error.
#  2      Not scanned, as the scanner ran out of memory.
#  3  X   The object is not of a type the scanner knows. This
#         may  either mean it was misidentified or that it is
#         corrupted.
#  4  X   The object was valid, but encrypted and  could  not
#         be scanned.
#  5      Scanning of the object was interrupted.
#  7  X   The  object was identified as an "innocent" object.
#  9  X   The object was successfully scanned and nothing was
#         found.
#  11     The object is infected.
#  13     The object was disinfected.
	unless(defined $code) {
	    $errmsg = "No summary code found";
	    last SEARCH_DEMON;
	}
	if($code < 3 # I/O error, unable to handle, out of mem
	   # any filesystem error less than zero
	   || $code == 5) { # interrupted
	    ## assume this a temporary failure
	    $errmsg = "Scan error #$code: $msg";
		last SEARCH_DEMON;
	}

	if($code > 10) { # infected; (disinfected: Should never happen!)
	    # Add the accumulated information
	    $VirusScannerMessages .= $msg;
	    if ( length $virii ) {
		$VirusName = $virii;
	    } elsif ( $msg =~ /^\tmessage:\s+(\S.*)/m ) {
		$VirusName = $1;
	    } else {
                # no virus name found, log message returned by fprot
                $msg =~ s/\s+/ /g;
                md_syslog('info',
                    qq[$MsgID: cannot extract virus name from f-prot: "$msg"]);
                $VirusName = "unknown";
            }
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	}
###### These codes are left to be handled:
#  3  X   The object is not of a type the scanner knows. This
#         may  either mean it was misidentified or that it is
#         corrupted.
#  4  X   The object was valid, but encrypted and  could  not
#         be scanned.
#  7  X   The  object was identified as an "innocent" object.
#  9  X   The object was successfully scanned and nothing was

#	9 is trivial; 7 is probably trivial
#	4 & 3 we can't do anything really, because if the attachment
#	is some unknown archive format, the scanner wouldn't had known
#	this issue anyway, hence, I consider it "clean"

	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
}

    # Could not connect to daemon or some error occurred during the
    # communication with it
    $errmsg =~ s/\s*\.*\s*\n+\s*/\. /g;
    md_syslog('err', "$errmsg");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_fprotd
# %ARGUMENTS:
#  entity -- a MIME entity
#  host (optional) -- F-Prot Demon host:port
# %RETURNS:
#  1 if entity contains a virus as reported by F-Prot Demon
# %DESCRIPTION:
#  Invokes the F-Prot daemon (http://www.frisk.org/) on
#  the entity.
#***********************************************************************
sub entity_contains_virus_fprotd {
    my ($entity) = shift;

    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    my $path = $entity->bodyhandle->path;
    # If path is not absolute, add cwd
    if (! ($path =~ m+^/+)) {
	$path = $CWD . "/" . $path;
    }
    return item_contains_virus_fprotd($path, $_[0]);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_fprotd
# %ARGUMENTS:
#  host (optional) -- F-Prot Demon host:port
# %RETURNS:
#  1 if entity contains a virus as reported by F-Prot Demon
# %DESCRIPTION:
#  Invokes the F-Prot daemon (http://www.frisk.org/) on
#  the entire message.
#***********************************************************************
sub message_contains_virus_fprotd {
    return item_contains_virus_fprotd ("$CWD/Work", $_[0]);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_hbedv
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by H+BEDV Antivir; 0 otherwise.
# %DESCRIPTION:
#  Runs the H+BEDV Antivir program on the entity. (http://www.hbedv.com)
#***********************************************************************
sub entity_contains_virus_hbedv {

    unless($Features{'Virus:HBEDV'}) {
	md_syslog('err', "H+BEDV not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;
    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:HBEDV'} . " --allfiles -z -rs $path 2>&1", "!Virus!|>>>|VIRUS:|ALERT:");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_hbedv_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_hbedv
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the H+BEDV Antivir program on the working directory
#***********************************************************************
sub message_contains_virus_hbedv {

    unless($Features{'Virus:HBEDV'}) {
	md_syslog('err', "H+BEDV not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:HBEDV'} . " --allfiles -z -rs ./Work 2>&1", "!Virus!|>>>|VIRUS:|ALERT:");
    return (wantarray ? interpret_hbedv_code($code) : $code);
}

sub interpret_hbedv_code {
    # Based on info from Nels Lindquist, updated by
    # Thorsten Schlichting
    my($code) = @_;

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Virus or virus in memory
    if ($code == 1 || $code == 2 || $code == 3) {
	$VirusName = $1 if ($CurrentVirusScannerMessage =~ m/ALERT: \[(\S+)/ or
			    $CurrentVirusScannerMessage =~ /!Virus! \S+ (\S+)/ or
			    $CurrentVirusScannerMessage =~ m/VIRUS: file contains code of the virus '(\S+)'/);
	$VirusName = "unknown-HBEDV-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # All other codes should not happen
    md_syslog('err', "Unknown HBEDV Virus scanner return code: $code");
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_vexira
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Vexira; 0 otherwise.
# %DESCRIPTION:
#  Runs the Vexira program on the entity. (http://www.centralcommand.com)
#***********************************************************************
sub entity_contains_virus_vexira {

    unless($Features{'Virus:VEXIRA'}) {
	md_syslog('err', "Vexira not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;
    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run vexira
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:VEXIRA'} . " -qqq --log=/dev/null --all-files -as $path 2>&1", ": (virus|iworm|macro|mutant|sequence|trojan) ");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_vexira_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_vexira
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Vexira program on the working directory
#***********************************************************************
sub message_contains_virus_vexira {

    unless($Features{'Virus:VEXIRA'}) {
	md_syslog('err', "Vexira not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run vexira
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:VEXIRA'} . " -qqq --log=/dev/null --all-files -as ./Work 2>&1", ": (virus|iworm|macro|mutant|sequence|trojan) ");
    return (wantarray ? interpret_vexira_code($code) : $code);
}

sub interpret_vexira_code {
    # http://www.centralcommand.com/ts/dl/pdf/scanner_en_vexira.pdf
    my($code) = @_;

    # OK or new file type we don't understand
    return ($code, 'ok', 'ok') if ($code == 0 or $code == 9);

    # Password-protected ZIP or corrupted file
    if ($code == 3 or $code == 5) {
	$VirusName = 'vexira-password-protected-zip';
	return ($code, 'suspicious', 'quarantine');
    }

    # Virus
    if ($code == 1 or $code == 2) {
	$VirusName = $2 if ($CurrentVirusScannerMessage =~ m/: (virus|iworm|macro|mutant|sequence|trojan) (\S+)/);
	$VirusName = "unknown-Vexira-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # All other codes should not happen
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_sophos
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Sophos Sweep
# %DESCRIPTION:
#  Runs the Sophos Sweep program on the entity.
#***********************************************************************
sub entity_contains_virus_sophos {

    unless($Features{'Virus:SOPHOS'}) {
	md_syslog('err', "Sophos Sweep not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;
    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:SOPHOS'} . " -f -mime -all -archive -ss $path 2>&1", "(>>> Virus)|(Password)|(Could not check)");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_sweep_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_savscan
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Sophos Savscan
# %DESCRIPTION:
#  Runs the Sophos Savscan program on the entity.
#***********************************************************************
sub entity_contains_virus_savscan {

    unless($Features{'Virus:SAVSCAN'}) {
	md_syslog('err', "Sophos Savscan not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;
    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:SAVSCAN'} . " -f -mime -all -cab -oe -tnef -archive -ss $path 2>&1", "(>>> Virus)|(Password)|(Could not check)");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_savscan_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_sophos
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Sophos Sweep program on the working directory
#***********************************************************************
sub message_contains_virus_sophos {

    unless($Features{'Virus:SOPHOS'}) {
	md_syslog('err', "Sophos Sweep not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:SOPHOS'} . " -f -mime -all -archive -ss ./Work 2>&1", "(>>> Virus)|(Password)|(Could not check)");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_sweep_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_savscan
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Sophos Savscan program on the working directory
#***********************************************************************
sub message_contains_virus_savscan {

    unless($Features{'Virus:SAVSCAN'}) {
	md_syslog('err', "Sophos Savscan not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:SAVSCAN'} . " -f -mime -all -cab -oe -tnef -archive -ss ./Work 2>&1", "(>>> Virus)|(Password)|(Could not check)");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_savscan_code($code) : $code);
}

sub interpret_sweep_code {
    # Based on info from Nicholas Brealey
    my($code) = @_;

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Interrupted
    return ($code, 'interrupted', 'tempfail') if ($code == 1);

    # This is technically an error code, but Sophos chokes
    # on a lot of M$ docs with this code, so we let it through...
    return (0, 'ok', 'ok') if ($code == 2);

    # Virus
    if ($code == 3) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/^\s*>>> Virus '(\S+)'/);
	$VirusName = "unknown-Sweep-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Unknown code
    return ($code, 'swerr', 'tempfail');
}

sub interpret_savscan_code {
    # Based on info from Nicholas Brealey
    my($code) = @_;

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Interrupted
    return ($code, 'interrupted', 'tempfail') if ($code == 1);

    # This is technically an error code, but Sophos chokes
    # on a lot of M$ docs with this code, so we let it through...
    return (0, 'ok', 'ok') if ($code == 2);

    # Virus
    if ($code == 3) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/^\s*>>> Virus '(\S+)'/);
	$VirusName = "unknown-Savscan-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Unknown code
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_clamav
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by clamav
# %DESCRIPTION:
#  Runs the clamav program on the entity.
#***********************************************************************
sub entity_contains_virus_clamav {
    unless ($Features{'Virus:CLAMAV'}) {
	md_syslog('err', "clamav not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run clamscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CLAMAV'} . " --stdout --no-summary --infected $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_clamav_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_clamav
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the clamscan program on the working directory
#***********************************************************************
sub message_contains_virus_clamav {
    unless ($Features{'Virus:CLAMAV'}) {
	md_syslog('err', "clamav not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run clamscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CLAMAV'} . " -r --stdout --no-summary --infected ./Work 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_clamav_code($code) : $code);
}

sub interpret_clamav_code {
    my($code) = @_;
    # From info obtained from:
    # clamscan(1)

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # virus found
    if ($code == 1) {
	$VirusName = $1 if ($CurrentVirusScannerMessage =~ m/: (.+) FOUND/);
	$VirusName = "unknown-Clamav-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # other codes
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_clamdscan
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by clamdscan
# %DESCRIPTION:
#  Runs the clamdscan program on the entity.
#***********************************************************************
sub entity_contains_virus_clamdscan {
    unless ($Features{'Virus:CLAMDSCAN'}) {
	md_syslog('err', "clamav not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run clamdscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CLAMDSCAN'} . " -c " . $Features{'Path:CLAMDCONF'} . " --no-summary --infected --fdpass --stream $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_clamav_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_clamdscan
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the clamdscan program on the working directory
#***********************************************************************
sub message_contains_virus_clamdscan {
    unless ($Features{'Virus:CLAMDSCAN'}) {
	md_syslog('err', "clamav not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run clamdscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CLAMDSCAN'} . " -c " . $Features{'Path:CLAMDCONF'} . " --no-summary --infected --fdpass --stream ./Work 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_clamav_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_avp5
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Kaspersky 5.x
# %DESCRIPTION:
#  Runs the Kaspersky 5.x aveclient program on the entity.
#***********************************************************************
sub entity_contains_virus_avp5 {
    unless ($Features{'Virus:AVP5'}) {
	md_syslog('err', "Kaspersky aveclient not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run aveclient
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:AVP5'} . " -s -p /var/run/aveserver $path 2>&1","INFECTED");

    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_avp5_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_avp5
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Kaspersky 5.x aveclient program on the working directory
#***********************************************************************
sub message_contains_virus_avp5 {
    unless ($Features{'Virus:AVP5'}) {
	md_syslog('err', "Kaspersky aveclient not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run aveclient
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:AVP5'} . " -s -p /var/run/aveserver $CWD/Work/* 2>&1","INFECTED");

    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_avp5_code($code) : $code);
}

sub interpret_avp5_code {
    my($code) = @_;
    # From info obtained from:
    # man aveclient (/opt/kav/man/aveclient.8)

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Scan incomplete
    return ($code, 'interrupted', 'tempfail') if ($code == 1);

    # "modified or damaged virus" = 2; virus = 4
    if ($code == 2 or $code == 4) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/INFECTED (\S+)/);
	$VirusName = "unknown-AVP5-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # "suspicious" object found
    if ($code == 3) {
	$VirusName = 'suspicious';
	return ($code, 'suspicious', 'quarantine');
    }

    # Disinfected ??
    return ($code, 'ok', 'ok') if ($code == 5);

    # Viruses deleted ??
    return ($code, 'ok', 'ok') if ($code == 6);

    # AVPLinux corrupt or infected
    return ($code, 'swerr', 'tempfail') if ($code == 7);

    # Corrupt objects found -- treat as suspicious
    if ($code == 8) {
	$VirusName = 'suspicious';
	return ($code, 'suspicious', 'quarantine');
    }

    # Anything else shouldn't happen
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_kavscanner
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Kaspersky kavscanner
# %DESCRIPTION:
#  Runs the Kaspersky kavscanner program on the entity.
#***********************************************************************
sub entity_contains_virus_kavscanner {
    unless ($Features{'Virus:KAVSCANNER'}) {
	md_syslog('err', "Kaspersky kavscanner not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run kavscanner
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:KAVSCANNER'} . " -e PASBME -o syslog -i0 $path 2>&1",
						      "INFECTED");

    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_kavscanner_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_kavscanner
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Kaspersky 5.x aveclient program on the working directory
#***********************************************************************
sub message_contains_virus_kavscanner {
    unless ($Features{'Virus:KAVSCANNER'}) {
	md_syslog('err', "Kaspersky aveclient not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run kavscanner
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:KAVSCANNER'} . " -e PASBME -o syslog -i0 $CWD/Work/* 2>&1",
						      "INFECTED");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_kavscanner_code($code) : $code);
}

sub interpret_kavscanner_code {
    my($code) = @_;
    # From info obtained from:
    # man kavscanner (/opt/kav/man/kavscanner.8)

    # OK
    return ($code, 'ok', 'ok') if ($code == 0 or $code == 5 or $code == 10);

    # Password-protected ZIP
    if ($code == 9) {
	    $VirusName = 'kavscanner-password-protected-zip';
	    return ($code, 'suspicious', 'quarantine');
    }

    # Virus or suspicious TODO: Set virus name
    if ($code == 20 or $code == 21 or $code == 25) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/INFECTED (\S+)/);
	$VirusName = 'unknown-kavscanner-virus' if $VirusName eq "";
	if ($code == 20) {
	    return ($code, 'suspicious', 'quarantine');
	} else {
	    return ($code, 'virus', 'quarantine');
	}
    }

    # Something else
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_avp
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by AVP AvpLinux
# %DESCRIPTION:
#  Runs the AvpLinux program on the entity.
#***********************************************************************
sub entity_contains_virus_avp {

    unless ($Features{'Virus:AVP'}) {
	md_syslog('err', "AVP AvpLinux not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($is_daemon);
    $is_daemon = ($Features{'Virus:AVP'} =~ /kavdaemon$/);
    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action);
    if ($is_daemon) {
	# If path is not absolute, add cwd
	if (! ($path =~ m+^/+)) {
	    $path = $CWD . "/" . $path;
	}
	($code, $category, $action) =
	    run_virus_scanner($Features{'Virus:AVP'} . " $CWD -o{$path} -dl -Y -O- -K -I0 -WU=$CWD/DAEMON.RPT 2>&1", "infected");
    } else {
	($code, $category, $action) =
	    run_virus_scanner($Features{'Virus:AVP'} . " -Y -O- -K -I0 $path 2>&1", "infected");
    }
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_avp_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_avp
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the AVP AvpLinux program on the working directory
#***********************************************************************
sub message_contains_virus_avp {

    unless ($Features{'Virus:AVP'}) {
	md_syslog('err', "AVP AvpLinux not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($is_daemon);
    $is_daemon = ($Features{'Virus:AVP'} =~ /kavdaemon$/);

    # Run antivir
    my($code, $category, $action);
    if ($is_daemon) {
	($code, $category, $action) =
	    run_virus_scanner($Features{'Virus:AVP'} . " $CWD -o{$CWD/Work} -dl -Y -O- -K -I0 -WU=$CWD/DAEMON.RPT 2>&1", "infected");
    } else {
	($code, $category, $action) =
	    run_virus_scanner($Features{'Virus:AVP'} . " -Y -O- -K -I0 ./Work 2>&1", "infected");
    }
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_avp_code($code) : $code);
}

sub interpret_avp_code {
    my($code) = @_;
    # From info obtained from:
    # http://sm.msk.ru/patches/violet-avp-sendmail-11.4.patch
    # and from Steve Ladendorf

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Scan incomplete
    return ($code, 'interrupted', 'tempfail') if ($code == 1);

    # "modified or damaged virus" = 2; virus = 4
    if ($code == 2 or $code == 4) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/infected\: (\S+)/);
	$VirusName = "unknown-AVP-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # "suspicious" object found
    if ($code == 3) {
	$VirusName = 'suspicious';
	return ($code, 'suspicious', 'quarantine');
    }

    # Disinfected ??
    return ($code, 'ok', 'ok') if ($code == 5);

    # Viruses deleted ??
    return ($code, 'ok', 'ok') if ($code == 6);

    # AVPLinux corrupt or infected
    return ($code, 'swerr', 'tempfail') if ($code == 7);

    # Corrupt objects found -- treat as suspicious
    if ($code == 8) {
	$VirusName = 'suspicious';
	return ($code, 'suspicious', 'quarantine');
    }

    # Anything else shouldn't happen
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_fprot
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by FRISK F-Prot; 0 otherwise.
# %DESCRIPTION:
#  Runs the F-PROT program on the entity. (http://www.f-prot.com)
#***********************************************************************
sub entity_contains_virus_fprot {
    unless ($Features{'Virus:FPROT'}) {
	md_syslog('err', "F-RISK FPROT not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run f-prot
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:FPROT'} . " -DUMB -ARCHIVE -PACKED $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }

    # f-prot return codes
    return (wantarray ? interpret_fprot_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_fprot
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the F-RISK f-prot program on the working directory
#***********************************************************************
sub message_contains_virus_fprot {
    unless ($Features{'Virus:FPROT'}) {
	md_syslog('err', "F-RISK f-prot not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run f-prot
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:FPROT'} . " -DUMB -ARCHIVE -PACKED ./Work 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    # f-prot return codes
    return (wantarray ? interpret_fprot_code($code) : $code);
}

sub interpret_fprot_code {
    # Info from
    my($code) = @_;
    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Unrecoverable error (Missing DAT, etc)
    return ($code, 'swerr', 'tempfail') if ($code == 1);

    # Driver integrity check failed
    return ($code, 'swerr', 'tempfail') if ($code == 2);

    # Virus found
    if ($code == 3) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/Infection\: (\S+)/);
	$VirusName = "unknown-FPROT-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Reserved for now. Treat as an error
    return ($code, 'swerr', 'tempfail') if ($code == 4);

    # Abnormal termination (scan didn't finish)
    return ($code, 'swerr', 'tempfail') if ($code == 5);

    # At least one virus removed - Should not happen as we aren't
    # requesting disinfection ( at least in this version).
    return ($code, 'swerr', 'tempfail') if ($code == 6);

    # Memory error
    return ($code, 'swerr', 'tempfail') if ($code == 7);

    # Something suspicious was found, but not recognized virus
    # ( uncomment the one your paranoia dictates :) ).
#    return ($code, 'virus', 'quarantine') if ($code == 8);
    return ($code, 'ok', 'ok') if ($code == 8);

    # Unknown exit code
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_fpscan
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by FRISK F-Prot; 0 otherwise.
# %DESCRIPTION:
#  Runs the F-PROT program on the entity. (http://www.f-prot.com)
#***********************************************************************
sub entity_contains_virus_fpscan {
    unless ($Features{'Virus:FPSCAN'}) {
        md_syslog('err', "F-RISK fpscan not installed on this system");
        return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
        return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
        return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run f-prot
    my($code, $category, $action) =
        run_virus_scanner($Features{'Virus:FPSCAN'} . " --report --archive=5  --scanlevel=4 --heurlevel=3 $path 2>&1");
    if ($action ne 'proceed') {
        return (wantarray ? ($code, $category, $action) : $code);
    }

    # f-prot return codes
    return (wantarray ? interpret_fpscan_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_fpscan
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the F-RISK f-prot program on the working directory
#***********************************************************************
sub message_contains_virus_fpscan {
    unless ($Features{'Virus:FPSCAN'}) {
        md_syslog('err', "F-RISK fpscan not installed on this system");
        return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run f-prot
    my($code, $category, $action) =
        run_virus_scanner($Features{'Virus:FPSCAN'} . " --report --archive=5  --scanlevel=4 --heurlevel=3 ./Work 2>&1");
    if ($action ne 'proceed') {
        return (wantarray ? ($code, $category, $action) : $code);
    }
    # f-prot return codes
    return (wantarray ? interpret_fpscan_code($code) : $code);
}

sub interpret_fpscan_code {
    # Info from
    my($code) = @_;

    # Set to 1 to mark heuristic matches as a virus
    my $heuristic_virus = 0;
    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # bit 1 (1)   ==> At least one virus-infected object was found (and
    #                 remains).
    if ($code & 0b1) {
        $VirusName = $1
            if ($CurrentVirusScannerMessage =~ m/^\[Found\s+[^\]]*\]\s+<([^ \t\(>]*)/m);
        $VirusName = "unknown-FPSCAN-virus" if $VirusName eq "";
        return ($code, 'virus', 'quarantine');
    }

    if ($heuristic_virus and $code & 0b10) {
        return ($code, 'virus', 'quarantine');
    }

    # bit 3 (4)   ==> Interrupted by user (SIGINT, SIGBREAK).
    if ($code & 0b100) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 4 (8)   ==> Scan restriction caused scan to skip files
    #                 (maxdepth directories, maxdepth archives,
    #                 exclusion list, etc).

    if ($code & 0b1000) {
        return ($code, 'swerr', 'tempfail');
    }
    # bit 5 (16)  ==> Platform error (out of memory, real I/O errors,
    #                 insufficient file permission etc.)

    if ($code & 0b10000) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 6 (32)  ==> Internal engine error (whatever the engine fails
    #                 at)
    if ($code & 0b100000) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 7 (64)  ==> At least one object was not scanned (encrypted
    #                 file, unsupported/unknown compression method,
    #                 corrupted or invalid file).
    if ($code & 0b1000000) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 8 (128) ==> At least one object was disinfected (clean now).
    # Should not happen as we aren't requesting disinfection ( at least
    # in this version).
    if ($code & 0b10000000) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 2 (2)   ==> At least one suspicious (heuristic match) object
    #                 was found (and remains).
    if ($code & 0b10) {
    # ( uncomment the one your paranoia dictates :) ).
        return ($code, 'ok', 'ok');
    }

    # Unknown exit code, this should never happen
    return ($code, 'swerr', 'tempfail');
}


#***********************************************************************
# %PROCEDURE: entity_contains_virus_trend
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Trend Micro vscan
# %DESCRIPTION:
#  Runs the vscan program on the entity.
#***********************************************************************
sub entity_contains_virus_trend {
    unless ($Features{'Virus:TREND'}) {
	md_syslog('err', "TREND vscan not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = @_;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:TREND'} . " -za -a $path 2>&1", "Found ");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_trend_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_trend
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Trend vscan program on the working directory
#***********************************************************************
sub message_contains_virus_trend {
    unless ($Features{'Virus:TREND'}) {
	md_syslog('err', "TREND Filescanner or Interscan  not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run vscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:TREND'} . " -za -a ./Work/* 2>&1", "Found ");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_trend_code($code) : $code);
}

sub interpret_trend_code {
    my($code) = @_;
    # From info obtained from:
    # http://cvs.sourceforge.net/cgi-bin/viewcvs.cgi/amavis/amavis/README.scanners

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # virus found
    if ($code >= 1 and $code < 10) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/^\*+ Found virus (\S+)/);
	$VirusName = "unknown-Trend-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Anything else shouldn't happen
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_nvcc
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Norman Virus Control(NVCC)
# %DESCRIPTION:
#  Runs the NVCC Anti-Virus program. (http://www.norman.no/)
#***********************************************************************
sub entity_contains_virus_nvcc {

    unless($Features{'Virus:NVCC'}) {
	md_syslog('err', "Norman Virus Control (NVCC) not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    my($entity) = shift;
    my($body) = $entity->bodyhandle;

    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }

    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Run nvcc
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:NVCC'} . " -u -c $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }

    # nvcc return codes
    return (wantarray ? interpret_nvcc_code($code) : ($code==1 || $code==2));
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_nvcc
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the NVCC Anti-Virus program on the working directory.
#  (http://www.norman.no/)
#***********************************************************************
sub message_contains_virus_nvcc {

    unless($Features{'Virus:NVCC'}) {
	md_syslog('err', "Norman Virus Control (NVCC) not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run nvcc
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:NVCC'} . " -u -c -s ./Work 2>&1");

    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    # nvcc return codes
    return (wantarray ? interpret_nvcc_code($code) : ($code==1 || $code==2));
}

sub interpret_nvcc_code {

    my($code) = shift;

    # OK
    return (0, 'ok', 'ok') if ($code == 0);

    # Found a virus
    if ($code == 1 or $code == 2 or $code == 14) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/Possible virus[^']*'(\S+)'$/);
        #' Emacs highlighting goes nuts with unbalanced single-quote...
	$VirusName = "unknown-NVCC-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Corrupt files/archives found -- treat as suspicious
    if ($code == 11) {
	$VirusName = 'NVCC-suspicious-code-11';
        return ($code, 'suspicious', 'quarantine');
    }

    # No scan area given or something went wrong
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_sophie
# %ARGUMENTS:
#  entity -- a MIME entity
#  sophie_sock (optional) -- Sophie socket path
# %RETURNS:
#  1 if entity contains a virus as reported by Sophie
# %DESCRIPTION:
#  Invokes the Sophie daemon (http://www.vanja.com/tools/sophie/)
#  on the entity.
#***********************************************************************
sub entity_contains_virus_sophie {
    my ($entity) = shift;
    my ($sophie_sock) = $SophieSock;
    $sophie_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 1) if (!defined($sophie_sock));
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    my $sock = IO::Socket::UNIX->new(Peer => $sophie_sock);
    if (defined $sock) {
	my $path = $entity->bodyhandle->path;
	# If path is not absolute, add cwd
	if (! ($path =~ m+^/+)) {
	    $path = $CWD . "/" . $path;
	}
	if (!$sock->print("$path\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	my($output);
	if (!$sock->sysread($output,256)) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->close) {
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if ($output =~ /^0/) { return (wantarray ? (0, 'ok', 'ok') : 0); }
	elsif ($output =~ /^1/) {
	    $VirusName = "Unknown-sophie-virus";
	    $VirusName = $1 if $output =~ /^1:(.*)$/;
	    $VirusScannerMessages .= "Sophie found the $VirusName virus.\n";
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	}
	elsif ($output =~ /^-1/) {
	    my $errmsg = "unknown status";
	    $errmsg = "$1" if $output =~ /^-1:(.*)$/;
	    md_syslog('err', "entity_contains_virus_sophie: $errmsg ($path)");
	    $VirusScannerMessages .= "Sophie error: $errmsg\n";
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	else {
	    md_syslog('err', "entity_contains_virus_sophie: unknown response - $output ($path)");
	    $VirusScannerMessages .= "Sophie error: unknown response - $output\n";
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
    }
    # Could not connect to daemon
    md_syslog('err', "Could not connect to Sophie Daemon at $sophie_sock");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_sophie
# %ARGUMENTS:
#  sophie_sock (optional) -- Sophie socket path
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Invokes the Sophie daemon (http://www.vanja.com/tools/sophie/)
#  on the entire message.
#***********************************************************************
sub message_contains_virus_sophie {
    my ($sophie_sock) = $SophieSock;
    $sophie_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 1) if (!defined($sophie_sock));
    my $sock = IO::Socket::UNIX->new(Peer => $sophie_sock);
    if (defined $sock) {
	if (!$sock->print("$CWD/Work\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	my($output, $ans);
	$ans = $sock->sysread($output, 256);
	if (!defined($ans)) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->close) {
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if ($output =~ /^0/) { return (wantarray ? (0, 'ok', 'ok') : 0); }
	elsif ($output =~ /^1/) {
	    $VirusName = "Unknown-sophie-virus";
	    $VirusName = $1 if $output =~ /^1:(.*)$/;
	    $VirusScannerMessages .= "Sophie found the $VirusName virus.\n";
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	}
	elsif ($output =~ /^-1/) {
	    my $errmsg = "unknown status";
	    $errmsg = "$1" if $output =~ /^-1:(.*)$/;
	    md_syslog('err', "message_contains_virus_sophie: $errmsg ($CWD/Work)");
	    $VirusScannerMessages .= "Sophie error: $errmsg\n";
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	else {
	    md_syslog('err', "message_contains_virus_sophie: unknown response - $output ($CWD/Work)");
	    $VirusScannerMessages .= "Sophie error: unknown response - $output\n";
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
    }
    # Could not connect to daemon
    md_syslog('err', "Could not connect to Sophie Daemon at $sophie_sock");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_clamd
# %ARGUMENTS:
#  entity -- a MIME entity
#  clamd_sock (optional) -- clamd socket path
# %RETURNS:
#  1 if entity contains a virus as reported by clamd
# %DESCRIPTION:
#  Invokes the clamd daemon (http://www.clamav.net/)
#  on the entity.
#***********************************************************************
sub entity_contains_virus_clamd {
    my ($entity) = shift;
    my ($clamd_sock) = $ClamdSock;
    $clamd_sock = shift if (@_ > 0);
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    my $sock = IO::Socket::UNIX->new(Peer => $clamd_sock);
    if (defined $sock) {
	my $path = $entity->bodyhandle->path;
	# If path is not absolute, add cwd
	if (! ($path =~ m+^/+)) {
	    $path = $CWD . "/" . $path;
	}
	if (!$sock->print("SCAN $path\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	my($output, $ans);
	$ans = $sock->sysread($output,256);
	$sock->close;
	if (!defined($ans) || !$ans) {
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if ($output =~ /: (.+) FOUND/) {
	    $VirusScannerMessages .= "clamd found the $1 virus.\n";
	    $VirusName = $1;
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	} elsif ($output =~ /: (.+) ERROR/) {
	    my $err_detail = $1;
	    md_syslog('err', "Clamd returned error: $err_detail");
	    # If it's a zip module failure, try falling back on clamscan.
	    # This is despicable, but it might work
	    if ($err_detail =~ /(?:zip module failure|not supported data format)/i &&
		$Features{'Virus:CLAMAV'}) {
		my ($code, $category, $action) =
		run_virus_scanner($Features{'Virus:CLAMAV'} . " -r --unzip --unrar --stdout --no-summary --infected $CWD/Work 2>&1");
		if ($action ne 'proceed') {
			return (wantarray ? ($code, $category, $action) : $code);
		}
		md_syslog('info', "Falling back on clamscan --unzip --unrar because of Zip module failure in clamd");
		return (wantarray ? interpret_clamav_code($code) : $code);
	    }
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    # Could not connect to daemon
    md_syslog('err', "Could not connect to clamd Daemon at $clamd_sock");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_clamd
# %ARGUMENTS:
#  clamd_sock (optional) -- clamd socket path
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Invokes the clamd daemon (http://www.clamav.net/)
#  on the entire message.
#***********************************************************************
sub message_contains_virus_clamd {
    my ($clamd_sock) = $ClamdSock;
    $clamd_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 1) if (!defined($clamd_sock));
    my ($output,$sock);

    # PING/PONG test to make sure clamd is alive
    $sock = IO::Socket::UNIX->new(Peer => $clamd_sock);

    if (!defined($sock)) {
	md_syslog('err', "Could not connect to clamd daemon at $clamd_sock");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    my $s = IO::Select->new();
    $s->add($sock);
    if (!$s->can_write(30)) {
	$sock->close;
	md_syslog('err', "Timeout writing to clamd daemon at $clamd_sock");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    $sock->print("PING");
    $sock->flush;

    if (!$s->can_read(60)) {
	$sock->close;
	md_syslog('err', "Timeout reading from clamd daemon at $clamd_sock");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    # Free up memory used by IO::Select object
    undef $s;

    $sock->sysread($output,256);
    $sock->close;
    chomp($output);
    if (! defined($output) || $output ne "PONG") {
	md_syslog('err', "clamd is not responding");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    # open up a socket and scan each file in ./Work
    $sock = IO::Socket::UNIX->new(Peer => $clamd_sock);
    if (defined $sock) {
	if (!$sock->print("SCAN $CWD/Work\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	my $ans;
	$ans = $sock->sysread($output,256);
	$sock->close;
	if (!defined($ans) || !$ans) {
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	if ($output =~ /: (.+) FOUND/) {
	    $VirusScannerMessages .= "clamd found the $1 virus.\n";
	    $VirusName = $1;
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	} elsif ($output =~ /: (.+) ERROR/) {
	    my $err_detail = $1;
	    md_syslog('err', "Clamd returned error: $err_detail");
	    # If it's a zip module failure, try falling back on clamscan.
	    # This is despicable, but it might work
	    if ($err_detail =~ /(?:zip module failure|not supported data format)/i &&
		$Features{'Virus:CLAMAV'}) {
		my ($code, $category, $action) =
		    run_virus_scanner($Features{'Virus:CLAMAV'} . " -r --unzip --unrar --stdout --no-summary --infected $CWD/Work 2>&1");
		if ($action ne 'proceed') {
			return (wantarray ? ($code, $category, $action) : $code);
		}
		md_syslog('info', "Falling back on clamscan --unzip --unrar because of Zip module failure in clamd");
		return (wantarray ? interpret_clamav_code($code) : $code);
	    }
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
    }
    else {
	# Could not connect to daemon
	md_syslog('err', "Could not connect to clamd daemon at $clamd_sock");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }
    # No errors, no infected files were found
    return (wantarray ? (0, 'ok', 'ok') : 0);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_trophie
# %ARGUMENTS:
#  entity -- a MIME entity
#  trophie_sock (optional) -- Trophie socket path
# %RETURNS:
#  1 if entity contains a virus as reported by Trophie
# %DESCRIPTION:
#  Invokes the Trophie daemon (http://www.vanja.com/tools/trophie/)
#  on the entity.
#***********************************************************************
sub entity_contains_virus_trophie {
    my ($entity) = shift;
    my ($trophie_sock) = $TrophieSock;
    $trophie_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 1) if (!defined($trophie_sock));
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    my $sock = IO::Socket::UNIX->new(Peer => $trophie_sock);
    if (defined $sock) {
	my $path = $entity->bodyhandle->path;
	# If path is not absolute, add cwd
	if (! ($path =~ m+^/+)) {
	    $path = $CWD . "/" . $path;
	}
	if (!$sock->print("$path\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	my($output);
	$sock->sysread($output, 256);
	$sock->close;
	if ($output =~ /^1:(.*)$/) {
	    $VirusScannerMessages .= "Trophie found the $1 virus.\n";
	    $VirusName = $1;
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	}
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    # Could not connect to daemon
    md_syslog('err', "Could not connect to Trophie Daemon at $trophie_sock");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_trophie
# %ARGUMENTS:
#  trophie_sock (optional) -- Trophie socket path
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Invokes the Trophie daemon (http://www.vanja.com/tools/trophie/)
#  on the entire message.
#***********************************************************************
sub message_contains_virus_trophie {
    my ($trophie_sock) = $TrophieSock;
    $trophie_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 1) if (!defined($trophie_sock));
    my $sock = IO::Socket::UNIX->new(Peer => $trophie_sock);
    if (defined $sock) {
	if (!$sock->print("$CWD/Work\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	my($output);
	$sock->sysread($output, 256);
	$sock->close;
	if ($output =~ /^1:(.*)$/) {
	    $VirusScannerMessages .= "Trophie found the $1 virus.\n";
	    $VirusName = $1;
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	}
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    # Could not connect to daemon
    md_syslog('err', "Could not connect to Trophie Daemon at $trophie_sock");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_nod32
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by NOD32; 0 otherwise.
# %DESCRIPTION:
#  Runs Eset NOD32 program on the entity. (http://www.eset.com)
#***********************************************************************
sub entity_contains_virus_nod32 {
    unless($Features{'Virus:NOD32'}) {
	md_syslog('err', "NOD32 not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }
    my($entity) = @_;
    my($body) = $entity->bodyhandle;
    if (!defined($body)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    # Get filename
    my($path) = $body->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    # Run NOD32
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:NOD32'} . " --subdir $path 2>&1", "virus=\"([^\"]+)\"");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_nod32_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_nod32
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 or 2  if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs Eset NOD32 program on the working directory
#***********************************************************************
sub message_contains_virus_nod32 {
    unless($Features{'Virus:NOD32'}) {
	md_syslog('err', "NOD32 not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }
    # Run NOD32
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:NOD32'} . " --subdir ./Work 2>&1", "virus=\"([^\"]+)\"");
    return (wantarray ? interpret_nod32_code($code) : $code);
}

sub interpret_nod32_code {
    my($code) = @_;
    # OK
    return ($code, 'ok', 'ok') if ($code == 0);
    # 1 or 2 -- virus found
    if ($code == 1 || $code == 2) {
	$VirusName = $1 if ($CurrentVirusScannerMessage =~ m/virus=\"([^"]*)/);
	$VirusName = "unknown-NOD32-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }
    # error
    return ($code, 'swerr', 'tempfail');
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
