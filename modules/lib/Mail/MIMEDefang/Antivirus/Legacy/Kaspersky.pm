#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::Kaspersky - Kaspersky support (AvpLinux, aveclient and kavscanner)

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

The interfaces handled here (AvpLinux, aveclient, kavscanner) belong to earlier Kaspersky Linux products.  The current Kaspersky Endpoint Security for Linux is driven through kesl-control, which is not supported.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::Kaspersky;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
