#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::CSAV - Command Anti-Virus (csav) support

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

Command AntiVirus was acquired by Commtouch (later Cyren) in 2010, and no current standalone Linux product is now available.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::CSAV;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
