#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::FSAV - F-Secure Anti-Virus (fsav) support

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

F-Secure Linux Security 11 reached end of support on 2020-12-31.  Its successor does not provide the fsav command.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::FSAV;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
