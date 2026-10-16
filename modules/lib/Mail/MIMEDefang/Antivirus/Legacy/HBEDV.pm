#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::HBEDV - H+BEDV AntiVir support

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

Avira discontinued its Linux products (AntiVir) in 2013 and stopped delivering detection updates for them in June 2016.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::HBEDV;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
