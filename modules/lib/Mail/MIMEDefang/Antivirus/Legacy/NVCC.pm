#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::NVCC - Norman Virus Control (nvcc) support

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

Norman was acquired by AVG in 2014, and no current Norman Linux scanner is available.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::NVCC;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
