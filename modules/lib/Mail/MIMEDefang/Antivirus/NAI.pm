#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::NAI - NAI/McAfee (now Trellix) uvscan support

=head1 DESCRIPTION

This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

The McAfee (now Trellix) command-line scanner, uvscan, is still sold and lists Linux among its platforms.

=cut

package Mail::MIMEDefang::Antivirus::NAI;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
