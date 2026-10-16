#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::BDC - Bitdefender bdc support

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

No current release was found.  The most recent BitDefender Antivirus Scanner for Unices build found dates from 2014.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::BDC;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
