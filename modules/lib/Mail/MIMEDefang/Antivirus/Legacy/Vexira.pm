#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::Vexira - Central Command Vexira support

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

Probably discontinued after 2005.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::Vexira;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
