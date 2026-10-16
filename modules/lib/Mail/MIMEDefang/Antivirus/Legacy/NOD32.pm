#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::NOD32 - ESET NOD32 command-line scanner support

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

ESET still sells Linux server products (ESET Server Security for Linux), which have their own command-line scanner.  It might still be compatible with the supported command-line interface.
=cut

package Mail::MIMEDefang::Antivirus::Legacy::NOD32;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
