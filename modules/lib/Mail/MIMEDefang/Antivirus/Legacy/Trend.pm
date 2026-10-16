#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::Trend - Trend Micro support (Filescanner and the Trophie daemon)

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

Trend Micro still sells ServerProtect for Linux, which has its own command-line interface.  It might still be compatible with this interface. 

=cut

package Mail::MIMEDefang::Antivirus::Legacy::Trend;

use strict;
use warnings;

use Mail::MIMEDefang;
use IO::Socket;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

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

1;
