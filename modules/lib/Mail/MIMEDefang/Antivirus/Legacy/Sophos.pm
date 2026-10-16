#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::Sophos - Sophos support (sweep, savscan and the Sophie daemon)

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

Sophos Anti-Virus for Linux (savscan, formerly sweep) reached end of life on 2023-07-20 and no longer receives signature updates.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::Sophos;

use strict;
use warnings;

use Mail::MIMEDefang;
use IO::Socket;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

#***********************************************************************
# %PROCEDURE: entity_contains_virus_sophos
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Sophos Sweep
# %DESCRIPTION:
#  Runs the Sophos Sweep program on the entity.
#***********************************************************************
sub entity_contains_virus_sophos {

    unless($Features{'Virus:SOPHOS'}) {
	md_syslog('err', "Sophos Sweep not installed on this system");
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
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:SOPHOS'} . " -f -mime -all -archive -ss $path 2>&1", "(>>> Virus)|(Password)|(Could not check)");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_sweep_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_savscan
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by Sophos Savscan
# %DESCRIPTION:
#  Runs the Sophos Savscan program on the entity.
#***********************************************************************
sub entity_contains_virus_savscan {

    unless($Features{'Virus:SAVSCAN'}) {
	md_syslog('err', "Sophos Savscan not installed on this system");
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
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:SAVSCAN'} . " -f -mime -all -cab -oe -tnef -archive -ss $path 2>&1", "(>>> Virus)|(Password)|(Could not check)");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_savscan_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_sophos
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Sophos Sweep program on the working directory
#***********************************************************************
sub message_contains_virus_sophos {

    unless($Features{'Virus:SOPHOS'}) {
	md_syslog('err', "Sophos Sweep not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:SOPHOS'} . " -f -mime -all -archive -ss ./Work 2>&1", "(>>> Virus)|(Password)|(Could not check)");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_sweep_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_savscan
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the Sophos Savscan program on the working directory
#***********************************************************************
sub message_contains_virus_savscan {

    unless($Features{'Virus:SAVSCAN'}) {
	md_syslog('err', "Sophos Savscan not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run antivir
    my($code, $category, $action) = run_virus_scanner($Features{'Virus:SAVSCAN'} . " -f -mime -all -cab -oe -tnef -archive -ss ./Work 2>&1", "(>>> Virus)|(Password)|(Could not check)");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_savscan_code($code) : $code);
}

sub interpret_sweep_code {
    # Based on info from Nicholas Brealey
    my($code) = @_;

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Interrupted
    return ($code, 'interrupted', 'tempfail') if ($code == 1);

    # This is technically an error code, but Sophos chokes
    # on a lot of M$ docs with this code, so we let it through...
    return (0, 'ok', 'ok') if ($code == 2);

    # Virus
    if ($code == 3) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/^\s*>>> Virus '(\S+)'/);
	$VirusName = "unknown-Sweep-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Unknown code
    return ($code, 'swerr', 'tempfail');
}

sub interpret_savscan_code {
    # Based on info from Nicholas Brealey
    my($code) = @_;

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Interrupted
    return ($code, 'interrupted', 'tempfail') if ($code == 1);

    # This is technically an error code, but Sophos chokes
    # on a lot of M$ docs with this code, so we let it through...
    return (0, 'ok', 'ok') if ($code == 2);

    # Virus
    if ($code == 3) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/^\s*>>> Virus '(\S+)'/);
	$VirusName = "unknown-Savscan-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Unknown code
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_sophie
# %ARGUMENTS:
#  entity -- a MIME entity
#  sophie_sock (optional) -- Sophie socket path
# %RETURNS:
#  1 if entity contains a virus as reported by Sophie
# %DESCRIPTION:
#  Invokes the Sophie daemon (http://www.vanja.com/tools/sophie/)
#  on the entity.
#***********************************************************************
sub entity_contains_virus_sophie {
    my ($entity) = shift;
    my ($sophie_sock) = $SophieSock;
    $sophie_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 1) if (!defined($sophie_sock));
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    my $sock = IO::Socket::UNIX->new(Peer => $sophie_sock);
    if (defined $sock) {
	my $path = $entity->bodyhandle->path;
	# If path is not absolute, add cwd
	if (! ($path =~ m+^/+)) {
	    $path = $CWD . "/" . $path;
	}
	if (!$sock->print("$path\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	my($output);
	if (!$sock->sysread($output,256)) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->close) {
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if ($output =~ /^0/) { return (wantarray ? (0, 'ok', 'ok') : 0); }
	elsif ($output =~ /^1/) {
	    $VirusName = "Unknown-sophie-virus";
	    $VirusName = $1 if $output =~ /^1:(.*)$/;
	    $VirusScannerMessages .= "Sophie found the $VirusName virus.\n";
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	}
	elsif ($output =~ /^-1/) {
	    my $errmsg = "unknown status";
	    $errmsg = "$1" if $output =~ /^-1:(.*)$/;
	    md_syslog('err', "entity_contains_virus_sophie: $errmsg ($path)");
	    $VirusScannerMessages .= "Sophie error: $errmsg\n";
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	else {
	    md_syslog('err', "entity_contains_virus_sophie: unknown response - $output ($path)");
	    $VirusScannerMessages .= "Sophie error: unknown response - $output\n";
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
    }
    # Could not connect to daemon
    md_syslog('err', "Could not connect to Sophie Daemon at $sophie_sock");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_sophie
# %ARGUMENTS:
#  sophie_sock (optional) -- Sophie socket path
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Invokes the Sophie daemon (http://www.vanja.com/tools/sophie/)
#  on the entire message.
#***********************************************************************
sub message_contains_virus_sophie {
    my ($sophie_sock) = $SophieSock;
    $sophie_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 1) if (!defined($sophie_sock));
    my $sock = IO::Socket::UNIX->new(Peer => $sophie_sock);
    if (defined $sock) {
	if (!$sock->print("$CWD/Work\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	my($output, $ans);
	$ans = $sock->sysread($output, 256);
	if (!defined($ans)) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->close) {
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if ($output =~ /^0/) { return (wantarray ? (0, 'ok', 'ok') : 0); }
	elsif ($output =~ /^1/) {
	    $VirusName = "Unknown-sophie-virus";
	    $VirusName = $1 if $output =~ /^1:(.*)$/;
	    $VirusScannerMessages .= "Sophie found the $VirusName virus.\n";
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	}
	elsif ($output =~ /^-1/) {
	    my $errmsg = "unknown status";
	    $errmsg = "$1" if $output =~ /^-1:(.*)$/;
	    md_syslog('err', "message_contains_virus_sophie: $errmsg ($CWD/Work)");
	    $VirusScannerMessages .= "Sophie error: $errmsg\n";
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	else {
	    md_syslog('err', "message_contains_virus_sophie: unknown response - $output ($CWD/Work)");
	    $VirusScannerMessages .= "Sophie error: unknown response - $output\n";
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
    }
    # Could not connect to daemon
    md_syslog('err', "Could not connect to Sophie Daemon at $sophie_sock");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

1;
