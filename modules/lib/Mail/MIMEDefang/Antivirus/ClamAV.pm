#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::ClamAV - ClamAV support (clamd, clamdscan and clamscan)

=head1 DESCRIPTION

This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

Actively maintained.  As of October 2026 ClamAV 1.5 is the current release, and the 1.4 LTS series is supported until August 2027.

=cut

package Mail::MIMEDefang::Antivirus::ClamAV;

use strict;
use warnings;

use Mail::MIMEDefang;
use IO::Socket;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

#***********************************************************************
# %PROCEDURE: entity_contains_virus_clamav
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by clamav
# %DESCRIPTION:
#  Runs the clamav program on the entity.
#***********************************************************************
sub entity_contains_virus_clamav {
    unless ($Features{'Virus:CLAMAV'}) {
	md_syslog('err', "clamav not installed on this system");
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

    # Run clamscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CLAMAV'} . " --stdout --no-summary --infected $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_clamav_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_clamav
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the clamscan program on the working directory
#***********************************************************************
sub message_contains_virus_clamav {
    unless ($Features{'Virus:CLAMAV'}) {
	md_syslog('err', "clamav not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run clamscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CLAMAV'} . " -r --stdout --no-summary --infected ./Work 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_clamav_code($code) : $code);
}

sub interpret_clamav_code {
    my($code) = @_;
    # From info obtained from:
    # clamscan(1)

    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # virus found
    if ($code == 1) {
	$VirusName = $1 if ($CurrentVirusScannerMessage =~ m/: (.+) FOUND/);
	$VirusName = "unknown-Clamav-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # other codes
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_clamdscan
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by clamdscan
# %DESCRIPTION:
#  Runs the clamdscan program on the entity.
#***********************************************************************
sub entity_contains_virus_clamdscan {
    unless ($Features{'Virus:CLAMDSCAN'}) {
	md_syslog('err', "clamav not installed on this system");
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

    # Run clamdscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CLAMDSCAN'} . " -c " . $Features{'Path:CLAMDCONF'} . " --no-summary --infected --fdpass --stream $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_clamav_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_clamdscan
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the clamdscan program on the working directory
#***********************************************************************
sub message_contains_virus_clamdscan {
    unless ($Features{'Virus:CLAMDSCAN'}) {
	md_syslog('err', "clamav not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run clamdscan
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:CLAMDSCAN'} . " -c " . $Features{'Path:CLAMDCONF'} . " --no-summary --infected --fdpass --stream ./Work 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    return (wantarray ? interpret_clamav_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_clamd
# %ARGUMENTS:
#  entity -- a MIME entity
#  clamd_sock (optional) -- clamd socket path
# %RETURNS:
#  1 if entity contains a virus as reported by clamd
# %DESCRIPTION:
#  Invokes the clamd daemon (http://www.clamav.net/)
#  on the entity.
#***********************************************************************
sub entity_contains_virus_clamd {
    my ($entity) = shift;
    my ($clamd_sock) = $ClamdSock;
    my $inet = 0;

    $clamd_sock = shift if (@_ > 0);
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    my $sock;
    if($clamd_sock =~ /\:/) {
      $sock = IO::Socket::INET->new($clamd_sock);
      $inet = 1;
    } else {
      $sock = IO::Socket::UNIX->new(Peer => $clamd_sock);
    }
    if (defined $sock) {
	my $path = $entity->bodyhandle->path;
	# If path is not absolute, add cwd
	if (! ($path =~ m+^/+)) {
	    $path = $CWD . "/" . $path;
	}
	if (!$sock->print("SCAN $path\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	my($output, $ans);
	$ans = $sock->sysread($output,256);
	$sock->close;
	if (!defined($ans) || !$ans) {
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	if ($output =~ /: (.+) FOUND/) {
	    $VirusScannerMessages .= "clamd found the $1 virus.\n";
	    $VirusName = $1;
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	} elsif ($output =~ /: (.+) ERROR/) {
	    my $err_detail = $1;
	    md_syslog('err', "Clamd returned error: $err_detail");
	    # If it's a zip module failure, try falling back on clamscan.
	    # This is despicable, but it might work
	    if ($err_detail =~ /(?:zip module failure|not supported data format)/i &&
		$Features{'Virus:CLAMAV'}) {
		my ($code, $category, $action) =
		run_virus_scanner($Features{'Virus:CLAMAV'} . " -r --unzip --unrar --stdout --no-summary --infected $CWD/Work 2>&1");
		if ($action ne 'proceed') {
			return (wantarray ? ($code, $category, $action) : $code);
		}
		md_syslog('info', "Falling back on clamscan --unzip --unrar because of Zip module failure in clamd");
		return (wantarray ? interpret_clamav_code($code) : $code);
	    }
	    return (wantarray ? (999, 'swerr', 'tempfail') : 1);
	}
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    # Could not connect to daemon
    md_syslog('err', "Could not connect to clamd Daemon at $clamd_sock");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_clamd
# %ARGUMENTS:
#  clamd_sock (optional) -- clamd socket path
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Invokes the clamd daemon (http://www.clamav.net/)
#  on the entire message.
#***********************************************************************
sub message_contains_virus_clamd {
    my ($clamd_sock) = $ClamdSock;
    $clamd_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 1) if (!defined($clamd_sock));
    my ($output,$sock);
    my $inet = 0;

    # PING/PONG test to make sure clamd is alive
    if($clamd_sock =~ /\:/) {
      $sock = IO::Socket::INET->new($clamd_sock);
      $inet = 1;
    } else {
      $sock = IO::Socket::UNIX->new(Peer => $clamd_sock);
    }
    if (!defined($sock)) {
	md_syslog('err', "Could not connect to clamd daemon at $clamd_sock");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    my $s = IO::Select->new();
    $s->add($sock);
    if (!$s->can_write(30)) {
	$sock->close;
	md_syslog('err', "Timeout writing to clamd daemon at $clamd_sock");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    $sock->print("PING");
    $sock->flush;

    if (!$s->can_read(60)) {
	$sock->close;
	md_syslog('err', "Timeout reading from clamd daemon at $clamd_sock");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    # Free up memory used by IO::Select object
    undef $s;

    $sock->sysread($output,256);
    $sock->close;
    chomp($output);
    if (! defined($output) || $output ne "PONG") {
	md_syslog('err', "clamd is not responding");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    # open up a socket and scan each file in ./Work
    if($inet) {
      $sock = IO::Socket::INET->new($clamd_sock);
    } else {
      $sock = IO::Socket::UNIX->new(Peer => $clamd_sock);
    }
    if (defined $sock) {
	if (!$sock->print("SCAN $CWD/Work\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	my $ans;
	$ans = $sock->sysread($output,256);
	$sock->close;
	if (!defined($ans) || !$ans) {
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	if ($output =~ /: (.+) FOUND/) {
	    $VirusScannerMessages .= "clamd found the $1 virus.\n";
	    $VirusName = $1;
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	} elsif ($output =~ /: (.+) ERROR/) {
	    my $err_detail = $1;
	    md_syslog('err', "Clamd returned error: $err_detail");
	    # If it's a zip module failure, try falling back on clamscan.
	    # This is despicable, but it might work
	    if ($err_detail =~ /(?:zip module failure|not supported data format)/i &&
		$Features{'Virus:CLAMAV'}) {
		my ($code, $category, $action) =
		    run_virus_scanner($Features{'Virus:CLAMAV'} . " -r --unzip --unrar --stdout --no-summary --infected $CWD/Work 2>&1");
		if ($action ne 'proceed') {
			return (wantarray ? ($code, $category, $action) : $code);
		}
		md_syslog('info', "Falling back on clamscan --unzip --unrar because of Zip module failure in clamd");
		return (wantarray ? interpret_clamav_code($code) : $code);
	    }
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
    }
    else {
	# Could not connect to daemon
	md_syslog('err', "Could not connect to clamd daemon at $clamd_sock");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }
    # No errors, no infected files were found
    return (wantarray ? (0, 'ok', 'ok') : 0);
}

1;
