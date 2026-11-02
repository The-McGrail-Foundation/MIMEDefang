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
use IO::Select;
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
# %PROCEDURE: clamd_interpret_reply
# %ARGUMENTS:
#  reply -- the complete reply of clamd to a SCAN command
# %RETURNS:
#  ($code, $category, $action, $error) -- standard virus-scanner return
#  values; $error is the text of the first ERROR reply, if any.
# %DESCRIPTION:
#  If a virus is found, $VirusName is set to the first one and every
#  virus is added to $VirusScannerMessages.  An empty reply is a
#  temporary failure; a reply that is neither a verdict nor an error
#  (e.g. from a newer clamd) is logged and the message is let through.
#***********************************************************************
sub clamd_interpret_reply {
    my ($reply) = @_;
    my (@viruses, @errors, $clean);
    $reply = '' unless defined($reply);

    return (999, 'swerr', 'tempfail', undef) if ($reply eq '');

    foreach my $line (split(/\r?\n|\0/, $reply)) {
	if ($line =~ /: (.+) FOUND$/) {
	    push(@viruses, $1);
	} elsif ($line =~ /(?:^|: )(.+) ERROR$/) {
	    push(@errors, $1);
	} elsif ($line =~ /: OK$/) {
	    $clean = 1;
	}
    }

    if (@viruses) {
	$VirusName = $viruses[0];
	$VirusScannerMessages .= "clamd found the $_ virus.\n" for @viruses;
	return (1, 'virus', 'quarantine', undef);
    }
    if (@errors) {
	md_syslog('err', "Clamd returned error: $errors[0]");
	return (999, 'swerr', 'tempfail', $errors[0]);
    }
    if (!$clean) {
	(my $shown = substr($reply, 0, 200)) =~ s/[^\x20-\x7e]+/ /g;
	md_syslog('warning', "Unexpected reply from clamd, message not scanned: '$shown'");
    }
    return (0, 'ok', 'ok', undef);
}

#***********************************************************************
# %PROCEDURE: _clamd_scan_path
# %ARGUMENTS:
#  clamd_sock -- clamd socket path, or host:port
#  path -- absolute path of the file or directory to scan
# %RETURNS:
#  ($code, $category, $action)
# %DESCRIPTION:
#  Asks clamd to scan $path and interprets its complete reply.
#***********************************************************************
sub _clamd_scan_path {
    my ($clamd_sock, $path) = @_;
    my $sock;
    if($clamd_sock =~ /\:/) {
      $sock = IO::Socket::INET->new($clamd_sock);
    } else {
      $sock = IO::Socket::UNIX->new(Peer => $clamd_sock);
    }
    if (!defined($sock)) {
	md_syslog('err', "Could not connect to clamd daemon at $clamd_sock");
	return (999, 'cannot-execute', 'tempfail');
    }
    if (!$sock->print("nSCAN $path\n") || !$sock->flush) {
	$sock->close;
	return (999, 'swerr', 'tempfail');
    }
    # Read the whole reply; clamd closes the connection when done
    my ($reply, $buf, $ans) = ('');
    while ($ans = $sock->sysread($buf, 4096)) {
	$reply .= $buf;
	last if (length($reply) > 65536);
    }
    $sock->close;
    if (!defined($ans) && $reply eq '') {
	return (999, 'swerr', 'tempfail');
    }

    my ($code, $category, $action, $err) = clamd_interpret_reply($reply);
    # If it's a zip module failure, try falling back on clamscan.
    # This is despicable, but it might work
    if (defined($err) && $err =~ /(?:zip module failure|not supported data format)/i &&
	$Features{'Virus:CLAMAV'}) {
	($code, $category, $action) =
	    run_virus_scanner($Features{'Virus:CLAMAV'} . " -r --stdout --no-summary --infected $path 2>&1");
	return ($code, $category, $action) if ($action ne 'proceed');
	md_syslog('info', "Falling back on clamscan because of Zip module failure in clamd");
	return interpret_clamav_code($code);
    }
    return ($code, $category, $action);
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

    $clamd_sock = shift if (@_ > 0);
    return (wantarray ? (999, 'swerr', 'tempfail') : 999) if (!defined($clamd_sock));
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    my $path = $entity->bodyhandle->path;
    if (!defined($path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 999);
    }
    # If path is not absolute, add cwd
    $path = $CWD . "/" . $path if ($path !~ m+^/+);

    my @r = _clamd_scan_path($clamd_sock, $path);
    return (wantarray ? @r : $r[0]);
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
    return (wantarray ? (999, 'swerr', 'tempfail') : 999) if (!defined($clamd_sock));
    my ($output,$sock);

    # PING/PONG test to make sure clamd is alive
    if($clamd_sock =~ /\:/) {
      $sock = IO::Socket::INET->new($clamd_sock);
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

    $sock->print("nPING\n");
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
    if (! defined($output) || $output !~ /^PONG\r?\n?\z/) {
	md_syslog('err', "clamd is not responding");
	return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
    }

    # scan each file in ./Work
    my @r = _clamd_scan_path($clamd_sock, "$CWD/Work");
    return (wantarray ? @r : $r[0]);
}

1;
