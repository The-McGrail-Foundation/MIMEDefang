#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::FProt - F-Prot support (f-prot, fpscan, fprotd and fprotd v6)

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

F-Prot reached end of life on 2021-07-31 and no longer receives signature updates.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::FProt;

use strict;
use warnings;

use Mail::MIMEDefang;
use IO::Socket;
use Mail::MIMEDefang::Antivirus qw(run_virus_scanner);

#***********************************************************************
# %PROCEDURE: scan_file_using_fprotd_v6
# %ARGUMENTS:
#  fname -- name of file to scan
#  host -- host and port on which FPROTD version 6 is listening,
#          eg 127.0.0.1:7777
# %RETURNS:
#  A (code, category, action) triplet.  Sets VirusName if virus found.
# %DESCRIPTION:
#  Asks FPROTD version 6 to scan a file.
#***********************************************************************
sub scan_file_using_fprotd_v6
{
    my($fname, $hname) = @_;

    $hname ||= $Fprotd6Host;
    my($host, $port) = split(/:/, $hname);
    $host ||= '127.0.0.1';
    $port ||= 10200;

    my $connect_timeout = 10;
    my $read_timeout = 60;

    # Convert path to absolute
    if (! ($fname =~ m+^/+)) {
	my($cwd);
	chomp($cwd = `pwd`);
	$fname = $cwd . "/" . $fname;
    }

    my $sock = IO::Socket::INET->new(
	PeerAddr => $host,
	PeerPort => $port,
	Timeout => $connect_timeout);

    unless (defined $sock) {
	md_syslog('warning', "Could not connect to FPROTD6 on $host: $!");
	return (999, 'cannot-execute', 'tempfail');
    }

    if (!$sock->print("SCAN --scanlevel=2 --archive=2 --heurlevel=2 --adware --applications FILE $fname\n") || !$sock->flush()) {
	md_syslog('warning', "Error writing to FPROTD6 on $host: $!");
	$sock->close();
	return (999, 'cannot-execute', 'tempfail');
    }

    my $s = IO::Select->new($sock);
    if (!$s->can_read($read_timeout)) {
	$sock->close();
	md_syslog('warning', "Timeout reading from FPROTD6 daemon on $host");
	return (999, 'cannot-execute', 'tempfail');
    }

    my $resp = $sock->getline();
    $sock->close();
    if (!$resp) {
	md_syslog('warning', "Did not get response from FPROTD6 on $host while scanning $fname");
	return (999, 'cannot-execute', 'tempfail');
    }

    my ($code, $desc, $name);
    unless (($code, $desc, $name) = $resp =~ /\A(\d+)\s<(.*?)>\s(.*)\Z/) {
	md_syslog('warning', "Failed to parse response from FPROTD6 for $fname: $resp");
	return (999, 'cannot-execute', 'tempfail');

    }

    # Clean up $desc
    $desc =~ s/\A(?:contains infected objects|infected):\s//i;

    # Our output should contain:
    # 1) A code.  The code is a bitmask of:
    # bit num Meaning
    #  0   1  At least one virus-infected object was found (and remains).
    #  1   2  At least one suspicious (heuristic match) object was found (and remains).
    #  2   4  Interrupted by user. (SIGINT, SIGBREAK).
    #  3   8  Scan restriction caused scan to skip files (maxdepth directories, maxdepth archives, exclusion list, etc).
    #  4  16  Platform error (out of memory, real I/O errors, insufficient file permission etc.).
    #  5  32  Internal engine error (whatever the engine fails at)
    #  6  64  At least one object was not scanned (encrypted file, unsupported/unknown compression method, corrupted or invalid file).
    #  7 128  At least one object was disinfected (clean now) (treat same as virus for File::VirusScan)
    #
    # 2) The description, including virus name
    #
    # 3) The item name, incl. member of archive etc.  We ignore
    # this for now.

    if($code & (1 | 2 | 128)) {
	$VirusName = $desc;
	$VirusName ||= 'unknown-FPROTD6-virus';
	return ($code, 'virus', 'quarantine');
    } elsif($code & 4) {
	md_syslog('warning', 'FPROTD6 scanning interrupted by user');
	return ($code, 'interrupted', 'tempfail');
    } elsif($code & 16) {
	md_syslog('warning', 'FPROTD6 platform error');
	return ($code, 'swerr', 'tempfail');
    } elsif($code & 32) {
	md_syslog('warning', 'FPROTD6 internal engine error');
	return ($code, 'swerr', 'tempfail');
    }

    return(0, 'ok', 'ok');
}

sub entity_contains_virus_fprotd_v6
{
    my($entity, $host) = @_;
    $host ||= $Fprotd6Host;
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    return scan_file_using_fprotd_v6($entity->bodyhandle->path,
				     $host);
}

sub message_contains_virus_fprotd_v6
{
    my($host) = @_;
    $host ||= $Fprotd6Host;

    my $dir;
    if (!opendir($dir, "./Work")) {
	md_syslog('err', "message_contains_virus_fprotd_v6: Could not open ./Work directory: $!");
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Scan all files in Work
    my(@files);
    @files = grep { -f "./Work/$_" } readdir($dir);
    closedir($dir);

    my($code, $category, $action);
    foreach my $file (@files) {
	($code, $category, $action) =
	    scan_file_using_fprotd_v6("Work/$file", $host);
	if ($code != 0) {
	    return (wantarray ? ($code, $category, $action) : $code);
	}
    }
    return (0, 'ok', 'ok');
}

#***********************************************************************
# %PROCEDURE: item_contains_virus_fprotd
# %ARGUMENTS:
#  item -- a file or directory
#  host (optional) -- Fprotd host and base port.
# %RETURNS:
#  Usual virus status
# %DESCRIPTION:
#  Scans the entity using Fprotd scanning daemon
#***********************************************************************
sub item_contains_virus_fprotd {
    my $item = shift;
    my ($host) = $FprotdHost;
    $host = shift if (@_ > 0);
    $host = '127.0.0.1' if (!defined($host));
    my $baseport = 10200;
    if($host =~ /(.*):(.*)/ ) {
	$host = $1;
	$baseport = $2;
    }

    md_syslog('info', "Scan '$item' via F-Protd \@$host:$baseport");
    # The F-Prot demon cannot scan directories, but files only
    # hence, we recurse any directories manually
    if(-d $item) {
	my @result;
	$host .= ":$baseport";
	foreach my $entry (glob("$item/*")) {
	    @result = &item_contains_virus_fprotd($entry, $host);
	    last if $result[0] != 0;
	}
	return (wantarray ? @result : $result[0]);
    }

    # Default error message when reaching end of function
    my $errmsg = "Could not connect to F-Prot Daemon at $host:$baseport";

    # Try 5 ports in order to find an active scanner; they may change the port
    # when they find and spawn an updated demon executable
SEARCH_DEMON: foreach my $port ($baseport..($baseport+4)) {
    my $sock = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port);
    if (defined $sock) {

	# The arguments (following the '?' sign in the HTTP request)
	# are the same as for the command line F-Prot, the additional
	# -remote-dtd suppresses the useless XML DTD prefix
	if (!$sock->print("GET $item?-dumb%20-archive%20-packed%20-remote-dtd HTTP/1.0\n\n")) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}
	if (!$sock->flush) {
	    $sock->close;
	    return (wantarray ? (999, 'swerr', 'tempfail') : 999);
	}

	# Fetch HTTP Header
	## Maybe dropped, if no validation checks are to be made
	while(my $output = $sock->getline) {
	    if($output =~ /^\s*$/) {
		last;	# break line for XML content
		#### Below here: Validating the protocol
		#### If the protocol is not recognized, it's assumed that the
		#### endpoint is not an F-Prot demon, hence,
		#### the next port is probed.
	    } elsif($output =~ /^HTTP(.*)/) {
		my $h = $1;
		next SEARCH_DEMON unless $h =~ m!/1\.0\s+200\s!;
	    } elsif($output =~ /^Server:\s*(\S*)/) {
		next SEARCH_DEMON if $1 !~ /^fprotd/;
	    }
	}

	# Parsing XML results
	my $xml = HTML::TokeParser->new($sock);
	my $t = $xml->get_tag('fprot-results');
	unless($t) {	# This is an essential tag --> assume a broken demon
	    $errmsg = 'Demon did not return <fprot-results> tag';
	    last SEARCH_DEMON;
	}

	if($t->[1]{'version'} ne '1.0') {
	    $errmsg = "Incompatible F-Protd results version: "
		. $t->[1]{'version'};
	    last SEARCH_DEMON;
	}

	my $curText;	# temporarily accumulated information
	my $virii = '';	# name(s) of virus(es) found
	my $code;	# overall exit code
	my $msg = '';	# accumulated message of virus scanner
	while( $t = $xml->get_token ) {
	    my $tag = $t->[1];
	    if($t->[0] eq 'S') {	# Start tag
		# Accumulate the information temporarily
		# into $curText until the </detected> tag is found
		my $text = $xml->get_trimmed_text;
		# $tag 'filename' of no use in MIMEDefang
		if($tag eq 'name') {
		    $virii .= (length $virii ? " " : "" ) . $text;
		    $curText .= "Found the virus: '$text'\n";
		} elsif($tag eq 'accuracy' || $tag eq 'disinfectable' ||
		        $tag eq 'message') {
		    $curText .= "\t$tag: $text\n";
		} elsif($tag eq 'error') {
		    $msg .= "\nError: $text\n";
		} elsif($tag eq 'summary') {
		    $code = $t->[2]{'code'}
		    if defined $t->[2]{'code'};
		}
	    } elsif($t->[0] eq 'E') {	# End tag
		if($tag eq 'detected') {
		    # move the cached information to the
		    # accumulated message
		    $msg .= "\n$curText" if $curText;
		    undef $curText;
		} elsif($tag eq 'fprot-results') {
		    last;	# security check
		}
	    }
	}
	$sock->close;

## Check the exit code (man f-protd)
## NOTE: These codes are different from the ones of the command line version!
#  0      Not scanned, unable to handle the object.
#  1      Not scanned due to an I/O error.
#  2      Not scanned, as the scanner ran out of memory.
#  3  X   The object is not of a type the scanner knows. This
#         may  either mean it was misidentified or that it is
#         corrupted.
#  4  X   The object was valid, but encrypted and  could  not
#         be scanned.
#  5      Scanning of the object was interrupted.
#  7  X   The  object was identified as an "innocent" object.
#  9  X   The object was successfully scanned and nothing was
#         found.
#  11     The object is infected.
#  13     The object was disinfected.
	unless(defined $code) {
	    $errmsg = "No summary code found";
	    last SEARCH_DEMON;
	}
	if($code < 3 # I/O error, unable to handle, out of mem
	   # any filesystem error less than zero
	   || $code == 5) { # interrupted
	    ## assume this a temporary failure
	    $errmsg = "Scan error #$code: $msg";
		last SEARCH_DEMON;
	}

	if($code > 10) { # infected; (disinfected: Should never happen!)
	    # Add the accumulated information
	    $VirusScannerMessages .= $msg;
	    if ( length $virii ) {
		$VirusName = $virii;
	    } elsif ( $msg =~ /^\tmessage:\s+(\S.*)/m ) {
		$VirusName = $1;
	    } else {
                # no virus name found, log message returned by fprot
                $msg =~ s/\s+/ /g;
                md_syslog('info',
                    qq[$MsgID: cannot extract virus name from f-prot: "$msg"]);
                $VirusName = "unknown";
            }
	    return (wantarray ? (1, 'virus', 'quarantine') : 1);
	}
###### These codes are left to be handled:
#  3  X   The object is not of a type the scanner knows. This
#         may  either mean it was misidentified or that it is
#         corrupted.
#  4  X   The object was valid, but encrypted and  could  not
#         be scanned.
#  7  X   The  object was identified as an "innocent" object.
#  9  X   The object was successfully scanned and nothing was

#	9 is trivial; 7 is probably trivial
#	4 & 3 we can't do anything really, because if the attachment
#	is some unknown archive format, the scanner wouldn't had known
#	this issue anyway, hence, I consider it "clean"

	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
}

    # Could not connect to daemon or some error occurred during the
    # communication with it
    $errmsg =~ s/\s*\.*\s*\n+\s*/\. /g;
    md_syslog('err', "$errmsg");
    return (wantarray ? (999, 'cannot-execute', 'tempfail') : 999);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_fprotd
# %ARGUMENTS:
#  entity -- a MIME entity
#  host (optional) -- F-Prot Demon host:port
# %RETURNS:
#  1 if entity contains a virus as reported by F-Prot Demon
# %DESCRIPTION:
#  Invokes the F-Prot daemon (http://www.frisk.org/) on
#  the entity.
#***********************************************************************
sub entity_contains_virus_fprotd {
    my ($entity) = shift;

    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    my $path = $entity->bodyhandle->path;
    # If path is not absolute, add cwd
    if (! ($path =~ m+^/+)) {
	$path = $CWD . "/" . $path;
    }
    return item_contains_virus_fprotd($path, $_[0]);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_fprotd
# %ARGUMENTS:
#  host (optional) -- F-Prot Demon host:port
# %RETURNS:
#  1 if entity contains a virus as reported by F-Prot Demon
# %DESCRIPTION:
#  Invokes the F-Prot daemon (http://www.frisk.org/) on
#  the entire message.
#***********************************************************************
sub message_contains_virus_fprotd {
    return item_contains_virus_fprotd ("$CWD/Work", $_[0]);
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_fprot
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by FRISK F-Prot; 0 otherwise.
# %DESCRIPTION:
#  Runs the F-PROT program on the entity. (http://www.f-prot.com)
#***********************************************************************
sub entity_contains_virus_fprot {
    unless ($Features{'Virus:FPROT'}) {
	md_syslog('err', "F-RISK FPROT not installed on this system");
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

    # Run f-prot
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:FPROT'} . " -DUMB -ARCHIVE -PACKED $path 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }

    # f-prot return codes
    return (wantarray ? interpret_fprot_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_fprot
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the F-RISK f-prot program on the working directory
#***********************************************************************
sub message_contains_virus_fprot {
    unless ($Features{'Virus:FPROT'}) {
	md_syslog('err', "F-RISK f-prot not installed on this system");
	return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run f-prot
    my($code, $category, $action) =
	run_virus_scanner($Features{'Virus:FPROT'} . " -DUMB -ARCHIVE -PACKED ./Work 2>&1");
    if ($action ne 'proceed') {
	return (wantarray ? ($code, $category, $action) : $code);
    }
    # f-prot return codes
    return (wantarray ? interpret_fprot_code($code) : $code);
}

sub interpret_fprot_code {
    # Info from
    my($code) = @_;
    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # Unrecoverable error (Missing DAT, etc)
    return ($code, 'swerr', 'tempfail') if ($code == 1);

    # Driver integrity check failed
    return ($code, 'swerr', 'tempfail') if ($code == 2);

    # Virus found
    if ($code == 3) {
	$VirusName = $1
	    if ($CurrentVirusScannerMessage =~ m/Infection\: (\S+)/);
	$VirusName = "unknown-FPROT-virus" if $VirusName eq "";
	return ($code, 'virus', 'quarantine');
    }

    # Reserved for now. Treat as an error
    return ($code, 'swerr', 'tempfail') if ($code == 4);

    # Abnormal termination (scan didn't finish)
    return ($code, 'swerr', 'tempfail') if ($code == 5);

    # At least one virus removed - Should not happen as we aren't
    # requesting disinfection ( at least in this version).
    return ($code, 'swerr', 'tempfail') if ($code == 6);

    # Memory error
    return ($code, 'swerr', 'tempfail') if ($code == 7);

    # Something suspicious was found, but not recognized virus
    # ( uncomment the one your paranoia dictates :) ).
#    return ($code, 'virus', 'quarantine') if ($code == 8);
    return ($code, 'ok', 'ok') if ($code == 8);

    # Unknown exit code
    return ($code, 'swerr', 'tempfail');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_fpscan
# %ARGUMENTS:
#  entity -- a MIME entity
# %RETURNS:
#  1 if entity contains a virus as reported by FRISK F-Prot; 0 otherwise.
# %DESCRIPTION:
#  Runs the F-PROT program on the entity. (http://www.f-prot.com)
#***********************************************************************
sub entity_contains_virus_fpscan {
    unless ($Features{'Virus:FPSCAN'}) {
        md_syslog('err', "F-RISK fpscan not installed on this system");
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

    # Run f-prot
    my($code, $category, $action) =
        run_virus_scanner($Features{'Virus:FPSCAN'} . " --report --archive=5  --scanlevel=4 --heurlevel=3 $path 2>&1");
    if ($action ne 'proceed') {
        return (wantarray ? ($code, $category, $action) : $code);
    }

    # f-prot return codes
    return (wantarray ? interpret_fpscan_code($code) : $code);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_fpscan
# %ARGUMENTS:
#  Nothing
# %RETURNS:
#  1 if any file in the working directory contains a virus
# %DESCRIPTION:
#  Runs the F-RISK f-prot program on the working directory
#***********************************************************************
sub message_contains_virus_fpscan {
    unless ($Features{'Virus:FPSCAN'}) {
        md_syslog('err', "F-RISK fpscan not installed on this system");
        return (wantarray ? (1, 'not-installed', 'tempfail') : 1);
    }

    # Run f-prot
    my($code, $category, $action) =
        run_virus_scanner($Features{'Virus:FPSCAN'} . " --report --archive=5  --scanlevel=4 --heurlevel=3 ./Work 2>&1");
    if ($action ne 'proceed') {
        return (wantarray ? ($code, $category, $action) : $code);
    }
    # f-prot return codes
    return (wantarray ? interpret_fpscan_code($code) : $code);
}

sub interpret_fpscan_code {
    # Info from
    my($code) = @_;

    # Set to 1 to mark heuristic matches as a virus
    my $heuristic_virus = 0;
    # OK
    return ($code, 'ok', 'ok') if ($code == 0);

    # bit 1 (1)   ==> At least one virus-infected object was found (and
    #                 remains).
    if ($code & 0b1) {
        $VirusName = $1
            if ($CurrentVirusScannerMessage =~ m/^\[Found\s+[^\]]*\]\s+<([^ \t\(>]*)/m);
        $VirusName = "unknown-FPSCAN-virus" if $VirusName eq "";
        return ($code, 'virus', 'quarantine');
    }

    if ($heuristic_virus and $code & 0b10) {
        return ($code, 'virus', 'quarantine');
    }

    # bit 3 (4)   ==> Interrupted by user (SIGINT, SIGBREAK).
    if ($code & 0b100) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 4 (8)   ==> Scan restriction caused scan to skip files
    #                 (maxdepth directories, maxdepth archives,
    #                 exclusion list, etc).

    if ($code & 0b1000) {
        return ($code, 'swerr', 'tempfail');
    }
    # bit 5 (16)  ==> Platform error (out of memory, real I/O errors,
    #                 insufficient file permission etc.)

    if ($code & 0b10000) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 6 (32)  ==> Internal engine error (whatever the engine fails
    #                 at)
    if ($code & 0b100000) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 7 (64)  ==> At least one object was not scanned (encrypted
    #                 file, unsupported/unknown compression method,
    #                 corrupted or invalid file).
    if ($code & 0b1000000) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 8 (128) ==> At least one object was disinfected (clean now).
    # Should not happen as we aren't requesting disinfection ( at least
    # in this version).
    if ($code & 0b10000000) {
        return ($code, 'swerr', 'tempfail');
    }

    # bit 2 (2)   ==> At least one suspicious (heuristic match) object
    #                 was found (and remains).
    if ($code & 0b10) {
    # ( uncomment the one your paranoia dictates :) ).
        return ($code, 'ok', 'ok');
    }

    # Unknown exit code, this should never happen
    return ($code, 'swerr', 'tempfail');
}

1;
