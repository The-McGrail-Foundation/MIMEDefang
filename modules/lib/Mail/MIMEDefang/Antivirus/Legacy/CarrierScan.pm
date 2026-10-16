#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antivirus::Legacy::CarrierScan - Symantec CarrierScan support

=head1 DESCRIPTION

This is a legacy scanner interface, kept for backward compatibility.
This module is loaded on demand by L<Mail::MIMEDefang::Antivirus>,
the first time one of its scanners is initialized or used.  Filters should
keep calling these routines through L<Mail::MIMEDefang::Antivirus>, which
provides the original function names, instead of loading this module
directly.

=head1 STATUS

Symantec Protection Engine (Broadcom) is the successor of this product line.  CarrierScan protocol might be still supported.

=cut

package Mail::MIMEDefang::Antivirus::Legacy::CarrierScan;

use strict;
use warnings;

use Mail::MIMEDefang;
use IO::Socket;

#***********************************************************************
# %PROCEDURE: scan_file_using_carrier_scan
# %ARGUMENTS:
#  fname -- name of file to scan
#  host -- host and port on which Carrier Scan is listening, eg 127.0.0.1:7777
#          Can optionally have :local or :nonlocal appended to force
#          AVSCANLOCAL or AVSCAN
# %RETURNS:
#  A (code, category, action) triplet.  Sets VirusName if virus found.
# %DESCRIPTION:
#  Asks Symantec CarrierScan Server to scan a file.
#***********************************************************************
sub scan_file_using_carrier_scan {
    my($fname, $hname) = @_;

    my($host, $port, $local) = split(/:/, $hname);
    # If not specified, use local scanning for 127.0.0.1, remote for
    # any other.
    unless(defined($local)) {
	if ($host =~ /^127\.0\.0\.1/) {
	    $local = 1;
	} else {
	    $local = 0;
	}
    }

    # Convert from strings
    if ($local eq "local") {
	$local = 1;
    }
    if ($local eq "nonlocal") {
	$local = 0;
    }

    $port = 7777 unless defined($port);

    # Convert path to absolute
    if (! ($fname =~ m+^/+)) {
	my($cwd);
	chomp($cwd = `pwd`);
	$fname = $cwd . "/" . $fname;
    }
    my $sock = IO::Socket::INET->new("$host:$port");
    my ($line);
    unless (defined $sock) {
	md_syslog('warning', "Could not connect to CarrierScan Server on $host: $!");
	return (999, 'cannot-execute', 'tempfail');
    }

    # Read first line of reply from socket
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    unless ($line =~ /^220/) {
	md_syslog('warning', "Unexpected reply $line from CarrierScan Server");
	$sock->close;
	return (999, 'swerr', 'tempfail');
    }

    # Next line must be version
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    unless ($line eq "2") {
	md_syslog('warning', "Unexpected version $line from CarrierScan Server");
	$sock->close;
	return(999, 'swerr', 'tempfail');
    }

    # Cool; send our stuff!
    my $in;
    if ($local) {
	if (!$sock->print("Version 2\nAVSCANLOCAL\n$fname\n")) {
	    $sock->close;
	    return (999, 'swerr', 'tempfail');
	}
    } else {
	my ($size);
	my ($chunk);
	my ($chunksize, $nread);
	$size = (stat($fname))[7];
	unless(defined($size)) {
	    md_syslog('warning', "Cannot stat $fname: $!");
	    $sock->close;
	    return(999, 'swerr', 'tempfail');
	}
	if (!$sock->print("Version 2\nAVSCAN\n$fname\n$size\n")) {
	    $sock->close;
	    return (999, 'swerr', 'tempfail');
	}
	unless(open($in, "<", "$fname")) {
	    md_syslog('warning', "Cannot open $fname: $!");
	    $sock->close;
	    return(999, 'swerr', 'tempfail');
	}
	while ($size > 0) {
	    if ($size < 8192) {
		$chunksize = $size;
	    } else {
		$chunksize = 8192;
	    }
	    $nread = read($in, $chunk, $chunksize);
	    unless(defined($nread)) {
		md_syslog('warning', "Error reading $fname: $!");
		$sock->close;
                close($in);
		return(999, 'swerr', 'tempfail');
	    }
	    last if ($nread == 0);
	    if (!$sock->print($chunk)) {
		$sock->close;
                close($in);
		return (999, 'swerr', 'tempfail');
	    }
	    $size -= $nread;
	}
	if ($size > 0) {
	    md_syslog('warning', "Error reading $fname: $!");
	    $sock->close;
            close($in);
	    return(999, 'swerr', 'tempfail');
	}
    }
    if (!$sock->flush) {
	$sock->close;
        close($in);
	return (999, 'swerr', 'tempfail');
    }

    # Get reply from server
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    unless ($line =~ /^230/) {
	md_syslog('warning', "Unexpected response to AVSCAN or AVSCANLOCAL command: $line");
	$sock->close;
        close($in);
	return(999, 'swerr', 'tempfail');
    }
    # Get infection status
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    if ($line == 0) {
	$sock->close;
        close($in);
	return (0, 'ok', 'ok');
    }

    # Skip definition date and version, infection count and filename
    chomp($line = $sock->getline); # Definition date
    chomp($line = $sock->getline); # Definition version
    chomp($line = $sock->getline); # Infection count (==1)
    chomp($line = $sock->getline); # Filename

    # Get virus name
    chomp($line = $sock->getline);
    $line =~ s/\r//g;
    close($in);
    $sock->close;

    $VirusName = $line;
    return (1, 'virus', 'quarantine');
}

#***********************************************************************
# %PROCEDURE: entity_contains_virus_carrier_scan
# %ARGUMENTS:
#  entity -- a MIME entity
#  host (optional) -- Symantec CarrierScan host:port
# %RETURNS:
#  Usual virus status
# %DESCRIPTION:
#  Scans the entity using Symantec CarrierScan
#***********************************************************************
sub entity_contains_virus_carrier_scan {
    my($entity) = shift;
    my($host) = $CSSHost;
    $host = shift if (@_ > 0);
    $host = '127.0.0.1:7777:local' if (!defined($host));
    if (!defined($entity->bodyhandle)) {
	return (wantarray ? (0, 'ok', 'ok') : 0);
    }
    if (!defined($entity->bodyhandle->path)) {
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }
    return scan_file_using_carrier_scan($entity->bodyhandle->path,
					$host);
}

#***********************************************************************
# %PROCEDURE: message_contains_virus_carrier_scan
# %ARGUMENTS:
#  host (optional) -- Symantec CarrierScan host:port
# %RETURNS:
#  Usual virus status
# %DESCRIPTION:
#  Scans the entity using Symantec CarrierScan
#***********************************************************************
sub message_contains_virus_carrier_scan {
    my($host) = $CSSHost;
    $host = shift if (@_ > 0);
    $host = '127.0.0.1:7777:local' if (!defined($host));

    my $dir;
    if (!opendir($dir, "./Work")) {
	md_syslog('err', "message_contains_virus_carrier_scan: Could not open ./Work directory: $!");
	return (wantarray ? (999, 'swerr', 'tempfail') : 1);
    }

    # Scan all files in Work
    my(@files);
    @files = grep { -f "./Work/$_" } readdir($dir);
    closedir($dir);

    my($code, $category, $action);
    foreach my $file (@files) {
	($code, $category, $action) =
	    scan_file_using_carrier_scan("Work/$file", $host);
	if ($code != 0) {
	    return (wantarray ? ($code, $category, $action) : $code);
	}
    }
    return (0, 'ok', 'ok');
}

1;
