package Mail::MIMEDefang::Utils;

use strict;
use warnings;

use Mail::MIMEDefang::Core;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(time_str date_str
                 synthesize_received_header copy_or_link);
our @EXPORT_OK = qw(read_results);

#***********************************************************************
# %PROCEDURE: time_str
# %ARGUMENTS:
#  None
# %RETURNS:
#  The current time in the form: "YYYY-MM-DD-HH:mm:ss"
# %DESCRIPTION:
#  Returns a string representing the current time.
#***********************************************************************
sub time_str {
    my($sec, $min, $hour, $mday, $mon, $year, $junk);
    ($sec, $min, $hour, $mday, $mon, $year, $junk) = localtime(time());
    return sprintf("%04d-%02d-%02d-%02d.%02d.%02d",
                   $year + 1900, $mon+1, $mday, $hour, $min, $sec);
}

#***********************************************************************
# %PROCEDURE: hour_str
# %ARGUMENTS:
#  None
# %RETURNS:
#  The current time in the form: "YYYY-MM-DD-HH"
# %DESCRIPTION:
#  Returns a string representing the current time.
#***********************************************************************
sub hour_str {
    my($sec, $min, $hour, $mday, $mon, $year, $junk);
    ($sec, $min, $hour, $mday, $mon, $year, $junk) = localtime(time());
    return sprintf('%04d-%02d-%02d-%02d', $year+1900, $mon+1, $mday, $hour);
}

#***********************************************************************
# %PROCEDURE: synthesize_received_header
# %ARGUMENTS:
#  None
# %RETURNS:
#  A "Received:" header for current message
# %DESCRIPTION:
#  Synthesizes a valid Received: header to reflect re-mailing.
#***********************************************************************
sub synthesize_received_header {
    my($hdr);

    my($hn) = $SendmailMacros{"if_name"};
    my($auth) = $SendmailMacros{"auth_authen"};

    my $strdate = Mail::MIMEDefang::RFC2822::rfc2822_date($CachedTimezone);

    $hn = Mail::MIMEDefang::Net::get_host_name() unless (defined($hn) and ($hn ne ""));
    if ($RealRelayHostname ne "[$RealRelayAddr]") {
      $hdr = "Received: from $Helo ($RealRelayHostname [$RealRelayAddr])\n";
    } else {
      $hdr = "Received: from $Helo ([$RealRelayAddr])\n";
    }
    if($auth) {
      $hdr .= "\tby $hn (envelope-sender $Sender) (MIMEDefang) with ESMTPA id $MsgID";
    } else {
      $hdr .= "\tby $hn (envelope-sender $Sender) (MIMEDefang) with ESMTP id $MsgID";
    }
    if ($#Recipients != 0) {
      $hdr .= "; ";
    } else {
      $hdr .= "\n\tfor " . $Recipients[0] . "; ";
    }

    $hdr .= $strdate . "\n";
    return $hdr;
}

#***********************************************************************
# %PROCEDURE: copy_or_link
# %ARGUMENTS:
#  src -- source filename
#  dest -- destination filename
# %RETURNS:
#  1 on success; 0 on failure.
# %DESCRIPTION:
#  Copies a file: First, attempts to make a hard link.  If that fails,
#  reads the file and copies the data.
#***********************************************************************
sub copy_or_link {
    my($src, $dst) = @_;
    return 1 if link($src, $dst);

    # Link failed; do it the hard way
    open(IN, "<$src") or return 0;
    if (!open(OUT, ">$dst")) {
        close(IN);
        return 0;
    }
    my($n, $string);
    while (($n = read(IN, $string, 4096)) > 0) {
        print OUT $string;
    }
    close(IN);
    close(OUT);
    return 1;
}

#***********************************************************************
# %PROCEDURE: read_results
# %ARGUMENTS:
# %RETURNS:
#  array of extracted from RESULTS file.
# %DESCRIPTION:
#  Extracts an array of command, key, values from RESULTS file,
#  needed for regression tests
#***********************************************************************
sub read_results
{
  my ($line, @res);
  my $fh = IO::File->new('./RESULTS', "r");
  while($line = <$fh>) {
    if($line =~ /([A-Z]{1})([A-Z-]+)\s([^\s]+)\s(.+)/i) {
        push(@res, [$1, $2, percent_decode($3), percent_decode($4)]);
    } elsif($line =~ /([A-Z]{1})([A-Z-]+)\s(.+)/i) {
        push(@res, [$1, $2, percent_decode($3)]);
    }
  }
  undef $fh;
  return @res;
}

1;
