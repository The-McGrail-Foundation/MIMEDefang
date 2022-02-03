package Mail::MIMEDefang::Utils;

use strict;
use warnings;

use MIME::Words qw(:all);

use Mail::MIMEDefang;
use Mail::MIMEDefang::RFC2822;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(time_str date_str
                 synthesize_received_header copy_or_link
                 re_match re_match_ext re_match_in_rar_directory re_match_in_zip_directory
                 md_copy_orig_msg_to_work_dir_as_mbox_file);
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

#***********************************************************************
# %PROCEDURE: re_match
# %ARGUMENTS:
#  entity -- a MIME entity
#  regexp -- a regular expression
# %RETURNS:
#  1 if either of Content-Disposition.filename or Content-Type.name
#  matches regexp; 0 otherwise.  Matching is
#  case-insensitive
# %DESCRIPTION:
#  A helper function for filter.
#***********************************************************************
sub re_match {
  my($entity, $regexp) = @_;
  my($head) = $entity->head;

  my($guess) = $head->mime_attr("Content-Disposition.filename");
  if (defined($guess)) {
	  $guess = decode_mimewords($guess);
	  return 1 if $guess =~ /$regexp/i;
  }

  $guess = $head->mime_attr("Content-Type.name");
  if (defined($guess)) {
	  $guess = decode_mimewords($guess);
	  return 1 if $guess =~ /$regexp/i;
  }

  return 0;
}

#***********************************************************************
# %PROCEDURE: re_match_ext
# %ARGUMENTS:
#  entity -- a MIME entity
#  regexp -- a regular expression
# %RETURNS:
#  1 if the EXTENSION part of either of Content-Disposition.filename or
#  Content-Type.name matches regexp; 0 otherwise.
#  Matching is case-insensitive.
# %DESCRIPTION:
#  A helper function for filter.
#***********************************************************************
sub re_match_ext {
  my($entity, $regexp) = @_;
  my($ext);
  my($head) = $entity->head;

  my($guess) = $head->mime_attr("Content-Disposition.filename");
  if (defined($guess)) {
	  $guess = decode_mimewords($guess);
	  return 1 if (($guess =~ /(\.[^.]*)$/) && ($1 =~ /$regexp/i));
  }

  $guess = $head->mime_attr("Content-Type.name");
  if (defined($guess)) {
	  $guess = decode_mimewords($guess);
	  return 1 if (($guess =~ /(\.[^.]*)$/) && ($1 =~ /$regexp/i));
  }

  return 0;
}

#***********************************************************************
# %PROCEDURE: re_match_in_rar_directory
# %ARGUMENTS:
#  fname -- name of RAR file
#  regexp -- a regular expression
# %RETURNS:
#  1 if the EXTENSION part of any file in the zip archive matches regexp
#  Matching is case-insensitive.
# %DESCRIPTION:
#  A helper function for filter.
#***********************************************************************
sub re_match_in_rar_directory {
  my($rarname, $regexp) = @_;
  my ($rf, $beginmark, $file);

  my @unrar_args = ("unrar", "l", "-c-", "-p-", "-idcdp", $rarname);

  unless ($Features{"unrar"}) {
	  md_syslog('err', "Attempted to use re_match_in_rar_directory, but unrar binary is not installed.");
	  return 0;
  }

  if ( -f $rarname ) {
    open(UNRAR_PIPE, "-|", @unrar_args)
                        || die "can't open @unrar_args|: $!";
    while(<UNRAR_PIPE>) {
      $rf = $_;
      if ( $beginmark and ( $rf !~ /^\-\-\-/ ) ) {
        $rf =~ /([12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))\s(\d+\:\d+)\s+(.*)/;
        $file = $5;
	      return 1 if ((defined $file) and ($file =~ /$regexp/i));
      }
      last if ( $beginmark and ( $rf !~ /^\-\-\-/ ) );
      $beginmark = 1 if ( $rf =~ /^\-\-\-/ );
    }
    close(UNRAR_PIPE);
  }

  return 0;
}

#***********************************************************************
# %PROCEDURE: re_match_in_7zip_directory
# %ARGUMENTS:
#  fname -- name of 7zip file
#  regexp -- a regular expression
# %RETURNS:
#  1 if the EXTENSION part of any file in the zip archive matches regexp
#  Matching is case-insensitive.
# %DESCRIPTION:
#  A helper function for filter.
#***********************************************************************
sub re_match_in_7zip_directory {
  my($zname, $regexp) = @_;
  my ($rf, $beginmark, $file);

  my @unz_args = ("7z", "l", $zname);

  unless ($Features{"7zip"}) {
          md_syslog('err', "Attempted to use re_match_in_7zip_directory, but 7zip binary is not installed.");
          return 0;
  }

  if ( -f $zname ) {
    open(UNZ_PIPE, "-|", @unz_args)
                        || die "can't open @unz_args|: $!";
    while(<UNZ_PIPE>) {
      $rf = $_;
      if ( $beginmark and ( $rf !~ /^\-\-\-/ ) ) {
        $rf =~ /([0-9-]+)\s+([0-9\:]+)\s+([\.[A-Za-z]+)\s+([0-9]+)\s+([0-9]+)\s+(.*)/;
        $file = $6;
        print $file;
              return 1 if ((defined $file) and ($file =~ /$regexp/i));
      }
      last if ( $beginmark and ( $rf !~ /^\-\-\-/ ) );
      $beginmark = 1 if ( $rf =~ /^\-\-\-/ );
    }
    close(UNZ_PIPE);
  }

  return 0;
}

#***********************************************************************
# %PROCEDURE: re_match_in_zip_directory
# %ARGUMENTS:
#  fname -- name of ZIP file
#  regexp -- a regular expression
# %RETURNS:
#  1 if the EXTENSION part of any file in the zip archive matches regexp
#  Matching is case-insensitive.
# %DESCRIPTION:
#  A helper function for filter.
#***********************************************************************
no strict 'subs';
sub dummy_zip_error_handler {} ;

sub re_match_in_zip_directory {
  my($zipname, $regexp) = @_;
  unless ($Features{"Archive::Zip"}) {
	  md_syslog('err', "Attempted to use re_match_in_zip_directory, but Perl module Archive::Zip is not installed.");
	  return 0;
  }
  my $zip = Archive::Zip->new();

  # Prevent carping about errors
  Archive::Zip::setErrorHandler(\&dummy_zip_error_handler);
  if ($zip->read($zipname) == AZ_OK()) {
	  foreach my $member ($zip->members()) {
	    my $file = $member->fileName();
	    return 1 if ($file =~ /$regexp/i);
	  }
  }

  return 0;
}
use strict 'subs';

#***********************************************************************
# %PROCEDURE: md_copy_orig_msg_to_work_dir_as_mbox_file
# %ARGUMENTS:
#  None
# %DESCRIPTION:
#  Copies original INPUTMSG file into work directory for virus-scanning
#  as a valid mbox file (adds the "From $Sender mumble..." stuff.)
# %RETURNS:
#  1 on success, 0 on failure.
#***********************************************************************
sub md_copy_orig_msg_to_work_dir_as_mbox_file {
  return if (!in_message_context("md_copy_orig_msg_to_work_dir_as_mbox_file"));
  open(IN, "<INPUTMSG") or return 0;
  unless (open(OUT, ">Work/INPUTMBOX")) {
	  close(IN);
	  return 0;
  }

  # Remove angle-brackets for From_ line
  my $s = $Sender;
  $s =~ s/^<//;
  $s =~ s/>$//;

  print OUT "From $s " . Mail::MIMEDefang::RFC2822::rfc2822_date($CachedTimezone) . "\n";
  my($n, $string);
  while (($n = read(IN, $string, 4096)) > 0) {
	  print OUT $string;
  }
  close(IN);
  close(OUT);
  return 1;
}

1;
