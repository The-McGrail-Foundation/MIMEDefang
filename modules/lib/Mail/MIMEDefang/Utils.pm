#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Utils - Support methods used internally or by email filters

=head1 DESCRIPTION

Mail::MIMEDefang::Utils are a set of methods that can be called
from F<mimedefang-filter> or by other methods.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Utils;

use strict;
use warnings;

use Carp;
use MIME::Words qw(:all);

use Mail::MIMEDefang;
use Mail::MIMEDefang::RFC2822;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(time_str date_str hour_str
                 synthesize_received_header copy_or_link
                 re_match re_match_ext re_match_in_rar_directory re_match_in_zip_directory
                 re_match_in_7zip_directory re_match_in_tgz_directory md_copy_orig_msg_to_work_dir_as_mbox_file read_results);
our @EXPORT_OK = qw(md_init gen_mx_id);

=item time_str

Method that returns a string representing the current time.

=cut

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

=item hour_str

Method that returns a string representing the current hour.

=cut

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

=item synthesize_received_header

Method that synthesizes a valid Received: header to reflect re-mailing.
Needed by Apache SpamAssassin to correctly parse email messages.

=cut

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
    my($tls_version) = $SendmailMacros{"tls_version"};

    my $strdate = Mail::MIMEDefang::RFC2822::rfc2822_date($CachedTimezone);

    $hn = Mail::MIMEDefang::Net::get_host_name() unless (defined($hn) and ($hn ne ""));
    my $relay = $RealRelayHostname;
    if($relay eq "") {
      $relay = Mail::MIMEDefang::Net::get_ptr_record($RealRelayAddr);
    }
    if ($relay ne "[$RealRelayAddr]") {
      $hdr = "Received: from $Helo ($relay [$RealRelayAddr])\n";
    } else {
      $hdr = "Received: from $Helo ([$RealRelayAddr])\n";
    }
    if($auth) {
      $hdr .= "\tby $hn (envelope-sender $Sender) (MIMEDefang) with ESMTP";
      if($tls_version) {
        $hdr .= "S";
      }
      $hdr .= "A id $MsgID";
    } else {
      $hdr .= "\tby $hn (envelope-sender $Sender) (MIMEDefang) with ESMTP";
      if($tls_version) {
        $hdr .= "S";
      }
      $hdr .= " id $MsgID";
    }
    if ($#Recipients != 0) {
      $hdr .= "; ";
    } else {
      $hdr .= "\n\tfor " . $Recipients[0] . "; ";
    }

    $hdr .= $strdate . "\n";
    return $hdr;
}

=item copy_or_link

Method that copies a file if it fails to create an hard link
to the original file.

=cut

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
    open(IN, "<", "$src") or return 0;
    if (!open(OUT, ">", "$dst")) {
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

=item read_results

Method that extracts an array of command, key, values from RESULTS file,
needed for regression tests.

=cut

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

=item re_match

Method that returns 1 if either Content-Disposition.filename or
Content-Type.name matches the regexp; 0 otherwise.

=cut

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

=item re_match_ext

Method that returns 1 if the EXTENSION part of either
Content-Disposition.filename or Content-Type.name matches regexp; 0 otherwise.

=cut

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

=item re_match_in_rar_directory

Method that returns 1 if the EXTENSION part of any file in the rar archive
matches regexp.
To enable the check $Features{'unrar'} should be enabled.

=cut

#***********************************************************************
# %PROCEDURE: re_match_in_rar_directory
# %ARGUMENTS:
#  fname -- name of RAR file
#  regexp -- a regular expression
# %RETURNS:
#  1 if the EXTENSION part of any file in the rar archive matches regexp
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
                        || croak "can't open @unrar_args|: $!";
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

=item re_match_in_7zip_directory

Method that returns 1 if the EXTENSION part of any file in the 7zip archive
matches regexp.
To enable the check $Features{'7zip'} should be enabled.

=cut

#***********************************************************************
# %PROCEDURE: re_match_in_7zip_directory
# %ARGUMENTS:
#  fname -- name of 7zip file
#  regexp -- a regular expression
# %RETURNS:
#  1 if the EXTENSION part of any file in the 7zip archive matches regexp
#  Matching is case-insensitive.
# %DESCRIPTION:
#  A helper function for filter.
#***********************************************************************
sub re_match_in_7zip_directory {
  my($zname, $regexp) = @_;
  my ($rf, $beginmark, $file);

  my @unz_args = ("7za", "l", $zname);

  unless ($Features{"7zip"}) {
          md_syslog('err', "Attempted to use re_match_in_7zip_directory, but 7zip binary is not installed.");
          return 0;
  }

  if ( -f $zname ) {
    open(UNZ_PIPE, "-|", @unz_args)
                        || croak "can't open @unz_args|: $!";
    while(<UNZ_PIPE>) {
      $rf = $_;
      if ( $beginmark and ( $rf !~ /^\-\-\-/ ) ) {
        $rf =~ /([0-9-]+)\s+([0-9\:]+)\s+([\.[A-Za-z]+)\s+([0-9]+)\s+([0-9]+)\s+(.*)/;
        $file = $6;
              return 1 if ((defined $file) and ($file =~ /$regexp/i));
      }
      last if ( $beginmark and ( $rf !~ /^\-\-\-/ ) );
      $beginmark = 1 if ( $rf =~ /^\-\-\-/ );
    }
    close(UNZ_PIPE);
  }

  return 0;
}

=item re_match_in_tgz_directory

Method that returns 1 if the EXTENSION part of any file in the tgz archive
matches regexp.
To enable the check $Features{'tar'} should be enabled.

=cut

#***********************************************************************
# %PROCEDURE: re_match_in_tgz_directory
# %ARGUMENTS:
#  fname -- name of tgz file
#  regexp -- a regular expression
# %RETURNS:
#  1 if the EXTENSION part of any file in the tgz archive matches regexp
#  Matching is case-insensitive.
# %DESCRIPTION:
#  A helper function for filter.
#***********************************************************************
sub re_match_in_tgz_directory {
  my($zname, $regexp) = @_;
  my ($rf, $beginmark, $file);

  my @unz_args;
  if($zname =~ /\.tar/) {
    @unz_args = ("tar", "tvf", $zname);
  } elsif($zname =~ /\.tar\.bz2/) {
    @unz_args = ("tar", "jtvf", $zname);
  } elsif($zname =~ /\.(?:tar\.gz|tgz)/) {
    @unz_args = ("tar", "ztvf", $zname);
  } else {
    md_syslog('err', "Attempted to use re_match_in_tgz_directory, but filename $zname is not supported.");
    return 0;
  }

  unless ($Features{"tar"}) {
          md_syslog('err', "Attempted to use re_match_in_tgz_directory, but tar binary is not installed.");
          return 0;
  }

  if ( -f $zname ) {
    open(UNZ_PIPE, "-|", @unz_args)
                        || croak "can't open @unz_args|: $!";
    while(<UNZ_PIPE>) {
      if(/(?:[a-z-]+)\s+(?:.*)\s+(?:\d+)\s+(?:\d+\-\d+\-\d+)\s+(?:\d+\:\d+)\s+(.*)/) {
        $file = $1;
              return 1 if ((defined $file) and ($file =~ /$regexp/i));
      }
    }
    close(UNZ_PIPE);
  }

  return 0;
}

=item re_match_in_zip_directory

Method that returns 1 if the EXTENSION part of any file in the zip archive
matches regexp.

=cut

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
sub dummy_zip_error_handler {} ;

sub md_init {
  my $use_zip = 0;
  if (!defined($Features{"Archive::Zip"}) or ($Features{"Archive::Zip"} eq 1)) {
    (eval 'use Archive::Zip qw( :ERROR_CODES ); $use_zip = 1;')
    or $use_zip = 0;
  }
  $Features{"Archive::Zip"} = $use_zip;
}

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

=item md_copy_orig_msg_to_work_dir_as_mbox_file

Method that copies original INPUTMSG file into work directory for virus-scanning
as a valid mbox file.

=cut

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
  open(IN, "<", "INPUTMSG") or return 0;
  unless (open(OUT, ">", "Work/INPUTMBOX")) {
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

=item gen_mx_id

Method that generates a random indentifier used by MIMEDefang
to create temporary files.

=cut

#***********************************************************************
# %PROCEDURE: gen_mx_id
# %ARGUMENTS:
#  None
# %DESCRIPTION:
#  Generates a random indentifier
# %RETURNS:
#  the random string.
#***********************************************************************
sub gen_mx_id {
  my @out;
  my $counter;

  # Our identifiers are in base-60
  use constant BASE => 60;
  # Our time-based identifier is 5 base-60 characters.
  use constant TIMESPAN => 60*60*60*60*60;
  # Our identifier is 7 chars long
  use constant MX_ID_LEN => 7;

  $counter++;
  my @char_map = split(//, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX");
  my $time_part = time % TIMESPAN;

  for (my $i=4; $i>=0; $i--) {
    $out[$i] = $char_map[$time_part % BASE];
    $time_part /= BASE;
  }
  for (my $i=6; $i>=5; $i--) {
    $out[$i] = $char_map[$counter % BASE];
    $counter /= BASE;
  }
  $out[MX_ID_LEN - 1] = 0;
  return join('', @out);
}

=back

=cut

1;
