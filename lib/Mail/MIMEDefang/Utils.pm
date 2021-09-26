package Mail::MIMEDefang::Utils;

use strict;
use warnings;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(percent_encode percent_encode_for_graphdefang
                 percent_decode md_syslog time_str date_str);

use Mail::MIMEDefang::Core;
use Sys::Syslog;

my $_syslogopen = undef;

#***********************************************************************
# %PROCEDURE: percent_encode
# %ARGUMENTS:
#  str -- a string, possibly with newlines and control characters
# %RETURNS:
#  A string with unsafe chars encoded as "%XY" where X and Y are hex
#  digits.  For example:
#  "foo\r\nbar\tbl%t" ==> "foo%0D%0Abar%09bl%25t"
#***********************************************************************
sub percent_encode {
  my($str) = @_;

  $str =~ s/([^\x21-\x7e]|[%\\'"])/sprintf("%%%02X", unpack("C", $1))/ge;
  #" Fix emacs highlighting...
  return $str;
}

#***********************************************************************
# %PROCEDURE: percent_encode_for_graphdefang
# %ARGUMENTS:
#  str -- a string, possibly with newlines and control characters
# %RETURNS:
#  A string with unsafe chars encoded as "%XY" where X and Y are hex
#  digits.  For example:
#  "foo\r\nbar\tbl%t" ==> "foo%0D%0Abar%09bl%25t"
# This differs slightly from percent_encode because we don't encode
# quotes or spaces, but we do encode commas.
#***********************************************************************
sub percent_encode_for_graphdefang {
  my($str) = @_;
  $str =~ s/([^\x20-\x7e]|[%\\,])/sprintf("%%%02X", unpack("C", $1))/ge;
  #" Fix emacs highlighting...
  return $str;
}

#***********************************************************************
# %PROCEDURE: percent_decode
# %ARGUMENTS:
#  str -- a string encoded by percent_encode
# %RETURNS:
#  The decoded string.  For example:
#  "foo%0D%0Abar%09bl%25t" ==> "foo\r\nbar\tbl%t"
#***********************************************************************
sub percent_decode {
  my($str) = @_;
  $str =~ s/%([0-9A-Fa-f]{2})/pack("C", hex($1))/ge;
  return $str;
}

#***********************************************************************
# %PROCEDURE: md_syslog
# %ARGUMENTS:
#  facility -- Syslog facility as a string
#  msg -- message to log
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Calls syslog, using Sys::Syslog package
#***********************************************************************
sub md_syslog
{
  my ($facility, $msg) = @_;

  if(!$_syslogopen) {
    md_openlog('mimedefang.pl', $SyslogFacility);
  }

  if (defined $MsgID && $MsgID ne 'NOQUEUE') {
    return Sys::Syslog::syslog($facility, '%s', $MsgID . ': ' . $msg);
  } else {
    return Sys::Syslog::syslog($facility, '%s', $msg);
  }
}

#***********************************************************************
# %PROCEDURE: md_openlog
# %ARGUMENTS:
#  tag -- syslog tag ("mimedefang.pl")
#  facility -- Syslog facility as a string
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Opens a log using Sys::Syslog
#***********************************************************************
sub md_openlog
{
  my ($tag, $facility) = @_;
  return Sys::Syslog::openlog($tag, 'pid,ndelay', $facility);
}

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

1;
