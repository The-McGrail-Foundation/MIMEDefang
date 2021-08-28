package MIMEDefang::RFC2822;

use strict;
use warnings;

use Time::Local;

#***********************************************************************
# %PROCEDURE: gen_date_msgid_headers
# %ARGUMENTS:
#  None
# %RETURNS:
#  A string like this: "Date: <rfc2822-date>\nMessage-ID: <message@id.com>\n"
# %DESCRIPTION:
#  Generates RFC2822-compliant Date and Message-ID headers.
#***********************************************************************
sub gen_date_msgid_headers {
  my ($msgid_header) = @_;
  return "Date: " . rfc2822_date() . "\n" . $msgid_header;
}

sub rfc2822_date
{
	my ($CachedTimezone) = @_;

	my $now = time();
	my ($ss, $mm, $hh, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($now);
	return sprintf("%s, %02d %s %04d %02d:%02d:%02d %s",
		(qw( Sun Mon Tue Wed Thu Fri Sat ))[$wday],
		$mday,
		(qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec ))[$mon],
		$year + 1900,
		$hh,
		$mm,
		$ss,
		header_timezone($CachedTimezone, $now)
	);
}

sub header_timezone
{
  my ($CachedTimezone, $now) = @_;

    return $CachedTimezone if ($CachedTimezone ne "");

    my($sec, $min, $hr, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($now);
    my $a = timelocal($sec, $min, $hr, $mday, $mon, $year);
    my $b = timegm($sec, $min, $hr, $mday, $mon, $year);
    my $c = ($b - $a) / 60;
    $hr = int(abs($c) / 60);
    $min = abs($c) - 60 * $hr;

    if ($c >= 0) {
	  $CachedTimezone = sprintf("+%02d%02d", $hr, $min);
    } else {
	  $CachedTimezone = sprintf("-%02d%02d", $hr, $min);
    }
    return $CachedTimezone;
}

#***********************************************************************
# %PROCEDURE: gen_msgid_header
# %ARGUMENTS:
#  None
# %RETURNS:
#  A string like this: "Message-ID: <message@id.com>\n"
# %DESCRIPTION:
#  Generates RFC2822-compliant Message-ID headers.
#***********************************************************************
sub gen_msgid_header {
	my ($QueueID, $hostname) = @_;

	my ($ss, $mm, $hh, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(time);

	# Generate a "random" message ID that looks
	# similiar to sendmail's for SpamAssassin comparing
	# Received / MessageID QueueID
	return sprintf("Message-ID: <%04d%02d%02d%02d%02d.%s\@%s>\n",
		$year + 1900,
		$mon  + 1,
		$mday,
		$hh,
		$mm,
		($QueueID eq 'NOQUEUE' ? rand() : $QueueID),
		$hostname
	);
}

1;
