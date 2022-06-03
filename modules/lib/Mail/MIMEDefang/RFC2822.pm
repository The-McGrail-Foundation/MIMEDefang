#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::RFC2822 - Dates related methods for email filters

=head1 DESCRIPTION

Mail::MIMEDefang::RFC2822 are a set of methods that can be called
from F<mimedefang-filter> to create RFC2822 formatted dates.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::RFC2822;

use strict;
use warnings;

use Time::Local;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(gen_date_msgid_headers);
our @EXPORT_OK = qw(header_timezone rfc2822_date gen_msgid_header);

=item gen_date_msgid_headers

Method that generates RFC2822 compliant Date and Message-ID headers.

=cut

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

=item rfc2822_date

Method that returns an RFC2822 formatted date.

=cut

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

=item header_timezone

Method that returns an RFC2822 compliant timezone header.

=cut

sub header_timezone
{
  my ($CachedTimezone, $now) = @_;

    return $CachedTimezone if ((defined $CachedTimezone) and ($CachedTimezone ne ""));

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

=item gen_msgid_header

Method that generates RFC2822 compliant Message-ID headers.

=cut

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

=back

=cut

1;
