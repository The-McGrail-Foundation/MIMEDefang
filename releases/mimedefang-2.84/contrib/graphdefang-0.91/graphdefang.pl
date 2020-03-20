#!/usr/bin/perl -w
#
# GraphDefang -- a set of tools to create graphs of your mimedefang
#                spam and virus logs.
#
# Written by:    John Kirkland
#                jpk@bl.org
#
# Copyright (c) 2002-2003, John Kirkland
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#=============================================================================

use strict;
use vars qw($MYDIR $OUTPUT_DIR $SUMMARYDB $QUIET $NODB $DATAFILE @DATAFILES @GRAPHS %TZ);

# Argument parsing
use Getopt::Long;
use Pod::Usage;

$QUIET = 0;	# No output
$NODB = 0;	# Don't use SummaryDB, just produce charts from logfile
my $trim = 0;	# Trim database
my $nomax = 0;	# Ignore max date/time
my $help = 0;	# Show help?
my $man = 0;	# Show bigger help?
my $file;	# Log file to parse (optional)

GetOptions( 	'quiet'  => \$QUIET,
		'nodb' 	 => \$NODB,
		'trim'   => \$trim,
		'nomax'  => \$nomax,
		'help|?' => \$help,
		'man'	 => \$man,
		'file=s' => \$file ) or pod2usage(2);;

pod2usage(1) if $help;
pod2usage(-exitstatus => 0, -verbose => 2) if $man;

# Get the directory from where graphdefang.pl is running
use File::Basename ();
($MYDIR) = (File::Basename::dirname($0) =~ /(.*)/);

# Get graph configurations
require("$MYDIR/graphdefang-config");

# Require the graphdefang library file
require ("$MYDIR/graphdefanglib.pl");

#
# Path to summary database
#

$SUMMARYDB = "$MYDIR/SummaryDB.db";

# Do we do a database trim?
if ($trim) {
	print STDERR "Beginning SummaryDB Trim\n" if (!$QUIET);
	trim_database();
	print STDERR "Completed SummaryDB Trim\n" if (!$QUIET);
	exit;
}

# Did the user specify a file on the command line?
$DATAFILE = $file if (defined($file));

my %DataSummary;

if ($DATAFILE) {

	print STDERR "Processing data file: $DATAFILE\n" if (!$QUIET);

	# Open DATAFILE and Summarize It

	%DataSummary = read_and_summarize_data($DATAFILE, $nomax)
        	or die "No valid mimedefang logs in $DATAFILE";

} elsif (@DATAFILES) {

	foreach my $datafile (@DATAFILES) {
		print STDERR "Processing data file: $datafile\n" if (!$QUIET);
		%DataSummary = read_and_summarize_data($datafile, $nomax)
			or die "No valid mimedefang logs in $datafile";
	}
} else {
	# No DATAFILE or DATAFILES specified!
	die "No DATAFILES specified on the command line or in your config file";
}

print STDERR "Processing graphs\n" if (!$QUIET);

# Draw graphs
foreach my $settings (@GRAPHS) {
	graph(\%{$settings}, \%DataSummary);
}

__END__

=head1 graphdefang.pl

Application for generating graphs from mimedefang log files.

=head1 SYNOPSIS

graphdefang.pl [options]

Options:
  --help            brief help message
  --man             full documentation
  --quiet           quiet output
  --nodb            do not update SummaryDB
  --trim            trim the SummaryDB
  --nomax           ignore the max date/time in SummaryDB
  --file            optional log file to parse

If called with no options, graphdefang.pl will parse the
logfile as defined by the $DATAFILE variable.

=head1 OPTIONS

=over 8

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=item B<--quiet>

Do not produce status output from mimedefang.pl.

=item B<--nodb>

Do not use nor update the SummaryDB, just parse the file and draw graphs from it.

=item B<--trim>

Trim the SummaryDB to cut out old data.  It trims out:
1.  hourly data older than 1.25x$NUM_HOURS_SUMMARY hours
2.  daily data older than 1.25x$NUM_DAYS_SUMMARY days
3.  all but top 25 sender, recipient, value1, value2, subject values
    for all dates prior to the current hour, day, and month..

=item B<--nomax>

Ignore the max date/time in the SummaryDB; add all lines from the parsed
file to the database.

=item B<--file>

Optional log file to parse.  If this option is not set, graphdefang
will use the $DATAFILE variable.

=back

=head1 DESCRIPTION

B<graphdefang.pl> will read a file that contains syslog messages from
mimedefang, update its internal summary database, and produce graphs
as requested by the user.

=cut
