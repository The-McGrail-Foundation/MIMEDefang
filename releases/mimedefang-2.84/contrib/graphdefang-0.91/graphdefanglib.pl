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
use Time::Local;
use Time::Zone;
use Date::Parse;
use Date::Format;
use Data::Dumper;
use File::ReadBackwards;

use MLDBM qw(DB_File Storable);
use Fcntl;

use File::Copy;	# for move() function

use GD::Graph::linespoints;
use GD::Graph::bars;

# X and Y Graph Sizes in pixels

my $X_GRAPH_SIZE = 700;
my $Y_GRAPH_SIZE = 300;

# Number of hours, days, and months in the hourly, daily, and monthly charts, respectively.

my $NUM_HOURS_SUMMARY = 48;
my $NUM_DAYS_SUMMARY = 60;
my $NUM_MONTH_SUMMARY = 24;

sub get_unixtime_by_timesummary($$) {
	my $timesummary = shift;
	my $unixtime = shift;
	
	# Get the number of seconds past the day for a given unixtime
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($unixtime);

	# zero out appropriate seconds,minutes,hours,days,etc...
	$sec = 0; #if ($timesummary =~ m/hourly|daily|monthly/);
	$min = 0; #if ($timesummary =~ m/hourly|daily|monthly/);
	$hour = 0 if ($timesummary ne 'hourly');
	$mday = 1 if ($timesummary eq 'monthly');
	
	# get unixtime for our new values
	$unixtime = timelocal($sec, $min, $hour, $mday, $mon, $year);

	return $unixtime;
}

sub trim_database() {

	my %data_db = ();
	my %data = ();

	read_summarydb(\%data, O_RDONLY);

	# Start the DB Trim

	my $now = time();
	my $trimcounter = 0;

	# Delete hourly data older than 1.25*$NUM_HOURS_SUMMARY hours

	my $deletetime = get_unixtime_by_timesummary('hourly',$now - 1.25*$NUM_HOURS_SUMMARY*60*60);

	foreach my $entrytime (keys %{$data{'hourly'}}) {
		if ($entrytime < $deletetime) {
			delete($data{'hourly'}{$entrytime});
			$trimcounter++;
		}
	}

	print STDERR "\tTrimmed $trimcounter 'hourly' entries from SummaryDB\n" if (!$QUIET);

	# Delete daily data older than 1.25*$NUM_DAYS_SUMMARY days

	$deletetime = get_unixtime_by_timesummary('daily',$now - 1.25*$NUM_DAYS_SUMMARY*60*60*24);
	$trimcounter=0;

	foreach my $entrytime (keys %{$data{'daily'}}) {
		if ($entrytime < $deletetime) {
			delete $data{'daily'}{$entrytime};
			$trimcounter++;
		}
	}

	print STDERR "\tTrimmed $trimcounter 'daily' entries from SummaryDB\n" if (!$QUIET);

	# Delete all but Top25 entries in hours, days, and months
	# other than the current one!
	
	my @DeleteTimes = ('hourly', 'daily', 'monthly');
	$trimcounter = 0;

	foreach my $deletetime (@DeleteTimes) {
		my $nowdeletetime = get_unixtime_by_timesummary($deletetime,$now);
		foreach my $entrytime (keys %{$data{$deletetime}}) {
			if ($entrytime < $nowdeletetime ) {
			foreach my $event (keys %{$data{$deletetime}{$entrytime}}) {
				foreach my $type (keys %{$data{$deletetime}{$entrytime}{$event}}) {
					if ($type ne 'summary') {
						my %total = ();
						foreach my $value (keys %{$data{$deletetime}{$entrytime}{$event}{$type}}) {
							$total{$value} = $data{$deletetime}{$entrytime}{$event}{$type}{$value};
						}
						# Create list of top 25 items.
						my $i = 0;
						my %keep = ();
						foreach my $TopName (sort { $total{$b} <=> $total{$a} } keys %total) {
							$keep{$TopName} = 1;
							$i++;
							last if $i >= 25;
						}
						# delete the entries unless it is in the topList.
						foreach my $value (keys %{$data{$deletetime}{$entrytime}{$event}{$type}}) {
							if (!defined($keep{$value})) {
								delete $data{$deletetime}{$entrytime}{$event}{$type}{$value};
								$trimcounter++;
							}
						}
					}
				}
			}
			}
		}
	}

	print STDERR "\tTrimmed $trimcounter 'non top25' entries from SummaryDB\n" if (!$QUIET);	

	backup_and_save_summarydb(\%data);
}

sub read_summarydb($$) {

	my $data = shift;
	my $method = shift;
	my %data_db; 

	tie (%data_db, 'MLDBM', $SUMMARYDB, $method, 0644)
		or die "Can't open $SUMMARYDB:$!\n";
	%$data = %data_db;
	untie %data_db;
}

sub backup_and_save_summarydb($) {
	my $dataPtr = shift;
	my %data_db;

	# Backup the old summarydb file and recreate it using the new data

	move("$SUMMARYDB", "$SUMMARYDB.bak")
		or die "Can't move $SUMMARYDB to $SUMMARYDB.bak: $!";

	tie (%data_db, 'MLDBM', $SUMMARYDB, O_RDWR|O_CREAT, 0644)
		or die "Can't open $SUMMARYDB:$!\n";

	%data_db = %$dataPtr;

	untie %data_db
		or die "Database Save Failed... restore from $SUMMARYDB.bak:$!\n";
# Leave the .bak around in case the original got corrupted.
#	unlink ("$SUMMARYDB.bak")
#		or die "Can't unlink $SUMMARYDB.bak:$!\n";

	return 1;
}

sub read_and_summarize_data($$) {
	use vars qw(%event $text $pid %spamd %user_unknown $event $value1 $value2 $sender $recipient $subject $NumEvents $FoundNewRow $unixtime $MaxDBUnixTime);
        my $fn = shift;
	my $nomax = shift;
        my %data = ();
	my %data_db = ();

	# Temporary variable for lookup information	
	%spamd = ();

	my %NumNewLines;
	
	# Set graphtimes
	my @GraphTimes = ("hourly","daily","monthly");

	# Load event processing perl code from the events subdirectory
	my $dirname = "$MYDIR/event";
	opendir(DIR, $dirname) or die "can't opendir $dirname: $!";
	while (defined(my $file = readdir(DIR))) {
		if (!($file =~ m/^\./) and !($file =~ m/^CVS/)) {
			# do nothing if file starts with '.'
			opendir(SUBDIR, "$dirname/$file") or die "can't opendir $dirname/$file: $!";
			while (defined(my $file2 = readdir(SUBDIR))) {
				if (!($file2 =~ m/^\./) and !($file2 =~ m/^CVS/)) {
					require "$dirname/$file/$file2";
				}
			}
		}
	}
	closedir(SUBDIR);
	closedir(DIR);

	# Open SummaryDB
	read_summarydb(\%data, O_RDONLY|O_CREAT) if (!$NODB);
       
	# Open log file 
	tie *ZZZ, 'File::ReadBackwards', $fn || die("can't open datafile: $!");

	# Get max unixtime value from DBM file 
	# This is left here for backwards compatibility... we now track MAX times per host 
	# to support log files from multiples hosts.
	$MaxDBUnixTime = 0;
	if (!$nomax && defined($data{'max'})) {
		$MaxDBUnixTime = $data{'max'};
		# delete the max entry 'cuz we won't use it again
		delete($data{'max'});
		print STDERR "\tConverting to host-based max times\n" if (!$QUIET and !$NODB);
		print STDERR "\tPrevious Max Unixtime from SummaryDB:  $MaxDBUnixTime\n" if (!$QUIET and !$NODB);
	} 

	# print out the list of max times per host
	my %ReadMaxHostTime;
	if (defined($data{'maxhosttime'})) {
		foreach my $host (sort keys %{$data{'maxhosttime'}}) {
			$ReadMaxHostTime{$host} = $data{'maxhosttime'}{$host};
			print STDERR "\tMax Unixtime from SummaryDB for $host: $data{'maxhosttime'}{$host}\n" if (!$QUIET and !$NODB);
		}
	} 

        while (<ZZZ>) {

                chomp;

		# Parse syslog line

		m/^(\S+\s+\d+\s+\d+:\d+:\d+)\s		# datestring -- 1
		(\S+)\s					# host -- 2
		(\S+?)					# program -- 3
		(?:\[(\d+)\])?:\s			# pid -- 4
		(?:\[ID\ \d+\ [a-z0-9]+\.[a-z]+\]\ )?	# Solaris stuff -- not used
		(.*)/x;					# text -- 5

		my $datestring = $1;
		my $host = $2;
		my $program = $3;
		$pid = $4;
		$text = $5;
	
		# Parse date string from syslog using any TIMEZONE info from the config file.	
		if (defined $TZ{$host}) {
			my $zone = tz2zone($TZ{$host});
			$unixtime=str2time($datestring,$zone);
		} else {
			$unixtime=str2time($datestring);
		}

		# don't examine the line if it is greater than 5 minutes
		# older than the maximum time in our DB.  The 5 minutes
		# comes from the PID, From, and Relay caching with sendmail
		# and spamd that occurs below.
		$MaxDBUnixTime = $ReadMaxHostTime{$host} if (!$nomax && defined($ReadMaxHostTime{$host}));
		last if ($unixtime < ($MaxDBUnixTime-60*5));

		$event = '';
		$value1 = '';
		$value2 = '';
		$sender = '';
		$recipient = '';
		$subject = '';

		$NumEvents = 1;
		$FoundNewRow = 0;

		if (defined $event{$program}) {
			foreach my $subroutine (sort keys %{$event{$program}} ) {
				$event{$program}{$subroutine}->();
				last if ($FoundNewRow);
			}
		}

		if ($FoundNewRow) {
			# Increment Number of New Lines Found
			$NumNewLines{$host}++;

			# rollup hourly, daily, and monthly summaries for every variable
			foreach my $timesummary (@GraphTimes) {

				my $summarytime = get_unixtime_by_timesummary($timesummary, $unixtime);
				$data{$timesummary}{$summarytime}{$event}{'summary'}+=$NumEvents;
				$data{$timesummary}{$summarytime}{$event}{'value1'}{$value1}+=$NumEvents 	if ($value1 ne '');
				$data{$timesummary}{$summarytime}{$event}{'value2'}{$value2}+=$NumEvents	if ($value2 ne '');
				$data{$timesummary}{$summarytime}{$event}{'sender'}{$sender}+=$NumEvents	if ($sender ne '');;
				$data{$timesummary}{$summarytime}{$event}{'recipient'}{$recipient}+=$NumEvents 	if ($recipient ne '');
				$data{$timesummary}{$summarytime}{$event}{'subject'}{$subject}+=$NumEvents     	if ($subject ne '');

				# Store the maximum unixtime per timesummary for later reference
				$data{'maxhosttime'}{$host} = $unixtime 
					if (!defined($data{'maxhosttime'}{$host}) 
						or $unixtime > $data{'maxhosttime'}{$host});
			} 
		}
	}
        close (ZZZ);

	if (!$NODB) {
		if (backup_and_save_summarydb(\%data)) {
			if (%NumNewLines) {
				foreach my $host (sort keys %NumNewLines) {
					print STDERR "\t$NumNewLines{$host} new log lines processed for $host\n" if (!$QUIET);
				}
			} else {
				print STDERR "\t 0 new log lines processed\n" if (!$QUIET);
			}
		}
	}
        return %data;
}

sub get_all_data_types($) {

	my $dataPtr = shift;

	my %all;
	my @return_all;

	# get list of potential event values

	foreach my $date (keys %{$dataPtr->{monthly}}) {
		foreach my $data_type (keys %{$dataPtr->{monthly}{$date}}) {
			$all{$data_type} = 1;
		}
	}

	foreach my $key (sort keys %all) {
		push @return_all, $key;
	}


	return @return_all;
}

sub graph($$) {
	my $settings = shift;
	my $data = shift;

	foreach my $grouping_time (@{$settings->{grouping_times}}) {

		$settings->{grouping_time} = $grouping_time;


		# Set the settings for the graph we've been asked to draw
		set_graph_settings($settings);

		print STDERR "\t$settings->{chart_filename}\n" if (!$QUIET);

		# Get the data for the graph we've been asked to draw
		my @GraphData = get_graph_data($settings,$data);

        	# Draw Graph
        	if ($settings->{graph_type} eq 'line') {
                	draw_line_graph($settings,\@GraphData);
        	} elsif ($settings->{graph_type} eq 'stacked_bar') {
                	draw_stacked_bar_graph($settings,\@GraphData);
        	} else {
                	die ("Invalid GraphSettings{graph_type} = $settings->{graph_type}");
        	}
	}
}

sub set_graph_settings($) {

	my $settings = shift;

        # Set the graph title and filename according to the options chosen

        # Initialize the title and filename
        $settings->{chart_title} = "";
        $settings->{chart_filename} = "";

	my $autotitle = "";
	my $autofilename = "";

	# Set graph x & y dimensions

	$settings->{x_graph_size} = $X_GRAPH_SIZE if (!defined($settings->{x_graph_size}));
	$settings->{y_graph_size} = $Y_GRAPH_SIZE if (!defined($settings->{y_graph_size}));

        # Add "Top N" to the beginning of the Title if necessary
        if ($settings->{top_n}) {
                $autotitle = "Top $settings->{top_n} ";
        } 

        # Set Data Type Title
	my $i = 0;
	foreach my $data_type (@{$settings->{data_types}}) {
		# Uppercase the first letter of the data_type
		$autotitle .= "\u$data_type";
		$autofilename .= $data_type;
		$i++;
		if ( $i == ($#{$settings->{data_types}}) ) {
			$autotitle .= " and "
		} elsif ( $i < ($#{$settings->{data_types}}) ) {
			$autotitle .= ", "
		}
	}

        # Set Grouping Title
        if ($settings->{grouping} eq 'summary') {
                $autotitle = $autotitle . " Total Counts ";
        } elsif ($settings->{grouping} eq 'value1') {
		if (defined($settings->{value1_title})) {
                	$autotitle = $autotitle . " Counts by $settings->{value1_title}";
		} else {
			$autotitle = $autotitle . " Counts by Value1";
		}
        } elsif ($settings->{grouping} eq 'value2') {
		if (defined($settings->{value2_title})) {
                	$autotitle = $autotitle . " Counts by $settings->{value2_title}";
		} else {
			$autotitle = $autotitle . " Counts by Value2";
		}
        } elsif ($settings->{grouping} eq 'sender') {
                $autotitle = $autotitle . " Counts by Sender";
        } elsif ($settings->{grouping} eq 'recipient') {
                $autotitle = $autotitle . " Counts by Recipient";
        } elsif ($settings->{grouping} eq 'subject') {
                $autotitle = $autotitle . " Counts by Subject";
        } else {
                die ("Invalid settings{grouping} value");
        }

	# Put top_n in the filename?

	if ($settings->{top_n}) {
        	$autofilename .= "_$settings->{top_n}";
	} else {
		$autofilename .= "_";
	}

	$autofilename .= "$settings->{grouping}_$settings->{graph_type}";

        # The final portion of the title will be set in the section below

        if ($settings->{grouping_time} eq 'hourly') {

                $settings->{x_axis_num_values}  = $NUM_HOURS_SUMMARY;   # Number of x-axis values on graph
		$settings->{x_axis_num_values}  = $settings->{num_hourly_values} if defined($settings->{num_hourly_values});
                $settings->{x_axis_num_sec_incr}= 60*60;                # Incremental number of seconds represented by each x-axis value
                $settings->{x_axis_date_format} = "%h %d, %I%p";        # Format of date string on x-axis
                $settings->{x_label}            = 'Hours';
                $settings->{y_label}            = 'Counts per Hour';
                $settings->{chart_title}        = $autotitle . " per Hour (last $settings->{x_axis_num_values} hours)"
                                                unless defined($settings->{title});
                $autofilename			= "hourly_" . $autofilename;

        } elsif ($settings->{grouping_time} eq 'daily') {

                $settings->{x_axis_num_values}  = $NUM_DAYS_SUMMARY;
		$settings->{x_axis_num_values}  = $settings->{num_daily_values} if defined($settings->{num_daily_values});
                $settings->{x_axis_num_sec_incr}= 60*60*24;
                $settings->{x_axis_date_format} = "%h %d";
                $settings->{x_label}            = 'Days';
                $settings->{y_label}            = 'Counts per Day';
                $settings->{chart_title}              = $autotitle . " per Day (Last $settings->{x_axis_num_values} days)"
                                                unless defined($settings->{title});
                $autofilename      = "daily_" . $autofilename;

        } elsif ($settings->{grouping_time} eq 'monthly') {

                $settings->{x_axis_num_values}  = $NUM_MONTH_SUMMARY;
		$settings->{x_axis_num_values}  = $settings->{num_monthly_values} if defined($settings->{num_monthly_values});
                $settings->{x_axis_num_sec_incr}= 60*60*24*31;
                $settings->{x_axis_date_format} = "%h";
                $settings->{x_label}            = 'Months';
                $settings->{y_label}            = 'Counts per Month';
                $settings->{chart_title}              = $autotitle . " per Month (Last $settings->{x_axis_num_values} months)"
                                                unless defined($settings->{title});
                $autofilename           = "monthly_" . $autofilename;
        }

	if (defined $settings->{filter_name}) {
		my $filter;
		($filter = $settings->{filter_name}) =~ s/\W/_/g;
		$settings->{chart_title} .= " filtered by $settings->{filter_name}";
		$autofilename .= "_$filter";
	}

	# Use the title from graphdefang-config if specified, else use the autotitle
	$settings->{chart_title} = $settings->{title} if (defined($settings->{title}));

	# Use the filename from graphdefang-config if specified, else use the autofilename
	$settings->{chart_filename} = $autofilename;
	$settings->{chart_filename} = "$settings->{grouping_time}_$settings->{filename}" if (defined($settings->{filename}));
	$settings->{chart_filename} =~ s/\//_/g; # Replace any '/' chars with '_'
}


sub get_graph_data($$) {

	my $settings = shift;
	my $data = shift;

        # Calculate the date cutoff for our graph

        my $currenttime = time();
	my $cutofftime;
	my $currentyear;
	my $currentmon;
	my $currentisdst;

	if ($settings->{grouping_time} eq 'monthly') {
		my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($currenttime);
		$currentyear = $year;
		$currentmon = $mon;
		$currentisdst = $isdst;
                # Decrement the month/year value n times
		for (my $i = 0; $i < $settings->{x_axis_num_values}-1; $i++) {
                       	if ($mon == 0) {
                       		$year--;
                               	$mon = 11;
                       	} else {
                               	$mon--;
			}
                }

                # get unixtime for our new values
		$mday = 1; # Get around a bug that only shows itself on the 30th or 31st of the month
                $cutofftime = timelocal($sec, $min, $hour, $mday, $mon, $year);

	} else {
        	$cutofftime = $currenttime - ($settings->{x_axis_num_sec_incr}*($settings->{x_axis_num_values}-1));
	}

	# Create Data Array for Graph

	my @GraphData = ();
	my @TopNNames = ();
	my %Total = ();
	my @Legend = ();

	# Handle data_types = 'all'
	my $allset;
	if ($settings->{'data_types'}[0] eq 'all') {
		$allset = 1;
		my %all;
		foreach my $date (keys %{$data->{$settings->{grouping_time}}}) {
			foreach my $data_type (keys %{$data->{$settings->{grouping_time}}{$date}}) {
				$all{$data_type} = 1;
			}
		}
		$settings->{'data_types'} = ();
		foreach my $key (sort keys %all) {
			push @{$settings->{'data_types'}}, $key;
		}
	}
	# Summarize totals across time interval
	for (my $time=$cutofftime; $time<=$currenttime; $time += $settings->{x_axis_num_sec_incr}) {
		my $date = get_unixtime_by_timesummary($settings->{grouping_time},$time);

		# Get total for summary grouping
		if ($settings->{'grouping'} eq 'summary') {

			foreach my $datatype (@{$settings->{'data_types'}}) {
				if (defined($data->{$settings->{grouping_time}}{$date}{$datatype}{'summary'})) {
					$Total{$datatype} += $data->
							{$settings->{grouping_time}}
							{$date}
							{$datatype}
							{'summary'};
				} else {
					$Total{$datatype} += 0;
				}
			}

		} else {
			# Get total for other groupings

			foreach my $datatype (@{$settings->{'data_types'}}) {
				foreach my $value (keys %{$data->
								{$settings->{grouping_time}}
								{$date}
								{$datatype}
								{$settings->{'grouping'}}} ) {
					$Total{'value'}{$value} += $data->
									{$settings->{grouping_time}}
									{$date}
									{$datatype}
									{$settings->{'grouping'}}
									{$value};	
					$Total{$date}{$value} += $data->
									{$settings->{grouping_time}}
									{$date}
									{$datatype}
									{$settings->{'grouping'}}
									{$value};
				}
			}	
		}
		# Recalculate the x_axis_num_sec_incr value if we are graphing monthly.
		# Determine the current month, increment it by one, and then get a time delta..
		if ($settings->{grouping_time} eq 'monthly') {
			my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($date);
			# Increment the month/year value
			if ($mon == 11) {
				$year++;
				$mon = 0;
			} else {
				$mon++;
			}

			# Has dst kicked in this month?  If so, adjust for it
			my $dstadjustment = 0;
			if (($currentyear == $year) && ($currentmon == $mon)) {
				if ($currentisdst > $isdst) {
					$dstadjustment = -3600;
				} elsif ($currentisdst < $isdst) {
					$dstadjustment = 3600;
				} else {
					$dstadjustment = 0;
				}
			}
			
			# get unixtime for our new values
			my $newmonthtime = timelocal($sec, $min, $hour, $mday, $mon, $year);

			$settings->{x_axis_num_sec_incr} = $newmonthtime - $date + $dstadjustment;
                }
	}

	# Sort the TopNNames list so we have it largest to smallest and keep only the top N.
	if ($settings->{'grouping'} eq 'summary') {

		foreach my $datatype (@{$settings->{'data_types'}}) {
			push @Legend, "\u$datatype, Total = $Total{$datatype}";
		}
	} else {
		my $i=0;
		foreach my $TopNName (sort { $Total{'value'}{$b} <=> $Total{'value'}{$a} } keys %{$Total{'value'}} ) {
			if (!defined($settings->{'filter'}) or $TopNName =~ m/$settings->{'filter'}/i) {
				push @TopNNames, $TopNName;
				push @Legend, "$TopNName, Total=$Total{'value'}{$TopNName}";
				$i++;
			}
			last if (defined($settings->{'top_n'}) and $settings->{'top_n'} > 0  and $i >= $settings->{'top_n'} );
		}
	}
	
	# If we have no legend, create one so graph doesn't error
	push @Legend,"No values of this type!" if (!@Legend);

	@{$settings->{legend}} = @Legend;

	for (my $time=$cutofftime; $time<=$currenttime; $time += $settings->{x_axis_num_sec_incr}) {

		my $date = get_unixtime_by_timesummary($settings->{grouping_time},$time);

		my $datestring = '';
		if (defined($TZ{GD_Display})) {
			my $zone = tz2zone($TZ{GD_Display});
			$datestring = time2str($settings->{x_axis_date_format},$date,$zone);
		} else {
			$datestring = time2str($settings->{x_axis_date_format},$date);
		}

		my $i=0;
		push @{$GraphData[$i]}, $datestring;
		
		if ( $settings->{'grouping'} eq 'summary' ) {
			foreach my $datatype (@{$settings->{'data_types'}}) {

			# Data format:
			#$data{$timesummary}{$summarytime}{$event}{'summary'}++;
			#$data{$timesummary}{$summarytime}{$event}{'value1'}{$value1}++

				$i++;
				# Set any undefined values to 0 so GD::Graph
				# has something to graph
				if ( defined($data->
						{$settings->{grouping_time}}
						{$date}
						{$datatype}
						{'summary'}) ) {
					push @{$GraphData[$i]}, $data->
								{$settings->{grouping_time}}
								{$date}
								{$datatype}
								{'summary'};
				} else {
					push @{$GraphData[$i]}, 0;
				}
			}
		} else {
			# iterate over top_n values if they exist, else push 0
			if ($#TopNNames > -1) {
				foreach my $TopNName (@TopNNames) {
					$i++;
					# Set any undefined values to 0 so GD::Graph
					# has something to graph
					if ( defined ($Total{$date}{$TopNName}) ) {
						push @{$GraphData[$i]}, $Total{$date}{$TopNName};
					} else {
						push @{$GraphData[$i]}, 0;
					}	
				}
			} else {
				$i++;
				push @{$GraphData[$i]}, 0;
			}
		}
		# Recalculate the x_axis_num_sec_incr value if we are graphing monthly.
		# Determine the current month, increment it by one, and then get a time delta..
		if ($settings->{grouping_time} eq 'monthly') {
			my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($date);
			# Increment the month/year value
			if ($mon == 11) {
				$year++;
				$mon = 0;
			} else {
				$mon++;
			}

			# Has dst kicked in this month?  If so, adjust for it
			my $dstadjustment = 0;
			if (($currentyear == $year) && ($currentmon == $mon)) {
				if ($currentisdst > $isdst) {
					$dstadjustment = -3600;
				} elsif ($currentisdst < $isdst) {
					$dstadjustment = 3600;
				} else {
					$dstadjustment = 0;
				}
			}

			# get unixtime for our new values
			my $newmonthtime = timelocal($sec, $min, $hour, $mday, $mon, $year);

			$settings->{x_axis_num_sec_incr} = $newmonthtime - $date + $dstadjustment;
                }
	}	

	@{$settings->{'data_types'}} = ('all') if ($allset);

	return @GraphData;
}

sub draw_line_graph($$) {
        my $settings = shift;
        my $data = shift;
        my $my_graph = new GD::Graph::linespoints($settings->{x_graph_size}, $settings->{y_graph_size});

        $my_graph->set(
                x_label                 => $settings->{x_label},
                y_label                 => $settings->{y_label},
                title                   => $settings->{chart_title},
                x_labels_vertical       => 1,
                x_label_position        => 1/2,

                bgclr                   => 'white',
                fgclr                   => 'gray',
                boxclr                  => 'lgray',

                y_tick_number           => 10,
                y_label_skip            => 2,
                long_ticks              => 1,
                marker_size             => 1,
                skip_undef              => 1,
                line_width              => 1,
                transparent             => 0,
        );

	$my_graph->set( dclrs => [ qw(lred lgreen lblue lyellow lpurple cyan lorange dred dgreen dblue dyellow dpurple) ] );


        $my_graph->set_legend( @{$settings->{legend}} );
        $my_graph->plot($data);
        save_chart($my_graph, "$OUTPUT_DIR/$settings->{chart_filename}");
}

sub draw_stacked_bar_graph($$) {
        my $settings = shift;
        my $data = shift;

        my $my_graph = new GD::Graph::bars($settings->{x_graph_size}, $settings->{y_graph_size});

        $my_graph->set(
                x_label                 => $settings->{x_label},
                y_label                 => $settings->{y_label},
                title                   => $settings->{chart_title},
                x_labels_vertical       => 1,
                x_label_position        => 1/2,

                bgclr                   => 'white',
                fgclr                   => 'gray',
                boxclr                  => 'lgray',

                y_tick_number           => 10,
                y_label_skip            => 2,
                long_ticks              => 1,
                cumulate                => 1,
                transparent             => 0,
                correct_width           => 0,
        );
	
	$my_graph->set( dclrs => [ qw(lred lgreen lblue lyellow lpurple cyan lorange dred dgreen dblue dyellow dpurple) ] );

        $my_graph->set_legend( @{$settings->{legend}} );
        $my_graph->plot($data);
        save_chart($my_graph, "$OUTPUT_DIR/$settings->{chart_filename}");
}

sub save_chart($$) {
        my $chart = shift or die "Need a chart!";
        my $name = shift or die "Need a name!";
        local(*OUT);

        my $ext = $chart->export_format;

        open(OUT, ">$name.png") or
                die "Cannot open $name.$ext for write: $!";
        binmode OUT;
        print OUT $chart->gd->png;
        close OUT;
}
1;
