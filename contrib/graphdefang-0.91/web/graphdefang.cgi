#!/usr/bin/perl
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
use warnings;

use CGI qw(:standard);
use CGI::Carp qw(fatalsToBrowser);
use Fcntl;
use Data::Dumper;

use vars qw($MYDIR $OUTPUT_DIR $SUMMARYDB $QUIET $NODB $NOFILE $DATAFILE @GRAPHS %TZ);

# CONFIGURE HERE
my $GRAPHDEFANGDIR = '/home/jpk/graphdefang';
$SUMMARYDB = "$GRAPHDEFANGDIR/SummaryDB.db";
# THE REST SHOULD BE OKAY

# Require the graphdefang library file
require ("$GRAPHDEFANGDIR/graphdefanglib.pl");

# Don't output messages for the web app
$QUIET = 1;

# Open the SummaryDB file
my %data = ();;
read_summarydb(\%data, O_RDONLY);

# Get the cmd from the parameter list:
my $cmd = '';
if (param('cmd')) {
	$cmd = param('cmd');
} else {
	$cmd = 'null';
}

# Check for errors
my $error = '';
my $submit = param('submit');
if ($submit && !param('data_types')) {
	$error = "<font color=red>No Data Types Selected.  Please Try Again!</font>\n";
}

# Create image
if ($cmd eq 'get-image') {

	my $grouping_time = param('grouping_time');
	my $grouping = param('grouping');
	my $graph_type = param('graph_type');
	my @data_types = param('data_types');
	my $top_n = param('top_n');
	my %settings = ();

	push @{$settings{grouping_times}}, $grouping_time;
	$settings{grouping} = $grouping;
	$settings{graph_type} = $graph_type;
	$settings{data_types} = ();
	push @{$settings{data_types}}, @data_types;
	$settings{top_n} = $top_n;

	$settings{num_hourly_values} = 48;
	$settings{num_hourly_values} = param('num_hourly_values') if param('num_hourly_values');
	$settings{num_daily_values} = 60;
	$settings{num_daily_values} = param('num_daily_values') if param('num_daily_values');
	$settings{num_monthly_values} = 24;
	$settings{num_monthly_values} = param('num_monthly_values') if param('num_monthly_values');

	$settings{x_graph_size} = 700;
	$settings{x_graph_size} = param('x_graph_size') if param('x_graph_size');
	$settings{y_graph_size} = 300;
	$settings{y_graph_size} = param('y_graph_size') if param('y_graph_size');

	$OUTPUT_DIR="/tmp";
	graph(\%settings, \%data);

	my $filename = $settings{chart_filename};

	open IMG, "< $OUTPUT_DIR/$filename.png" or die $!;
	binmode IMG;

	print header(-type=>'image/png', -expires=>'now');
	print while <IMG>;
	close IMG;

	unlink ("$OUTPUT_DIR/$filename.png");

} elsif ($cmd eq 'null') {

	my @all_data_types = get_all_data_types(\%data);
	
	print header(-type=>'text/html',
		     -expires=>'now');
	print start_html(-title=>'GraphDefang CGI Interface');
	print h2('Select graph attributes and click the Submit button');
	print startform();
	print "<table border=1 cellspacing=0 cellpadding=5>\n";
	print "  <tr>\n";
	print "    <th>Data Types</th>\n";
	print "    <th>Grouping Time</th>\n";
	print "    <th>Grouping</th>\n";
	print "    <th>Graph Type</th>\n";
	print "  </tr>\n";
	print "  <tr valign=top>\n";
	print "    <td>\n";
	print        checkbox_group(-name=>'data_types',
					-values=>\@all_data_types,
					-linebreak=>'true');
	print "    </td>\n";
	print "    <td>\n";
  	print "      <table>\n";
	print "        <tr>\n";
	print "          <td>\n";
	print              radio_group(-name=>'grouping_time',
					-values=>['hourly'],
					-default=>'hourly');
	print "          </td>\n";
	print "          <td>\n";
	print              textfield(-name=>'num_hourly_values',
					-default=>48,
					-size=>2,
					-maxlength=>3);
	print "          </td>\n";
	print "        </tr>\n";
	print "        <tr>\n";
	print "          <td>\n";
	print              radio_group(-name=>'grouping_time',
					-values=>['daily'],
					-default=>'hourly');
	print "          </td>\n";
	print "          <td>\n";
	print              textfield(-name=>'num_daily_values',
					-default=>60,
					-size=>2,
					-maxlength=>3);
	print "          </td>\n";
	print "        </tr>\n";
	print "        <tr>\n";
	print "          <td>\n";
	print              radio_group(-name=>'grouping_time',
					-values=>['monthly'],
					-default=>'hourly');
	print "          </td>\n";
	print "          <td>\n";
	print              textfield(-name=>'num_monthly_values',
					-default=>24,
					-size=>2,
					-maxlength=>3);
	print "          </td>\n";
	print "        </tr>\n";
	print "      </table>\n";
	print "    </td>\n";
	print "    <td>\n";
	print        radio_group(-name=>'grouping',
				-values=>['summary','sender','recipient','subject','value1','value2'],
				-linebreak=>'true',
				-default=>'summary');
	print        "<br>Top N:&nbsp;";
	print        textfield(-name=>'top_n',
				-default=>10,
				-size=>2,
				-maxlength=>2);
	print "    </td>\n";
	print "    <td>\n";
	print        radio_group(-name=>'graph_type',
				-values=>['line','stacked_bar'],
				-linebreak=>'true',
				-default=>'line');
	print "    </td>\n";
	print "  </tr>\n";
	print "</table>\n";
	print "<br>\n";
	print "X Graph Size: ";  
	print textfield(-name=>'x_graph_size', -default=>700, -size=>3, -maxlength=>4);
	print "&nbsp;&nbsp;\n";
	print "Y Graph Size: ";
	print textfield(-name=>'y_graph_size', -default=>300, -size=>3, -maxlength=>4);
	print "<p>\n";
	print submit(-value=>'Submit');
	print hidden(-name=>'submit', 'default'=>['1']);
	print endform();
	print "<img src=./graphdefang.cgi?cmd=get-image;" . query_string() . ">\n" if (param('submit') && !$error);
	if ($error) {
		print "$error";
	}
	print end_html();
}
