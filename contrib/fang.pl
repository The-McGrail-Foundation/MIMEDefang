#!/usr/bin/perl
######################################################################
#	PROGRAM:	fang -d <dir> -s <start> -e <end>
#	PURPOSE:	To put messages back together after defang
#			is done with them.
#	AUTHOR:		N. McKellar (mckellar@telusplanet.net)
#	DATE:		9 Jan 2002
#	MODIFICATIONS:
#
#	17 March 2002, N. McKellar
#	- Moved MIME::Lite connection down past the USAGE output so
#	  you can run 'fang -h' without specifying the mail server
#	  first.
#	- Added exit() to USAGE so program doesn't just run anyway.
#	- Added a check to ensure that the directory passed in is
#	  really a directory.
#	- Modified all the open() calls to explicitly open files as
#	  read (should keep open() from executing programs).
#
#	Copyright (C) 2002 Neil McKellar (mckellar@telusplanet.net)
#
# * This program may be distributed under the terms of the GNU General
# * Public License, Version 2, or (at your option) any later version.
#
#  Notes:
#  Modify the name of the mail server to use when sending the
#  reconstructed mail messages.  Ideally this will be your own mail
#  server.  Look for 'your.mail.server.here' in the code below.
#
#  It may be worth noting that a properly misnamed file or directory
#  might still be used to spoof reading or processing of files and
#  directories you don't intend.
#
#  Using -T won't help much as the command line arguments are passed
#  through Getopt::Std first before arriving here and Taint won't
#  see whether they've been cleaned or not.
#
#  DON'T make this script setuid.
#  BE CAUTIOUS if your defang directory needs root permissions to fix
#  messages with this script.  A better idea would be to make a quick
#  and temporary working directory to use this script in that doesn't
#  need root.
#
######################################################################

use strict;
use warnings;

use Net::SMTP;
use MIME::Lite;
use Getopt::Std;
use Date::Parse;

########################################
#  Setup
########################################

my $DEBUG       = 0;		## DEBUG MODE

my %opts;
my %folders;

my $start_time  = -1;		## less than epoch
my $end_time    = time + 3600;	## current time + 1 hour

my $mail_server = 'your.mail.server.here';

########################################
#  Get arguments
########################################

getopt('dse?h', \%opts);

if (exists $opts{'?'} || exists $opts{'h'}) {
  print <<USAGE;
USAGE: fang [-d <dir>] [-s <start>] [-e <end>]
       <start> and <end> must be parsable by
       Date::Parse.  A good format would be:
           YYYY:MM:DD:HH:TT:SS
       eg. 2002:01:09:21:32:00

       OR

           DD Mon YYYY HH:MM
       eg.  9 Jan 2002 19:30

USAGE
  exit 0;
}

$opts{'d'}  = '.'              unless ($opts{'d'} ne '' && $opts{'d'} != 1);
$start_time = str2time($opts{'s'}) if ($opts{'s'} ne '' && $opts{'s'} != 1);
$end_time   = str2time($opts{'e'}) if ($opts{'e'} ne '' && $opts{'e'} != 1);

## Make sure we didn't get something bogus here
Error("$opts{'d'} is not a valid directory!") unless (-d $opts{'d'});

if ($DEBUG) {
  print <<DEBUG;
[DEBUG] Start: [$start_time]
[DEBUG] End:   [$end_time]
DEBUG
}


########################################
#  Compile a list of directories
########################################

opendir(TOP,$opts{'d'}) || Error("Can't open $opts{'d'}: $!");
my @dirs = readdir(TOP);
closedir(TOP);

while (@dirs) {
  my $item = shift(@dirs);
  my $curr = "$opts{'d'}/$item";

  next if ($item =~ /^\.+/);		## Skip ., .., .<hidden>
  next unless (-d $curr);		## Only directories

  my @dir_stat    = stat($curr);

  if ($dir_stat[9] >= $start_time && $dir_stat[9] <= $end_time) {
    $folders{$item} = $dir_stat[9];	## track mtime
    print "[DEBUG] $item matches\n" if ($DEBUG);
  }
}

########################################
#  Connect to Mail Server
########################################

MIME::Lite->send('smtp', $mail_server);

foreach my $msg (sort keys %folders) {
  make_message($msg);
}

exit 0;

######################################################################
#	SUBROUTINES
######################################################################

########################################
sub Error {
########################################
#	Print error messages
########################################

  my $msg = shift(@_);
  print "ERROR: $msg\n\n";
  exit -1;
}

########################################
sub make_message {
########################################
#	Read files in directory and
#	make a MIME::Lite message
########################################

  my $dir = shift(@_);

  my %body;
  my %file;
  my %type;

  ######################################
  #  Get list of recipients
  ######################################

  my @to;
  open(TO,"<$opts{'d'}/$dir/RECIPIENTS")
    || Error("Can't read $dir/RECIPIENTS: $!");
  while (<TO>) { chomp; push @to,$_; }
  close(TO);

  ######################################
  #  Get sender
  ######################################

  my $from;
  open(FROM,"<$opts{'d'}/$dir/SENDER")
    || Error("Can't read $dir/SENDER: $!");
  $from = <FROM>;
  close(FROM);

  ######################################
  #  Get Subject line and Date
  ######################################

  my $subject;
  my $date;
  open(HEADER,"<$opts{'d'}/$dir/HEADERS")
    || Error("Can't read $dir/HEADERS: $!");
  while (<HEADER>) {
    chomp;
    SWITCH: {
	/Date:/ && do {
	  s/Date: //;
	  $date = $_;
	};

	/Subject:/ && do {
	  s/Subject: //;
	  $subject = $_;
	};
    }
  }
  close(HEADER);

  ######################################
  #  List PART.*
  #  Get 'BODY' and 'HEADERS' for each
  #  part.
  ######################################

  opendir(FOLDER,"$opts{'d'}/$dir")
    || Error("Can't list $dir: $!");
  my @files = readdir(FOLDER);
  close(FOLDER);

  foreach (@files) {
    next unless (/^PART/);

    ## Parse 'part' name
    my ($part,$idx,$piece) = split(/\./);

    ## Store body content and headers separately
    SWITCH: foreach ($piece) {
	/BODY/ && do {
	  $body{$idx} = 'body';
	};

	/HEADERS/ && do {
	  ## Read HEADERS for 'part'
	  my $header = "$opts{'d'}/$dir/" . $part . "." . $idx . "." . $piece;
	  open(DATA,"<$header")
	    || Error("Can't read $header: $!");
	  while (<DATA>) {
	    if (/Content-Type/ && /name=/) {
	      s/Content-Type: (.*?);/$1/;
	      $type{$idx} = $_;
	      s/.*name="(.*)"/$1/;
	      $file{$idx} = $_;
	    } elsif (/Content-Disposition/ && /filename=/) {
	      s/.*name="(.*)"/$1/;
	      $file{$idx} = $_;
	    }
	    if ($DEBUG) {
	      print <<DEBUG;
[DEBUG] HEADER:       $header
[DEBUG] Content-Type: $type{$idx}
[DEBUG] filename:     $file{$idx}
DEBUG
	    }
	  }
	  close(DATA);
	};
    }
  }

  ######################################
  #  Generate message 'data'
  #  DEBUG:  For debugging purposes
  #          Replace To: line with your
  #          own e-mail address.
  #          Remember to set it back
  #          to:
  #              join(',',@to),
  #          when finished.
  ######################################

  my $msg = MIME::Lite->new(
		  From    => $from,
		  To      => join(',',@to),
		  Subject => $subject,
		  Type    => 'multipart/mixed',
  );

  foreach my $idx (sort {$a <=> $b} keys %body) {
    $msg->attach(
		  Type     => $type{$idx},
		  Path     => "$opts{'d'}/$dir/PART.$idx.BODY",
		  Filename => $file{$idx},
    );
  }

  ######################################
  #  Send finished message
  ######################################

  $msg->send() unless ($DEBUG);
}
