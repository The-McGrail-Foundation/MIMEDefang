#!/usr/bin/perl -w

use strict;
use MLDBM qw(DB_File Storable);
use Fcntl;
use Time::Local;

my $SUMMARYDB = "./SummaryDB.db";

my %data_db = ();
my %data = ();

tie (%data_db, 'MLDBM', $SUMMARYDB, O_RDWR|O_CREAT, 0644)
	or die "Can't open $SUMMARYDB:$!\n";

%data = %data_db;
untie (%data_db);

#reset the max time to 12/31/02 23:59:59 in the local timezone

my $year = 2002;
my $mon = 11; # 0 - 11
my $mday = 31; # 1 - 31
my $hour = 23;
my $min = 59;
my $sec = 59;

my $unixtime = timelocal($sec, $min, $hour, $mday, $mon, $year);

print "Current max time: $data{'max'}\n";

$data{'max'} = $unixtime;

print "Reset max time to $unixtime\n";

# Delete future data from SummaryDB

my $deletetime = $unixtime;
my $trimcounter = 0;

foreach my $entrytime (keys %{$data{'hourly'}}) {
	if ($entrytime > $deletetime) {
		delete($data{'hourly'}{$entrytime});
		$trimcounter++;
	}
}

print "Trimmed $trimcounter 'hourly' future entries from SummaryDB\n";

$trimcounter=0;

foreach my $entrytime (keys %{$data{'daily'}}) {
	if ($entrytime > $deletetime) {
		delete $data{'daily'}{$entrytime};
		$trimcounter++;
	}
}

print "Trimmed $trimcounter 'daily' future entries from SummaryDB\n";

$trimcounter=0;

foreach my $entrytime (keys %{$data{'monthly'}}) {
        if ($entrytime > $deletetime) {
                delete $data{'monthly'}{$entrytime};
                $trimcounter++;
        }
}

print "Trimmed $trimcounter 'monthly' future entries from SummaryDB\n";

tie (%data_db, 'MLDBM', $SUMMARYDB, O_RDWR|O_CREAT, 0644)
        or die "Can't open $SUMMARYDB:$!\n";
%data_db = %data;
untie (%data_db);
