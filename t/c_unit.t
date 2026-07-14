#!/usr/bin/env perl
use strict;
use warnings;

my $cc     = $ENV{MD_CC} || $ENV{CC} || 'cc';
my $cflags = '-I. -std=c89 -D_BSD_SOURCE -D_DEFAULT_SOURCE';
my $libs   = 'utils.c dynbuf.c';

my @sources = sort glob 't/test_*.c';

unless (@sources) {
    print "1..0 # Skip no C test files found\n";
    exit 0;
}

unless (-f 'config.h') {
    print "1..0 # Skip config.h missing; run perl Makefile.PL or ./configure first\n";
    exit 0;
}

my (@lines, @bins, $total);

for my $src (@sources) {
    (my $bin = $src) =~ s/\.c$//;

    if (system("$cc $cflags -o $bin $src $libs 2>/dev/null") != 0) {
        $total++;
        push @lines, "not ok $total - compile failed: $src\n";
        next;
    }
    push @bins, $bin;

    open(my $fh, '-|', $bin) or die "Cannot run $bin: $!";
    while (<$fh>) {
        if (/^1\.\.\d+/) {
            # discard per-binary plan; emit a unified one at the end
        } elsif (/^(not ok|ok)\s+\d+(.*)/) {
            $total++;
            push @lines, "$1 $total$2\n";
        } else {
            push @lines, $_;    # pass diagnostics through unchanged
        }
    }
    close $fh;
}

print "1..$total\n";
print for @lines;

unlink @bins;
