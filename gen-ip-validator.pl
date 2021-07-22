#!/usr/bin/perl

#***********************************************************************
#
# gen-ip-validator.pl
#
# Generate a random number used to confirm IP address header.
#
# * This program may be distributed under the terms of the GNU General
# * Public License, Version 2, or (at your option) any later version.
#
#***********************************************************************

use Crypt::OpenSSL::Random;
use Digest::SHA1;

my $rng;

for (;;) {
  $rng .= sprintf "%x\n", rand(0xffffffff);
  if (-r "/dev/urandom") {
    open(IN, "</dev/urandom");
    read(IN, $junk, 64);
    $rng .= $junk;
    close(IN);
  }
  last if(Crypt::OpenSSL::Random::random_status());
}
Crypt::OpenSSL::Random::random_seed($rng);

my $ctx = Digest::SHA1->new;
my $data = Crypt::OpenSSL::Random::random_bytes(256);

$ctx->add($data);
my $rnd = $ctx->hexdigest;
print "X-MIMEDefang-Relay-$rnd\n";
