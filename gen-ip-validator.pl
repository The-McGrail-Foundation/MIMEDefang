#!/usr/bin/perl

#***********************************************************************
#
# gen-ip-validator.pl
#
# Generate a random number used to confirm IP address header.
#
# * This program may be distributed under the terms of the GNU General
# * Public License, Version 2.
#
#***********************************************************************

use constant HAS_OPENSSL_RANDOM => eval { require Crypt::OpenSSL::Random; };

BEGIN
{
  eval{
    Crypt::OpenSSL::Random->import
  };
}

use Digest::SHA;

sub read_urandom($) {
  my $len = shift;
  my $junk;

  if (-r "/dev/urandom") {
    open(IN, "<", "/dev/urandom");
    read(IN, $junk, $len);
    close(IN);
  }

  return $junk;
}

my $rng;
my $data;

if(HAS_OPENSSL_RANDOM) {
  for (;;) {
    $rng .= sprintf "%x\n", rand(0xffffffff);
    $rng .= read_urandom(64);
    last if(Crypt::OpenSSL::Random::random_status());
  }
  Crypt::OpenSSL::Random::random_seed($rng);
  $data = Crypt::OpenSSL::Random::random_bytes(256);
} else {
  $data = read_urandom(256);
}

my $ctx = Digest::SHA->new;
$ctx->add($data);
my $rnd = $ctx->hexdigest;
print "X-MIMEDefang-Relay-$rnd\n";
