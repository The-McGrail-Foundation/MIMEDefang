#***********************************************************************
#
# gen-ip-validator.pl
#
# Generate a random number used to confirm IP address header.
#
# Copyright (C) 2000-2005 Roaring Penguin Software Inc.
#
#***********************************************************************

use Digest::SHA1;

$ctx = Digest::SHA1->new;

$data = "";
for ($i=0; $i<256; $i++) {
    $data .= pack("C", rand(256));
}
$data .= `ls -l; ps; date; uptime; uname -a`;

if (-r "/dev/urandom") {
    open(IN, "</dev/urandom");
    read(IN, $junk, 64);
    $data .= $junk;
    close(IN);
}

$ctx->add($data);
$d = $ctx->hexdigest;
print "X-MIMEDefang-Relay-$d\n";
