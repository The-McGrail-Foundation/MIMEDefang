package Mail::MIMEDefang::Unit::Net;

use strict;
use warnings;
use lib qw(lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang::Net;

sub expand_ipv6_address : Test(1)
{
  my $ipv6 = ::main::expand_ipv6_address('2a00:1450:4009:816::200e');
  is($ipv6, '2a00:1450:4009:0816:0000:0000:0000:200e');
}

__PACKAGE__->runtests();
