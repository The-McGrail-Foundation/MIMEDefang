package Mail::MIMEDefang::Unit::Net;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;
use Sys::Hostname;

use Mail::MIMEDefang::Net;

sub t_expand_ipv6_address : Test(1)
{
  my $ipv6 = expand_ipv6_address('2a00:1450:4009:816::200e');
  is($ipv6, '2a00:1450:4009:0816:0000:0000:0000:200e');
}

sub t_get_host_name : Test(2)
{
  my $hostname = hostname;
  my $host = ::main::get_host_name($hostname);
  like($host, qr/$hostname\.*/);
  $host = ::main::get_host_name(undef);
  like($host, qr/$hostname\.*/);
}

sub t_ipv4_public_ip : Test(2)
{
  my $ip_priv = '172.16.0.1';
  my $ip_pub = '212.212.212.212';
  is(is_public_ip4_address($ip_priv), 0);
  is(is_public_ip4_address($ip_pub), 1);
}

__PACKAGE__->runtests();
