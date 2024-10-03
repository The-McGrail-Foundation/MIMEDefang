package Mail::MIMEDefang::Unit::Net;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;
use Sys::Hostname;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Net;

init_globals;
$Features{"Net::DNS"} = 1;

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

sub t_ipv6_public_ip : Test(2)
{
  my $ip_priv = 'fe80::354f:365c:422e:6ae';
  my $ip_pub = '2001:460:1e1f:ddc::1';
  is(is_public_ip6_address($ip_priv), 0);
  is(is_public_ip6_address($ip_pub), 1);
}

sub t_reverse_ip : Test(2)
{
  my $ipv4 = '192.168.0.2';
  my $ipv6 = 'fe80::1121:34db:fb39:a64e';
  is(reverse_ip_address_for_rbl($ipv4), '2.0.168.192');
  is(reverse_ip_address_for_rbl($ipv6), 'e.4.6.a.9.3.b.f.b.d.4.3.1.2.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f');
}

sub t_get_ptr_record : Test(1)
{
  my $ipv4 = '1.1.1.1';
  is(Mail::MIMEDefang::Net::get_ptr_record($ipv4), 'one.one.one.one');
}

sub t_relay_is_blacklisted_multi : Test(1)
{
  my @rbl;
  $rbl[0] = "dnsbltest.spamassassin.org";
  my $relayip = "144.137.3.98";

  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    detect_and_load_perl_modules();
    my $res = relay_is_blacklisted_multi($relayip, 10, 1, \@rbl);
    is($res->{"dnsbltest.spamassassin.org"}[0], "127.0.0.2");
  }
}

sub t_relay_is_blacklisted : Test(1)
{
  my $rbl = "dnsbltest.spamassassin.org";
  my $relayip = "144.137.3.98";

  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    detect_and_load_perl_modules();
    my $ret = relay_is_blacklisted($relayip, $rbl);
    is($ret, "127.0.0.2");
  }
}

sub t_email_is_blacklisted : Test(1)
{
  my $rbl = "hashbltest2.spamassassin.org";
  my $email = 'hustl.er@gmail.com';

  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    detect_and_load_perl_modules();
    my $ret = email_is_blacklisted($email, $rbl, 'md5');
    is($ret, "127.0.0.2");
  }
}

__PACKAGE__->runtests();
