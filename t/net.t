package Mail::MIMEDefang::Unit::Net;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;
use Sys::Hostname;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Net;
use Mail::MIMEDefang::Net qw(md_shared_resolver md_dns_query md_dns_cache_clear);
use Net::DNS;

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

sub t_ipv6_public_ip : Test(19)
{
  my @not_public = (
    'fe80::354f:365c:422e:6ae',  # link-local
    'febf::1',                   # link-local, end of fe80::/10
    'fec0::1',                   # site-local
    '::1',                       # loopback
    '0:0:0:0:0:0:0:1',           # loopback, uncompressed
    '::',                        # unspecified
    'fc00::1',                   # unique-local
    'FD12:3456::1',              # unique-local, upper case
    'ff02::1',                   # multicast
    '100::1',                    # discard-only
    '2001:db8::1',               # documentation
    '::ffff:10.0.0.1',           # IPv4-mapped private
    '::ffff:127.0.0.1',          # IPv4-mapped loopback
    'not-an-address',
    '1.2.3.4',
  );
  my @public = (
    '2001:460:1e1f:ddc::1',
    '2a00:1450:4009:816::200e',
    'fe00::1',                   # outside fe80::/10
    '::ffff:212.212.212.212',    # IPv4-mapped public
  );
  is(is_public_ip6_address($_), 0, "$_ is not public") for @not_public;
  is(is_public_ip6_address($_), 1, "$_ is public") for @public;
}

sub t_reverse_ip : Test(2)
{
  my $ipv4 = '192.168.0.2';
  my $ipv6 = 'fe80::1121:34db:fb39:a64e';
  is(reverse_ip_address_for_rbl($ipv4), '2.0.168.192');
  is(reverse_ip_address_for_rbl($ipv6), 'e.4.6.a.9.3.b.f.b.d.4.3.1.2.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f');
}

sub t_get_ptr_record : Test(2)
{
  my $ipv4 = '1.1.1.1';
  my $ipv6 = '2606:4700:4700::1111';

  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 2
    }
    is(Mail::MIMEDefang::Net::get_ptr_record($ipv4), 'one.one.one.one');
    is(Mail::MIMEDefang::Net::get_ptr_record($ipv6), 'one.one.one.one');
  }
}

sub t_get_ptr_record_ipv6_zone : Test(2)
{
  my @asked;
  md_dns_cache_clear();
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::send = sub {
    my (undef, $name, $type) = @_;
    push(@asked, $name);
    return _fake_reply($name, $type, 'NOERROR', "$name. 300 IN PTR host.example.org.");
  };
  is(Mail::MIMEDefang::Net::get_ptr_record('2001:db8::1'), 'host.example.org');
  is($asked[0], '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
     'IPv6 PTR lookups go to ip6.arpa');
  md_dns_cache_clear();
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

sub t_md_get_bogus_mx_hosts : Test(1)
{
  my $domain = 'multihomed.dnsbltest.spamassassin.org';

  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    my @res = md_get_bogus_mx_hosts($domain);
    is(scalar @res, 1);
  }
}

sub t_md_get_dmarc_record : Test(2)
{
  my $domain = 'dmarc4.spamassassin.org';
  my $subdomain = 'multihomed.dnsbltest.spamassassin.org';

  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    my $res = md_get_dmarc_record($domain);
    is($res, 'v=DMARC1; p=reject; adkim=s; aspf=s;');
    $res = md_get_dmarc_record($subdomain);
    is($res, undef);
  }
}

sub t_get_mx_ip_addresses : Test(1)
{
  my $domain = 'mimedefang.org';

  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    my @res = get_mx_ip_addresses($domain);
    is(scalar @res, 1);
  }
}

# --- shared resolver and DNS answer cache (no network: send() is stubbed) ---

sub _fake_reply
{
  my ($name, $type, $rcode, @rdata) = @_;
  my $pkt = Net::DNS::Packet->new($name, $type);
  $pkt->header->qr(1);
  $pkt->header->rcode($rcode);
  foreach my $r (@rdata) {
    $pkt->push(answer => Net::DNS::RR->new($r));
  }
  return $pkt;
}

sub t_shared_resolver : Test(3)
{
  my $r1 = md_shared_resolver();
  isa_ok($r1, 'Net::DNS::Resolver');
  is(md_shared_resolver(), $r1, 'the resolver is reused');
  ok(!$r1->{defnames}, 'search list is not appended to lookups');
}

sub t_dns_query_cache : Test(11)
{
  my $calls = 0;
  my $reply;
  my $res = md_shared_resolver();
  md_dns_cache_clear();
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::send = sub { $calls++; return $reply; };

  # positive answer is cached, and the trailing dot / case do not matter
  $reply = _fake_reply('a.example.org', 'A', 'NOERROR', 'a.example.org. 120 IN A 192.0.2.1');
  my $p = md_dns_query($res, 'a.example.org', 'A');
  is(($p->answer)[0]->address, '192.0.2.1');
  md_dns_query(undef, 'A.Example.ORG.', 'A');
  is($calls, 1, 'second lookup answered from the cache');

  # NXDOMAIN: query() semantics (undef), cached; send() semantics (packet)
  $calls = 0;
  $reply = _fake_reply('nx.example.org', 'TXT', 'NXDOMAIN');
  is(md_dns_query($res, 'nx.example.org', 'TXT'), undef, 'NXDOMAIN gives undef with query');
  my $s = md_dns_query($res, 'nx.example.org', 'TXT', 'send');
  is($s->header->rcode, 'NXDOMAIN', 'NXDOMAIN packet is returned with send');
  is($calls, 1, 'negative answer was cached');

  # SERVFAIL and timeouts are never cached
  $calls = 0;
  $reply = _fake_reply('sf.example.org', 'A', 'SERVFAIL');
  md_dns_query($res, 'sf.example.org', 'A') for 1..2;
  is($calls, 2, 'SERVFAIL is not cached');
  $reply = undef;
  md_dns_query($res, 'to.example.org', 'A') for 1..2;
  is($calls, 4, 'timeout is not cached');

  # TTL expiry
  $calls = 0;
  $reply = _fake_reply('ttl.example.org', 'A', 'NOERROR', 'ttl.example.org. 1 IN A 192.0.2.9');
  md_dns_query($res, 'ttl.example.org', 'A');
  sleep(2);
  md_dns_query($res, 'ttl.example.org', 'A');
  is($calls, 2, 'entry expired after its TTL');

  # a resolver supplied by the caller is never cached
  $calls = 0;
  my $mine = Net::DNS::Resolver->new;
  $reply = _fake_reply('b.example.org', 'A', 'NOERROR', 'b.example.org. 120 IN A 192.0.2.2');
  md_dns_query($mine, 'b.example.org', 'A') for 1..2;
  is($calls, 2, 'caller-supplied resolver bypasses the cache');

  md_dns_cache_clear();
  $calls = 0;
  $reply = _fake_reply('a.example.org', 'A', 'NOERROR', 'a.example.org. 120 IN A 192.0.2.1');
  md_dns_query($res, 'a.example.org', 'A');
  md_dns_cache_clear();
  md_dns_query($res, 'a.example.org', 'A');
  is($calls, 2, 'md_dns_cache_clear empties the cache');
}

sub t_dns_txt_uses_cache : Test(2)
{
  my $calls = 0;
  my $res = md_shared_resolver();
  md_dns_cache_clear();
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::send = sub {
    $calls++;
    return _fake_reply('_dmarc.example.net', 'TXT', 'NOERROR',
                       '_dmarc.example.net. 300 IN TXT "v=DMARC1; p=none"');
  };
  is(scalar(md_dns_txt($res, '_dmarc.example.net', qr/^v=DMARC1/)), 'v=DMARC1; p=none');
  md_dns_txt($res, '_dmarc.example.net', qr/^v=DMARC1/);
  is($calls, 1, 'md_dns_txt goes through the cache');
}

sub t_dns_txt_multiple : Test(5)
{
  my $res = md_shared_resolver();
  md_dns_cache_clear();
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::send = sub {
    return _fake_reply('multi.example.net', 'TXT', 'NOERROR',
                       'multi.example.net. 300 IN TXT "google-site-verification=abc"',
                       'multi.example.net. 300 IN TXT "v=spf1 " "-all"',
                       'multi.example.net. 300 IN TXT "v=spf1 +all"');
  };
  my @all = md_dns_txt($res, 'multi.example.net');
  is(scalar(@all), 3, 'list context returns every TXT record');
  my @spf = md_dns_txt($res, 'multi.example.net', qr/^v=spf1\b/);
  is_deeply(\@spf, ['v=spf1 -all', 'v=spf1 +all'], 'filter applies to every record, strings concatenated');
  is(scalar(md_dns_txt($res, 'multi.example.net', qr/^v=spf1\b/)), 'v=spf1 -all', 'scalar context returns the first match');
  my @none = md_dns_txt($res, 'multi.example.net', qr/^v=DMARC1/);
  is(scalar(@none), 0, 'no match is an empty list');
  ok(!defined scalar(md_dns_txt($res, 'multi.example.net', qr/^v=DMARC1/)), 'no match is undef in scalar context');
}

sub t_dns_query_nocache : Test(3)
{
  my $calls = 0;
  my $res = md_shared_resolver();
  md_dns_cache_clear();
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::send = sub {
    $calls++;
    return _fake_reply('nc.example.org', 'A', 'NOERROR', 'nc.example.org. 120 IN A 192.0.2.3');
  };

  my $p = md_dns_query($res, 'nc.example.org', 'A', 'query', 1);
  is(($p->answer)[0]->address, '192.0.2.3');
  md_dns_query(undef, 'nc.example.org', 'A', 'query', 1);
  is($calls, 2, 'nocache lookups always go to the network');
  md_dns_query($res, 'nc.example.org', 'A');
  is($calls, 3, 'nocache lookups do not fill the cache');
}

sub t_rbl_multi_uses_md_dns_query : Test(3)
{
  my @resolvers;
  pipe(my $rd, my $wr) or die "pipe: $!";
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::bgsend = sub { push(@resolvers, $_[0]); return $rd; };

  my $ans = relay_is_blacklisted_multi('192.0.2.1', 0, 0, ['rbl.example.org']);
  is($ans->{'rbl.example.org'}, 'SERVFAIL', 'no answer within the timeout');
  is(scalar(@resolvers), 1, 'one bgsend per blocklist');
  is($resolvers[0], md_shared_resolver(), 'the shared resolver is used');
}

# Fake zone for the MX tests: name/type => list of RRs
my %MX_ZONE = (
  'mx.example.org MX'      => ['mx.example.org. 300 IN MX 10 mail.example.org.',
                               'mx.example.org. 300 IN MX 20 mail6.example.org.'],
  'mail.example.org A'     => ['mail.example.org. 300 IN A 192.0.2.10'],
  'mail.example.org AAAA'  => ['mail.example.org. 300 IN AAAA 2001:4860:0:0::10'],
  'mail6.example.org AAAA' => ['mail6.example.org. 300 IN AAAA fe80::1'],
  'nomx.example.org A'     => ['nomx.example.org. 300 IN A 10.0.0.1'],
  'nomx.example.org AAAA'  => ['nomx.example.org. 300 IN AAAA 2001:4860::20'],
  'pref.example.org MX'    => ['pref.example.org. 300 IN MX 20 backup.example.org.',
                               'pref.example.org. 300 IN MX 10 primary.example.org.',
                               'pref.example.org. 300 IN MX 20 backup2.example.org.'],
  'primary.example.org A'  => ['primary.example.org. 300 IN A 192.0.2.1'],
  'backup.example.org A'   => ['backup.example.org. 300 IN A 192.0.2.2'],
  'backup2.example.org A'  => ['backup2.example.org. 300 IN A 192.0.2.3'],
);

sub _fake_mx_send
{
  my (undef, $name, $type) = @_;
  $name =~ s/\.$//;
  my $rrs = $MX_ZONE{"$name $type"} // [];
  return _fake_reply($name, $type, 'NOERROR', @$rrs);
}

sub t_get_mx_ip_addresses_ipv6 : Test(3)
{
  md_dns_cache_clear();
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::send = \&_fake_mx_send;

  my @res = get_mx_ip_addresses('mx.example.org');
  is_deeply(\@res, ['192.0.2.10', '2001:4860::10', 'fe80::1'],
            'A and AAAA records of every MX host');
  @res = get_mx_ip_addresses('nomx.example.org');
  is_deeply(\@res, ['10.0.0.1', '2001:4860::20'],
            'no MX: A and AAAA records of the domain');
  @res = md_get_bogus_mx_hosts('mx.example.org');
  is_deeply(\@res, ['fe80::1'], 'IPv6 MX hosts are checked as IPv6');
  md_dns_cache_clear();
}

sub t_get_mx_ip_addresses_sorted : Test(2)
{
  md_dns_cache_clear();
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::send = \&_fake_mx_send;

  my @res = get_mx_ip_addresses('pref.example.org');
  is_deeply(\@res, ['192.0.2.2', '192.0.2.1', '192.0.2.3'],
            'without the flag the DNS answer order is kept');
  @res = get_mx_ip_addresses('pref.example.org', undef, 1);
  is_deeply(\@res, ['192.0.2.1', '192.0.2.2', '192.0.2.3'],
            'with the flag addresses are sorted by MX preference');
  md_dns_cache_clear();
}

__PACKAGE__->runtests();
