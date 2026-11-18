package Mail::MIMEDefang::Unit::SPF;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Net;
use Mail::MIMEDefang::SPF;
use Net::DNS;

sub t_md_spf_verify : Test(5)
{
  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    my ($spf_code, $spf_expl, $helo_spf_code, $helo_spf_expl) = md_spf_verify('newsalerts-noreply@dnsbltest.spamassassin.org', '1.2.3.4', 'dnsbltest.spamassassin.org');
    is($spf_code, 'fail');
    ($spf_code, $spf_expl, $helo_spf_code, $helo_spf_expl) = md_spf_verify('newsalerts-noreply@dnsbltest.spamassassin.org', '65.214.43.157', 'dnsbltest.spamassassin.org');
    is($spf_code, 'neutral');
    is($helo_spf_code, 'neutral');
    ($spf_code, $spf_expl, $helo_spf_code, $helo_spf_expl) = md_spf_verify('dnsbltest.spamassassin.org', '65.214.43.157', 'dnsbltest.spamassassin.org');
    is($spf_code, 'neutral');
    ($spf_code, $spf_expl, $helo_spf_code, $helo_spf_expl) = md_spf_verify('', '65.214.43.157', 'dnsbltest.spamassassin.org');
    is($spf_code, 'invalid');
  };
}

sub t_md_spf_verify_cached : Test(4)
{
  my $calls = 0;
  local $Features{"Net::DNS"} = 1;
  Mail::MIMEDefang::Net::md_dns_cache_clear();
  no warnings 'redefine';
  local *Net::DNS::Resolver::Base::send = sub {
    my (undef, $name, $type) = @_;
    $calls++;
    $name =~ s/\.$//;
    my $pkt = Net::DNS::Packet->new($name, $type);
    $pkt->header->qr(1);
    $pkt->header->rcode('NOERROR');
    if ($name eq 'spf.example.org' and $type eq 'TXT') {
      $pkt->push(answer => Net::DNS::RR->new('spf.example.org. 120 IN TXT "v=spf1 ip4:192.0.2.1 -all"'));
    }
    return $pkt;
  };

  my ($spf_code) = md_spf_verify('user@spf.example.org', '192.0.2.1');
  is($spf_code, 'pass');
  my $first = $calls;
  ok($first > 0, 'SPF record looked up');
  ($spf_code) = md_spf_verify('user@spf.example.org', '192.0.2.2');
  is($spf_code, 'fail');
  is($calls, $first, 'second check answered from the DNS cache');
  Mail::MIMEDefang::Net::md_dns_cache_clear();
}

__PACKAGE__->runtests();
