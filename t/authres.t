package Mail::MIMEDefang::Unit::Authres;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Authres;
use Mail::MIMEDefang::BIMI;

use File::Copy;

sub t_md_authres : Test(3)
{
  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    copy('t/data/dkim1.eml', './INPUTMSG');

    my $header = md_authres('test@sa-test.spamassassin.org', '1.2.3.4', 'sa-test.spamassassin.org');
    like($header, qr{sa\-test\.spamassassin\.org(?:\s\(MIMEDefang\))?;(?:.*)\s+dkim=pass \(768\-bit key\) header\.d=sa-test\.spamassassin\.org header\.b=oRxHoP0Y;(?:.*)\s+spf=none \(domain of test\@sa\-test\.spamassassin\.org doesn't specify if 1\.2\.3\.4 is a permitted sender\) smtp\.mailfrom=test\@sa\-test\.spamassassin\.org;});

    copy('t/data/spf1.eml', './INPUTMSG');

    $header = md_authres('test@dnsbltest.spamassassin.org', '64.142.3.173', 'dnsbltest.spamassassin.org', 'dnsbltest.spamassassin.org');
    like($header, qr{dnsbltest\.spamassassin\.org(?:\s\(MIMEDefang\))?;(?:.*)\s+\s+spf=pass \(domain of test\@dnsbltest\.spamassassin\.org designates 64\.142\.3\.173 as permitted sender\) smtp\.mailfrom=test\@dnsbltest\.spamassassin\.org;});
    like($header, qr{dnsbltest\.spamassassin\.org(?:\s\(MIMEDefang\))?;(?:.*)\s+\s+spf=pass \(domain of dnsbltest\.spamassassin\.org designates 64\.142\.3\.173 as permitted sender\) smtp\.helo=dnsbltest\.spamassassin\.org;});

    unlink('./INPUTMSG');
  };
}

sub t_md_authres_bimi : Test(1)
{
  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1;
    }
    copy('t/data/dkim1.eml', './INPUTMSG');
    my $header = md_authres(
      'test@sa-test.spamassassin.org', '1.2.3.4',
      'sa-test.spamassassin.org', undef, 'google.com'
    );
    like($header, qr{\bbimi=(?:pass|fail|none|declined|skipped|temperror)\b.*header\.d=google\.com},
         'md_authres appends bimi= token when bimi_domain is supplied');
    unlink('./INPUTMSG');
  };
}

sub t_md_org_domain : Test(8)
{
  my $org = \&Mail::MIMEDefang::Authres::md_org_domain;
  SKIP: {
    skip "IO::Socket::SSL::PublicSuffix is needed for this test", 5
      unless eval { require IO::Socket::SSL::PublicSuffix; 1 };
    is($org->('mail.example.com'), 'example.com', 'subdomain of a .com domain');
    is($org->('www.bank.co.uk'), 'bank.co.uk', 'multi-label public suffix');
    isnt($org->('evil.co.uk'), $org->('bank.co.uk'), 'different co.uk domains do not align');
    is($org->('co.uk'), '', 'a public suffix has no organizational domain');
    is($org->('Mail.Example.COM.'), 'example.com', 'case and trailing dot');
  };
  is($org->(undef), '', 'undef');
  is($org->('bad;domain.com'), '', 'invalid characters');
  is($org->('[192.0.2.1]'), '', 'address literal');
}

sub t_ar_sanitize : Test(7)
{
  my $mf = \&Mail::MIMEDefang::Authres::_ar_mailfrom;
  my $dom = \&Mail::MIMEDefang::Authres::_ar_domain;

  is($mf->('<user.name+tag@example.com>'), 'user.name+tag@example.com', 'plain address kept');
  is($mf->('"x;dkim=pass header.d=bank.com"@evil.example'), 'evil.example',
     'quoted local part reduced to the domain');
  is($mf->('user@evil;dkim=pass'), undef, 'invalid domain refused');
  is($mf->('<>'), undef, 'null sender');
  is($dom->('mx.example.com'), 'mx.example.com', 'host name kept');
  is($dom->('[IPv6:2001:db8::1]'), '[IPv6:2001:db8::1]', 'address literal kept');
  is($dom->('evil (spf=pass) x'), undef, 'HELO with spaces refused');
}

__PACKAGE__->runtests();
