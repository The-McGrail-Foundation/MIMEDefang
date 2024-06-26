package Mail::MIMEDefang::Unit::Authres;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Authres;

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

__PACKAGE__->runtests();
