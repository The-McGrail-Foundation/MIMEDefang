package Mail::MIMEDefang::Unit::SPF;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang::SPF;

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

__PACKAGE__->runtests();
