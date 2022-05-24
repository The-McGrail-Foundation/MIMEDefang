package Mail::MIMEDefang::Unit::Authres;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Authres;

use File::Copy;

sub t_md_authres : Test(1)
{
  copy('t/data/dkim1.eml', './INPUTMSG');

  my $header = md_authres('test@sa-test.spamassassin.org', '1.2.3.4', 'sa-test.spamassassin.org');
  like($header, qr{sa\-test\.spamassassin\.org \(MIMEDefang\);(?:.*)\s+dkim=pass \(768\-bit key\) header\.d=sa-test\.spamassassin\.org header\.b=oRxHoP0Y;(?:.*)\s+spf=none \(sa\-test\.spamassassin\.org: domain of test\@sa\-test\.spamassassin\.org doesn't specify if 1\.2\.3\.4 is a permitted sender\) smtp\.mailfrom=test\@sa\-test\.spamassassin\.org;});

  unlink('./INPUTMSG');
}

__PACKAGE__->runtests();
