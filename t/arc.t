package Mail::MIMEDefang::Unit::DKIM::ARC;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

BEGIN {
  unless (eval { require Mail::DKIM::ARC::Signer; 1 }) {
    plan skip_all => 'Mail::DKIM (with ARC support) not installed';
  }
}

use Mail::MIMEDefang;
use Mail::MIMEDefang::DKIM::ARC;

use File::Copy;

sub arc_sign : Test(10)
{
  copy('t/data/arc1.eml', './INPUTMSG');

  my %headers = md_arc_sign('t/data/dkim.pem', 'rsa-sha256', 'none', 'testing.dkim.org', undef, 'selector');
  like($headers{"ARC-Seal"}, qr/i=1; a=rsa\-sha256; cv=none; d=testing\.dkim\.org; s=selector; t=/);
  like($headers{"ARC-Message-Signature"}, qr/i=1; a=rsa\-sha256; c=relaxed\/relaxed; d=/);
  like($headers{"ARC-Authentication-Results"}, qr/i=1; testing\.dkim\.org; header\.From=mickey\@dkim\.org; dkim=pass/);

  unlink('./INPUTMSG');
  undef %headers;

  copy('t/data/arc2.eml', './INPUTMSG');

  %headers = md_arc_sign('t/data/dkim.pem', 'rsa-sha256', 'none', 'sa-test.spamassassin.org', undef, 't0768');
  like($headers{"ARC-Seal"}, qr/i=1; a=rsa\-sha256; cv=none; d=sa-test\.spamassassin\.org; s=/);
  like($headers{"ARC-Message-Signature"}, qr/i=1; a=rsa\-sha256; c=relaxed\/relaxed; d=/);
  like($headers{"ARC-Authentication-Results"}, qr/i=1; sa-test.spamassassin.org;/);

  unlink('./INPUTMSG');
  undef %headers;

  # arc3.eml's generated A-R value contains a ": ", which the old header
  # split mis-keyed and dropped.
  copy('t/data/arc3.eml', './INPUTMSG');

  %headers = md_arc_sign('t/data/dkim.pem', 'rsa-sha256', 'none', 'mx.example.org', undef, 'selector');
  like($headers{"ARC-Seal"}, qr/i=1; a=rsa\-sha256; cv=none; d=mx\.example\.org; s=selector; t=/);
  like($headers{"ARC-Message-Signature"}, qr/i=1; a=rsa\-sha256; c=relaxed\/relaxed; d=/);
  like($headers{"ARC-Authentication-Results"}, qr/i=1; mx\.example\.org;.*dns: lookup ok/s);

  unlink('./INPUTMSG');
  undef %headers;

  copy('t/data/arc-wrong.eml', './INPUTMSG');

  %headers = md_arc_sign('t/data/dkim.pem', 'rsa-sha256', 'none', 'sa-test.spamassassin.org', undef, 't0768');
  is($headers{"ARC-Seal"}, undef);

  unlink('./INPUTMSG');
}
__PACKAGE__->runtests();
