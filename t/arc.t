package Mail::MIMEDefang::Unit::DKIM::ARC;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::DKIM::ARC;

use File::Copy;
use version;

sub arc_sign : Test(6)
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
}
__PACKAGE__->runtests();
