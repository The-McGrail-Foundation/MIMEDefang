package Mail::MIMEDefang::Unit::DKIM;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::DKIM::ARC;

use File::Copy;

sub arc_sign : Test(3)
{
  copy('t/data/arc1.eml', './INPUTMSG');

  my %headers = md_arc_sign('t/data/dkim.pem', 'rsa-sha256', 'none', 'testing.dkim.org', undef, 'selector');
  like($headers{"ARC-Seal"}, qr/i=1; a=rsa\-sha256; cv=none; d=testing\.dkim\.org; s=selector; t=/);
  like($headers{"ARC-Message-Signature"}, qr/i=1; a=rsa\-sha256; c=relaxed\/relaxed; d=/);
  like($headers{"ARC-Authentication-Results"}, qr/i=1; testing\.dkim\.org; header\.From=mickey\@dkim\.org; dkim=pass/);

  unlink('./INPUTMSG');
}

__PACKAGE__->runtests();
