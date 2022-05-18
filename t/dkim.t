package Mail::MIMEDefang::Unit::DKIM;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::DKIM;

use File::Copy;

sub dkim_sign : Test(2)
{
  copy('t/data/uri.eml', './INPUTMSG');

  my $correct_signature;
  open(FD, '<', 't/data/dkim_sig.txt') or die("Cannot open signature file: $!");
  while(<FD>) {
    local $/;
    $correct_signature .= $_;
  }
  close(FD);
  my ($header, $dkim_sig) = md_dkim_sign('t/data/dkim.pem');
  is($dkim_sig, $correct_signature);
  undef $correct_signature;

  open(FD, '<', 't/data/dkim_sig2.txt') or die("Cannot open signature file: $!");
  while(<FD>) {
    local $/;
    $correct_signature .= $_;
  }
  close(FD);
  ($header, $dkim_sig) = md_dkim_sign('t/data/dkim.pem', 'rsa-sha256', undef, 'example.com', 'selector');
  is($dkim_sig, $correct_signature);
  undef $correct_signature;

  unlink('./INPUTMSG');
}

sub dkim_verify : Test(3)
{
  my ($result, $domain, $ksize);

  copy('t/data/dkim1.eml', './INPUTMSG');
  ($result, $domain, $ksize) = md_dkim_verify();
  is($result, "pass");
  is($ksize, 768);
  unlink('./INPUTMSG');

  copy('t/data/dkim2.eml', './INPUTMSG');
  ($result, $domain, $ksize) = md_dkim_verify();
  is($result, "fail");
  unlink('./INPUTMSG');
}

__PACKAGE__->runtests();
