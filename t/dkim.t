package Mail::MIMEDefang::Unit::DKIM;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::DKIM;

use File::Copy;

sub dkim_sign : Test(5)
{
  copy('t/data/uri.eml', './INPUTMSG');

  my ($correct_signature, $dkim_sig, $dkim_sig_notw, $header);

  # disable DKIM TextWrap, must be the first call
  # otherwise Mail::DKIM::TextWrap will be loaded and cannot be disabled
  open(my $fd, '<', 't/data/dkim_sig2a.txt') or die("Cannot open signature file: $!");
  while(<$fd>) {
    local $/;
    $correct_signature .= $_;
  }
  close($fd);
  ($header, $dkim_sig_notw) = md_dkim_sign('t/data/dkim.pem', 'rsa-sha256', 'relaxed', 'example.com', 'selector', undef, 0);
  is($dkim_sig_notw, $correct_signature);
  if($dkim_sig_notw =~ /(?<!;)\s/) {
    ko("DKIM without text wrap");
  } else {
    ok("DKIM without text wrap");
  }
  undef $correct_signature;

  open($fd, '<', 't/data/dkim_sig.txt') or die("Cannot open signature file: $!");
  while(<$fd>) {
    local $/;
    $correct_signature .= $_;
  }
  close($fd);

  ($header, $dkim_sig) = md_dkim_sign('t/data/dkim.pem');
  is($dkim_sig, $correct_signature);
  if($dkim_sig =~ /(?<!;)\s/) {
    ok("DKIM with text wrap");
  } else {
    ko("DKIM with text wrap");
  }
  undef $correct_signature;

  open($fd, '<', 't/data/dkim_sig2.txt') or die("Cannot open signature file: $!");
  while(<$fd>) {
    local $/;
    $correct_signature .= $_;
  }
  close($fd);
  ($header, $dkim_sig) = md_dkim_sign('t/data/dkim.pem', 'rsa-sha256', 'relaxed/simple', 'example.com', 'selector');
  is($dkim_sig, $correct_signature);
  undef $correct_signature;

  unlink('./INPUTMSG');
}

sub dkim_verify : Test(9)
{
  my ($result, $domain, $ksize, $selector);

  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1
    }
    copy('t/data/dkim1.eml', './INPUTMSG');
    ($result, $domain, $ksize, undef) = md_dkim_verify();
    is($result, "pass");
    is($ksize, 768);
    unlink('./INPUTMSG');

    copy('t/data/dkim2.eml', './INPUTMSG');
    ($result, $domain, $ksize) = md_dkim_verify();
    is($result, "fail");
    my $dkim_verify = md_dkim_verify();
    is($dkim_verify->result, "fail");
    is($dkim_verify->signature->get_tag('s'), 't0768');
    unlink('./INPUTMSG');

    copy('t/data/dkim3.eml', './INPUTMSG');
    ($result, $domain, $ksize) = md_dkim_verify();
    like($result, qr/fail|invalid/);
    my $res = md_dkim_verify();
    is($res->signature->selector, "20210112");
    unlink('./INPUTMSG');

    copy('t/data/spf1.eml', './INPUTMSG');
    ($result, $domain, $ksize) = md_dkim_verify();
    $res = md_dkim_verify();
    is($result, "none");
    is($res->result, "none");
    unlink('./INPUTMSG');
  };
}

__PACKAGE__->runtests();
