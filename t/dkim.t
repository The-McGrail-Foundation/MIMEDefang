package Mail::MIMEDefang::Unit::DKIM;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::DKIM;

use File::Copy;

sub dkim_sign : Test(1)
{
  copy('t/data/uri.eml', './INPUTMSG');

  my $correct_signature;
  open(FD, '<', 't/data/dkim_sig.txt') or die("Cannot open signature file: $!");
  while(<FD>) {
    local $/;
    $correct_signature .= $_;
  }
  close(FD);

  my $dkim_sig = md_dkim_sign('t/data/dkim.pem');
  is($dkim_sig, $correct_signature);
  unlink('./INPUTMSG');
}

__PACKAGE__->runtests();
