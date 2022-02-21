package Mail::MIMEDefang::Unit::Smtp;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

sub t_smtp : Test(1)
{
  SKIP: {
    if ( ! -f "/.dockerenv" ) {
      skip "Smtp test should run inside Docker", 1
    }
    my $from = 'defang';
    my $to = 'defang';
    my $filemail = "t/data/multipart.eml";
    my $ret = Mail::MIMEDefang::Unit::smtp_mail($from, $to, $filemail);
    like($ret, qr/2.0.0 /);
  };
}

__PACKAGE__->runtests();
