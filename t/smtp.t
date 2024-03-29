package Mail::MIMEDefang::Unit::Smtp;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

sub t0_smtp_sa : Test(1)
{
  SKIP: {
    if ( (not defined $ENV{'SMTP_TEST'}) or ($ENV{'SMTP_TEST'} ne 'yes' )) {
      skip "Smtp test disabled", 1
    }
    my $from = 'defang';
    my $to = 'defang';
    my $filemail = "t/data/gtube.eml";
    my $ret = Mail::MIMEDefang::Unit::smtp_mail($from, $to, $filemail);
    like($ret, qr/5.7.1 /);
  };
}

sub t1_smtp : Test(1)
{
  SKIP: {
    if ( (not defined $ENV{'SMTP_TEST'}) or ($ENV{'SMTP_TEST'} ne 'yes' )) {
      skip "Smtp test disabled", 1
    }
    my $from = 'defang';
    my $to = 'defang';
    my $filemail = "t/data/multipart.eml";
    my $ret = Mail::MIMEDefang::Unit::smtp_mail($from, $to, $filemail);
    like($ret, qr/2.0.0 /);
  };
}

__PACKAGE__->runtests();
