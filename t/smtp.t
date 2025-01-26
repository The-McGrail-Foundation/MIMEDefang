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
    like($ret, qr/5\.7\.1 /);
  };
}

sub t1_smtp : Test(2)
{
  SKIP: {
    if ( (not defined $ENV{'SMTP_TEST'}) or ($ENV{'SMTP_TEST'} ne 'yes' )) {
      skip "Smtp test disabled", 1
    }
    my $from = 'defang';
    my $to = 'defang';
    my $filemail = "t/data/multipart.eml";
    my $ret = Mail::MIMEDefang::Unit::smtp_mail($from, $to, $filemail);
    sleep 5;
    like($ret, qr/2\.0\.0 /);
    $filemail = "t/data/exe.eml";
    $ret = Mail::MIMEDefang::Unit::smtp_mail($from, $to, $filemail);
    sleep 5;
    my $warning = 0;
    if(open(my $fh, '<', '/var/spool/mail/defang')) {
      while(my $line = <$fh>) {
        if($line =~ /An attachment named test.exe was removed/) {
          $warning = 1;
        }
      }
      close $fh;
    }
    is($warning, 1);
  };
}

__PACKAGE__->runtests();
