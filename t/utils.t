package Mail::MIMEDefang::Unit::Utils;

use strict;
use warnings;
use lib qw(lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang::Core;
use Mail::MIMEDefang::Utils;

sub t_percent_encode : Test(1)
{
  my $pe = percent_encode("foo\r\nbar\tbl%t");
  is($pe, "foo%0D%0Abar%09bl%25t");
}

sub t_percent_decode : Test(2)
{
  my $pd = percent_decode("foo%0D%0Abar%09bl%25t");
  is($pd, "foo\r\nbar\tbl%t");
}

sub t_synthetize : Test(3)
{
  init_globals();
  $Helo = "test.example.com";
  my $hn = $Helo;
  $SendmailMacros{"if_name"} = $Helo;
  $RealRelayAddr = "1.2.3.4";
  $Sender = 'me@example.com';
  my $header = synthesize_received_header();
  like($header, qr/Received\: from $Helo \( \[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTP id NOQUEUE/);
}

__PACKAGE__->runtests();
