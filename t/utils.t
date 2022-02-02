package Mail::MIMEDefang::Unit::Utils;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use MIME::Parser;

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

sub t_re_match : Test(4)
{
  my ($done, @parts);

  my $parser = new MIME::Parser;
  $parser->output_to_core(1);
  my $entity = $parser->parse_open("t/data/multipart.eml");
  @parts = $entity->parts();
  foreach my $part (@parts) {
    if($part->head->mime_encoding eq "base64") {
      $done = re_match($part, "wow\.bin");
      is($done, 1);
      $done = re_match($part, "test\.bin");
      is($done, 0);
    }
  }
}

sub t_re_match_ext : Test(5)
{
  my ($done, @parts);

  my $parser = new MIME::Parser;
  $parser->output_to_core(1);
  my $entity = $parser->parse_open("t/data/multipart.eml");
  @parts = $entity->parts();
  foreach my $part (@parts) {
    if($part->head->mime_encoding eq "base64") {
      $done = re_match_ext($part, "\.bin");
      is($done, 1);
      $done = re_match_ext($part, "\.txt");
      is($done, 0);
    }
  }
}

__PACKAGE__->runtests();
