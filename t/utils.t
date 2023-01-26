package Mail::MIMEDefang::Unit::Utils;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use MIME::Parser;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Utils;

use constant HAS_ARCHIVEZIP => eval { require Archive::Zip; };

sub t_percent_encode : Test(1)
{
  my $pe = percent_encode("foo\r\nbar\tbl%t");
  is($pe, "foo%0D%0Abar%09bl%25t");
}

sub t_percent_decode : Test(1)
{
  my $pd = percent_decode("foo%0D%0Abar%09bl%25t");
  is($pd, "foo\r\nbar\tbl%t");
}

sub t_synthetize : Test(4)
{
  init_globals();
  $Helo = "test.example.com";
  my $hn = $Helo;
  $SendmailMacros{"if_name"} = $Helo;
  $RealRelayAddr = "1.2.3.4";
  $Sender = 'me@example.com';
  my $header = synthesize_received_header();
  like($header, qr/Received\: from $Helo \( \[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTP id NOQUEUE/);

  $SendmailMacros{"tls_version"} = "1.2";
  $header = synthesize_received_header();
  like($header, qr/Received\: from $Helo \( \[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTPS id NOQUEUE/);

  undef $SendmailMacros{"tls_version"};
  $SendmailMacros{"auth_authen"} = "user";
  $header = synthesize_received_header();
  like($header, qr/Received\: from $Helo \( \[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTPA id NOQUEUE/);

  $SendmailMacros{"auth_authen"} = "user";
  $SendmailMacros{"tls_version"} = "1.2";
  $header = synthesize_received_header();
  like($header, qr/Received\: from $Helo \( \[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTPSA id NOQUEUE/);
}

sub t_re_match : Test(2)
{
  my ($done, @parts);

  my $parser = new MIME::Parser;
  $parser->output_to_core(1);
  my $entity = $parser->parse_open("t/data/multipart.eml");
  my $bad_exts = '(bin|exe|\{[^\}]+\})';
  my $re = '\.' . $bad_exts . '\.*$';
  @parts = $entity->parts();
  foreach my $part (@parts) {
    if($part->head->mime_encoding eq "base64") {
      $done = re_match($part, $re);
      is($done, 1);
    } else {
      $done = re_match($part, $re);
      is($done, 0);
    }
  }
}

sub t_re_match_ext : Test(2)
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

sub t_re_match_zip : Test(2)
{
  my ($done, @parts);

  SKIP: {
    skip "Archive::Zip is needed for this test to work", 1 unless (HAS_ARCHIVEZIP);

    # Set up temporary dir
    system('rm', '-rf', 't/tmp');
    mkdir('t/tmp', 0755);

    # Make a parser
    my $parser = MIME::Parser->new();
    $parser->extract_nested_messages(1);
    $parser->extract_uuencode(1);
    $parser->output_to_core(0);
    $parser->tmp_to_core(0);
    my $filer = MIME::Parser::FileInto->new('t/tmp');
    $filer->ignore_filename(1);
    $parser->filer($filer);

    detect_and_load_perl_modules();
    my $entity = $parser->parse_open("t/data/zip.eml");
    @parts = $entity->parts();
    foreach my $part (@parts) {
      my $bh = $part->bodyhandle();
      if (defined($bh)) {
        my $path = $bh->path();
        if (defined($path)) {
          $done = re_match_in_zip_directory($path, "\.bin");
          is($done, 0);
          $done = re_match_in_zip_directory($path, "\.txt");
          is($done, 1);
        }
      }
    }
    system('rm', '-rf', 't/tmp');
  };
}

sub t_gen_mx_id : Test(1)
{
  my $str = Mail::MIMEDefang::Utils::gen_mx_id();
  is(length($str), 7);
}

__PACKAGE__->runtests();
