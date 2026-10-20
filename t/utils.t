package Mail::MIMEDefang::Unit::Utils;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use File::Temp ();
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
  like($header, qr/Received\: from $Helo \(\[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTP id NOQUEUE/);

  $SendmailMacros{"tls_version"} = "1.2";
  $header = synthesize_received_header();
  like($header, qr/Received\: from $Helo \(\[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTPS id NOQUEUE/);

  undef $SendmailMacros{"tls_version"};
  $SendmailMacros{"auth_authen"} = "user";
  $header = synthesize_received_header();
  like($header, qr/Received\: from $Helo \(\[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTPA id NOQUEUE/);

  $SendmailMacros{"auth_authen"} = "user";
  $SendmailMacros{"tls_version"} = "1.2";
  $header = synthesize_received_header();
  like($header, qr/Received\: from $Helo \(\[$RealRelayAddr\]\)\n\tby $hn \(envelope-sender $Sender\) \(MIMEDefang\) with ESMTPSA id NOQUEUE/);
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

sub t_re_match_tgz_directory : Test(2)
{
  my ($done, @parts);

  ($Features{'tar'}) = map { "$_/tar" } grep { -x "$_/tar" } split(/:/, $ENV{PATH} // '');

  SKIP: {
    skip "tar(1) is needed for this test to work", 1 unless $Features{'tar'};

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
    my $entity = $parser->parse_open("t/data/tgz.eml");
    @parts = $entity->parts();
    foreach my $part (@parts) {
      my $bh = $part->bodyhandle();
      if (defined($bh)) {
        my $path = $bh->path();
        if (defined($path)) {
          $done = re_match_in_tgz_directory($path, "\.exe");
          is($done, 1);
          $done = re_match_in_tgz_directory($path, "\.txt");
          is($done, 0);
        }
      }
    }
    system('rm', '-rf', 't/tmp');
  };
}

sub t_re_match_tar_directory : Test(2)
{
  my ($done, @parts);

  ($Features{'tar'}) = map { "$_/tar" } grep { -x "$_/tar" } split(/:/, $ENV{PATH} // '');

  SKIP: {
    skip "tar(1) is needed for this test to work", 1 unless $Features{'tar'};

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
    my $entity = $parser->parse_open("t/data/tar.eml");
    @parts = $entity->parts();
    foreach my $part (@parts) {
      my $bh = $part->bodyhandle();
      if (defined($bh)) {
        my $path = $bh->path();
        next unless defined($path) && $path =~ /\.tar$/;
        $done = re_match_in_tgz_directory($path, "\.exe");
        is($done, 1);
        $done = re_match_in_tgz_directory($path, "\.txt");
        is($done, 0);
      }
    }
    system('rm', '-rf', 't/tmp');
  };
}

sub t_re_match_7zip_directory : Test(6)
{
  ($Features{'7zip'}) = map { "$_/7za" } grep { -x "$_/7za" } split(/:/, $ENV{PATH} // '');

  SKIP: {
    skip "7za(1) is needed for this test to work", 6 unless $Features{'7zip'};

    # Solid archive: only the first file of the block has a compressed
    # size, and a directory is listed first
    is(re_match_in_7zip_directory("t/data/multi.7z", '\.exe$'), 1, 'exe after the first entry');
    is(re_match_in_7zip_directory("t/data/multi.7z", '^readme\.txt$'), 1, 'file without compressed size');
    is(re_match_in_7zip_directory("t/data/multi.7z", 'c\.txt$'), 1, 'last entry');
    is(re_match_in_7zip_directory("t/data/multi.7z", '^sub$'), 0, 'directories are skipped');
    is(re_match_in_7zip_directory("t/data/multi.7z", '\.scr$'), 0, 'no match');

    # Encrypted headers: must not prompt for a password on stdin
    # archive protected with password "enc"
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm(20);
    my $r = eval { re_match_in_7zip_directory("t/data/enc.7z", '\.exe$') };
    alarm(0);
    is($r, 0, 'encrypted headers fail without hanging');
  };
}

sub t_re_match_rar_directory : Test(3)
{
  # Fake unrar(1) printing a real "unrar l" listing
  my $dir = File::Temp::tempdir(CLEANUP => 1);
  open(my $fh, '>', "$dir/unrar") or die "$dir/unrar: $!";
  print $fh <<'EOS';
#!/bin/sh
cat <<'EOF'

UNRAR 7.00 freeware      Copyright (c) 1993-2024 Alexander Roshal

Archive: test.rar
Details: RAR 5

 Attributes      Size     Date    Time   Name
----------- ---------  ---------- -----  ----
 -rw-r--r--         6  2026-10-20 22:39  readme.txt
 -rw-r--r--         4  2026-10-20 22:39  pay load.exe
----------- ---------  ---------- -----  ----
                   10                    2
 -rw-r--r--         4  2026-10-20 22:39  after.scr
EOF
EOS
  close($fh);
  chmod(0755, "$dir/unrar");
  local $ENV{PATH} = "$dir:$ENV{PATH}";
  local $Features{'unrar'} = "$dir/unrar";

  is(re_match_in_rar_directory("t/data/multi.7z", '\.exe$'), 1, 'exe after the first entry');
  is(re_match_in_rar_directory("t/data/multi.7z", '\.doc$'), 0, 'no match');
  is(re_match_in_rar_directory("t/data/multi.7z", '\.scr$'), 0, 'stops at the closing separator');
}

sub t_gen_mx_id : Test(1)
{
  my $str = Mail::MIMEDefang::Utils::gen_mx_id();
  is(length($str), 7);
}

__PACKAGE__->runtests();
