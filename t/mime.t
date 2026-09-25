package Mail::MIMEDefang::Unit::MIME;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use HTML::Parser;
use MIME::Base64 qw(encode_base64);
use MIME::Parser;
use MIME::Entity;

use Mail::MIMEDefang;
use Mail::MIMEDefang::MIME;

sub uri_utm_text : Test(1)
{
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

  my $entity = $parser->parse_open("t/data/uri.eml");
  if(anonymize_uri($entity)) {
    is($entity->bodyhandle->as_string(), 'Click on this http://www.example.com/My_Blog/mypage.aspx?id=123 url');
  } else {
    fail("uri_utm_text");
  }
  system('rm', '-rf', 't/tmp');
}

sub uri_utm_html : Test(1)
{
  init_globals();
  $Features{"HTML::Parser"} = 1;
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

  my $entity = $parser->parse_open("t/data/uri-html.eml");
  if(anonymize_uri($entity)) {
    like($entity->bodyhandle->as_string(), qr,<a href="http://www\.example\.com/My_Blog/mypage\.aspx\?id=123">test</a>,);
  } else {
    fail("uri_utm_html");
  }
  system('rm', '-rf', 't/tmp');
}

sub t_takeStabAtFilename : Test(1)
{
  init_globals();
  $Features{"HTML::Parser"} = 1;
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

  my $entity = $parser->parse_open("t/data/zip.eml");
  my $res;
  foreach my $p ( $entity->parts() ) {
    if($p->head->recommended_filename()) {
      $res = takeStabAtFilename($p);
      like($res, qr/test\.zip/);
    }
  }
  system('rm', '-rf', 't/tmp');
}

sub t_builtin_create_parser : Test(1)
{
  my $parser = builtin_create_parser();
  isa_ok($parser, 'MIME::Parser', 'builtin_create_parser returns a MIME::Parser');
}

sub t_find_part : Test(3)
{
  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);

  my $parser = MIME::Parser->new();
  $parser->extract_nested_messages(1);
  $parser->output_to_core(0);
  $parser->tmp_to_core(0);
  my $filer = MIME::Parser::FileInto->new('t/tmp');
  $filer->ignore_filename(1);
  $parser->filer($filer);

  my $entity = $parser->parse_open('t/data/multipart.eml');
  ok(defined find_part($entity, 'text/plain', 0), 'find_part finds text/plain part');
  ok(defined find_part($entity, 'application/octet-stream', 0), 'find_part finds application/octet-stream part');
  ok(!defined find_part($entity, 'text/x-nonexistent', 0), 'find_part returns undef for missing content-type');

  system('rm', '-rf', 't/tmp');
}

sub t_collect_parts : Test(1)
{
  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);

  my $parser = MIME::Parser->new();
  $parser->extract_nested_messages(1);
  $parser->output_to_core(0);
  $parser->tmp_to_core(0);
  my $filer = MIME::Parser::FileInto->new('t/tmp');
  $filer->ignore_filename(1);
  $parser->filer($filer);

  my $entity = $parser->parse_open('t/data/multipart.eml');
  @FlatParts = ();
  collect_parts($entity, 0);
  is(scalar @FlatParts, 3, 'collect_parts finds 3 leaf parts in multipart.eml');

  system('rm', '-rf', 't/tmp');
}

sub t_append_to_part : Test(2)
{
  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);

  my $parser = MIME::Parser->new();
  $parser->extract_nested_messages(1);
  $parser->output_to_core(0);
  $parser->tmp_to_core(0);
  my $filer = MIME::Parser::FileInto->new('t/tmp');
  $filer->ignore_filename(1);
  $parser->filer($filer);

  my $entity = $parser->parse_open('t/data/multipart.eml');
  my $plain = find_part($entity, 'text/plain', 0);
  my $ret = append_to_part($plain, 'boilerplate text');
  is($ret, 1, 'append_to_part returns 1 on success');
  like($plain->bodyhandle->as_string(), qr/boilerplate text/, 'append_to_part appended text to part body');

  system('rm', '-rf', 't/tmp');
}

sub t_remove_redundant_html : Test(2)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);

  my $parser = MIME::Parser->new();
  $parser->extract_nested_messages(1);
  $parser->output_to_core(0);
  $parser->tmp_to_core(0);
  my $filer = MIME::Parser::FileInto->new('t/tmp');
  $filer->ignore_filename(1);
  $parser->filer($filer);

  my $entity = $parser->parse_open('t/data/multipart.eml');
  ok(defined find_part($entity, 'text/html', 0), 'text/html part exists before remove_redundant_html_parts');

  $InFilterEnd = 1;
  remove_redundant_html_parts($entity);
  ok(!defined find_part($entity, 'text/html', 0), 'text/html part removed after remove_redundant_html_parts');

  system('rm', '-rf', 't/tmp');
}

sub t_append_text_boilerplate : Test(2)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);

  my $parser = MIME::Parser->new();
  $parser->extract_nested_messages(1);
  $parser->output_to_core(0);
  $parser->tmp_to_core(0);
  my $filer = MIME::Parser::FileInto->new('t/tmp');
  $filer->ignore_filename(1);
  $parser->filer($filer);

  my $entity = $parser->parse_open('t/data/multipart.eml');
  my $ret = append_text_boilerplate($entity, '-- test signature', 0);
  is($ret, 1, 'append_text_boilerplate returns 1 on success');
  my $plain = find_part($entity, 'text/plain', 0);
  like($plain->bodyhandle->as_string(), qr/test signature/, 'append_text_boilerplate appended text to text/plain part');

  system('rm', '-rf', 't/tmp');
}

sub t_append_html_boilerplate : Test(2)
{
  init_globals();
  $Features{"HTML::Parser"} = 1;

  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);

  my $parser = MIME::Parser->new();
  $parser->extract_nested_messages(1);
  $parser->output_to_core(0);
  $parser->tmp_to_core(0);
  my $filer = MIME::Parser::FileInto->new('t/tmp');
  $filer->ignore_filename(1);
  $parser->filer($filer);

  my $entity = $parser->parse_open('t/data/multipart.eml');
  my $ret = append_html_boilerplate($entity, '<p>-- sig</p>', 0);
  is($ret, 1, 'append_html_boilerplate returns 1 on success');
  my $html = find_part($entity, 'text/html', 0);
  like($html->bodyhandle->as_string(), qr/<p>-- sig<\/p>/, 'append_html_boilerplate appended HTML before </body>');

  system('rm', '-rf', 't/tmp');
}

sub concatenated_base64_detected : Test(3)
{
  Mail::MIMEDefang::MIME::md_mime_prepare();
  my ($parser, $entity) =
    Mail::MIMEDefang::Unit::parse_string(Mail::MIMEDefang::Unit::base64_message(encode_base64("Hello, ") . encode_base64("world!")));
  Mail::MIMEDefang::MIME::md_mime_note_parse($parser);
  is(md_concatenated_base64(), 1, 'base64 part made of two streams is noticed');

 SKIP: {
    skip 'MIME-tools older than 5.519 does not join concatenated streams', 1
      unless MIME::Tools->VERSION >= 5.519;
    is($entity->parts(1)->bodyhandle->as_string(), 'Hello, world!',
       'concatenated streams decode as one payload');
  }

  Mail::MIMEDefang::MIME::md_mime_prepare();
  is(md_concatenated_base64(), 0, 'flag is reset before the next message');
}

sub single_base64_stream_not_flagged : Test(2)
{
  Mail::MIMEDefang::MIME::md_mime_prepare();
  my ($parser, $entity) = Mail::MIMEDefang::Unit::parse_string(Mail::MIMEDefang::Unit::base64_message(encode_base64("Hello, world!")));
  Mail::MIMEDefang::MIME::md_mime_note_parse($parser);
  is(md_concatenated_base64(), 0, 'single padded stream is not flagged');

  Mail::MIMEDefang::MIME::md_mime_prepare();
  ($parser, $entity) = Mail::MIMEDefang::Unit::parse_string(Mail::MIMEDefang::Unit::base64_message(encode_base64("x" x 5000)));
  Mail::MIMEDefang::MIME::md_mime_note_parse($parser);
  is(md_concatenated_base64(), 0, 'long multi-line stream is not flagged');
}

sub base64_tap_chunk_boundaries : Test(3)
{
  ok(Mail::MIMEDefang::Unit::tap_found('QUJDQQ==', 'QUJD'), 'data after padding in the next chunk is noticed');
  ok(!Mail::MIMEDefang::Unit::tap_found('QUJDQQ=', "=\n"), 'padding split across chunks is not flagged');
  ok(Mail::MIMEDefang::Unit::tap_found("QUJDQQ==\n", "\n\n", 'QUJD'),
     'data after padding is noticed across a whitespace-only chunk');
}

sub mime_suspicious : Test(4)
{
  Mail::MIMEDefang::MIME::md_mime_prepare();
  my ($parser, $entity) = Mail::MIMEDefang::Unit::parse_string(Mail::MIMEDefang::Unit::base64_message(encode_base64("Hello, world!")));
  Mail::MIMEDefang::MIME::md_mime_note_parse($parser);
  is(md_mime_suspicious(), 0, 'ordinary message is not suspicious');

  Mail::MIMEDefang::MIME::md_mime_prepare();
  ($parser, $entity) =
    Mail::MIMEDefang::Unit::parse_string(Mail::MIMEDefang::Unit::base64_message(encode_base64("Hello, ") . encode_base64("world!")));
  Mail::MIMEDefang::MIME::md_mime_note_parse($parser);
  is(md_mime_suspicious(), 0, 'concatenated base64 alone is not reported as ambiguous MIME');

 SKIP: {
    skip 'MIME::Parser has no ambiguous_content', 2
      unless MIME::Parser->can('ambiguous_content');

    Mail::MIMEDefang::MIME::md_mime_prepare();
    ($parser, $entity) = Mail::MIMEDefang::Unit::parse_string("From: a\@example.com\nTo: b\@example.com\n" .
      "Subject: test\nContent-Type: text/plain\nContent-Type: text/html\n\nbody\n");
    Mail::MIMEDefang::MIME::md_mime_note_parse($parser);
    is(md_mime_suspicious(), 1, 'repeated Content-Type header is reported');

    Mail::MIMEDefang::MIME::md_mime_prepare();
    is(md_mime_suspicious(), 0, 'flag is reset before the next message');
  }
}

__PACKAGE__->runtests();
