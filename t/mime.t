package Mail::MIMEDefang::Unit::MIME;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use HTML::Parser;
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

__PACKAGE__->runtests();
