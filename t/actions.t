package Mail::MIMEDefang::Unit::Utils;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;


use Mail::MIMEDefang;
use Mail::MIMEDefang::Actions;

sub t_get_quarantine_dir : Test(1)
{
  init_globals();
  # Set up temporary dir
  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);
  $Features{'Path:QUARANTINEDIR'} = 't/tmp';
  like(get_quarantine_dir, qr{.*\/(?:[0-9]{4})\-(?:[0-9]{2})\-(?:[0-9]{2})\-(?:[0-9]{2})\/qdir\-(?:[0-9]{4})\-(?:[0-9]{2})\-(?:[0-9]{2})\-(?:[0-9]{2})\.(?:[0-9]{2})\.(?:[0-9]{2})\-(?:[0-9]{3})});
  system('rm', '-rf', 't/tmp');
}

sub t_replace_with_warning : Test(1)
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

  $InFilterContext = 'action_replace_with_warning';
  my $entity = $parser->parse_open("t/data/uri.eml");
  my $ret;
  $ret = action_replace_with_warning('Warning');
  is($ret, 1);
  system('rm', '-rf', 't/tmp');
}

sub t_replace_with_url : Test(1)
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

  $InFilterContext = 'action_replace_with_url';
  my $entity = $parser->parse_open("t/data/uri.eml");
  my $ret;
  $ret = action_replace_with_url($entity, 't/tmp', 't/tmp', 'get file at _URL_');
  is($ret, 1);
  system('rm', '-rf', 't/tmp');
}

__PACKAGE__->runtests();
