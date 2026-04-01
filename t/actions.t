package Mail::MIMEDefang::Unit::Utils;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use MIME::Parser;

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

sub t_bounce : Test(4)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  undef $results_fh;
  unlink('./RESULTS') if -f './RESULTS';

  my $ret = action_bounce('Too big', 554, '5.7.1');
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }  
  is($ret, 1, 'action_bounce returns 1');
  is($Actions{'bounce'}, 1, 'action_bounce incremented Actions{bounce}');
  open(my $fh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  my $raw = do {
    local $/;
    <$fh>
  };
  close($fh);
  like($raw, qr/B554 5\.7\.1 Too%20big/, 'action_bounce wrote correct B line with custom args');
  unlink('./RESULTS') if -f './RESULTS';

  # Defaults apply when args are missing
  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  action_bounce();
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }  
  open($fh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  seek $fh, 0, 0;
  $raw = do {
    local $/;
    <$fh>
  };
  close($fh);
  like($raw, qr/B554 5\.7\.1 Forbidden%20for%20policy%20reasons/, 'action_bounce uses defaults when args omitted');
  unlink('./RESULTS') if -f './RESULTS';
}

sub t_discard : Test(3)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  undef $results_fh;
  unlink('./RESULTS') if -f './RESULTS';

  my $ret = action_discard();
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }  
  is($ret, 1, 'action_discard returns 1');
  is($Actions{'discard'}, 1, 'action_discard incremented Actions{discard}');
  open(my $fh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  seek $fh, 0, 0;
  my $raw = do { local $/; <$fh> };
  close($fh);
  like($raw, qr/^D\n/, 'action_discard wrote D line');
  unlink('./RESULTS') if -f './RESULTS';
}

sub t_tempfail : Test(4)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  undef $results_fh;
  unlink('./RESULTS') if -f './RESULTS';

  my $ret = action_tempfail('try later', 451, '4.3.0');
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }
  is($ret, 1, 'action_tempfail returns 1');
  is($Actions{'tempfail'}, 1, 'action_tempfail incremented Actions{tempfail}');
  open(my $fh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  seek $fh, 0, 0;  
  my $raw = do { local $/; <$fh> };
  close($fh);
  like($raw, qr/T451 4\.3\.0 try%20later/, 'action_tempfail wrote correct T line with custom args');
  unlink('./RESULTS') if -f './RESULTS';

  # Defaults apply when args are missing
  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  action_tempfail();
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }
  open($fh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  seek $fh, 0, 0;  
  $raw = do { local $/; <$fh> };
  close($fh);
  like($raw, qr/T451 4\.3\.0 Try%20again%20later/, 'action_tempfail uses defaults when args omitted');
  unlink('./RESULTS') if -f './RESULTS';
}

sub t_envelope_ops : Test(3)
{
  undef $results_fh;
  unlink('./RESULTS') if -f './RESULTS';

  add_recipient('<new@example.com>');
  delete_recipient('<old@example.com>');
  change_sender('<sender@example.com>');

  undef $results_fh;
  open(my $fh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  seek $fh, 0, 0;
  my @lines = <$fh>;
  close($fh);
  like($lines[0], qr/^R/, 'add_recipient wrote R line');
  like($lines[1], qr/^S/, 'delete_recipient wrote S line');
  like($lines[2], qr/^f/, 'change_sender wrote f line');
  unlink('./RESULTS') if -f './RESULTS';
}

sub t_sm_quarantine : Test(2)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  undef $results_fh;
  unlink('./RESULTS') if -f './RESULTS';

  action_sm_quarantine('spam detected');
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }
  is($Actions{'sm_quarantine'}, 1, 'action_sm_quarantine set Actions{sm_quarantine}');
  open(my $fh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  seek $fh, 0, 0;  
  my $raw = do { local $/; <$fh> };
  close($fh);
  like($raw, qr/Qspam%20detected/, 'action_sm_quarantine wrote Q line');
  unlink('./RESULTS') if -f './RESULTS';
}

sub t_accept_drop : Test(4)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InFilterContext = 'action_accept';
  my $ret = action_accept();
  is($ret, 1, 'action_accept returns 1');
  is($Action, 'accept', 'action_accept sets $Action to accept');

  init_globals();
  $CWD = '.';
  $InFilterContext = 'action_drop';
  $ret = action_drop();
  is($ret, 1, 'action_drop returns 1');
  is($Action, 'drop', 'action_drop sets $Action to drop');
}

sub t_accept_drop_with_warning : Test(4)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InFilterContext = 'action_accept_with_warning';
  action_accept_with_warning('watch out');
  is($Action, 'accept', 'action_accept_with_warning sets $Action to accept');
  is($Warnings[0], "watch out\n", 'action_accept_with_warning pushes warning message');

  init_globals();
  $InFilterContext = 'action_drop_with_warning';
  action_drop_with_warning('dangerous content');
  is($Action, 'drop', 'action_drop_with_warning sets $Action to drop');
  is($Warnings[0], "dangerous content\n", 'action_drop_with_warning pushes warning message');
}

sub t_rebuild : Test(1)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  $InFilterWrapUp   = 0;
  action_rebuild();
  is($Rebuild, 1, 'action_rebuild sets $Rebuild to 1');
}

sub t_message_rejected : Test(4)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $InMessageContext = 1;
  is(message_rejected(), 0, 'message_rejected returns 0 when no rejection action taken');

  init_globals();
  $InMessageContext = 1;
  undef $results_fh;
  unlink('./RESULTS') if -f './RESULTS';
  action_bounce();
  is(message_rejected(), 1, 'message_rejected returns true after action_bounce');
  unlink('./RESULTS') if -f './RESULTS';

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  undef $results_fh;
  unlink('./RESULTS') if -f './RESULTS';
  action_tempfail();
  is(message_rejected(), 1, 'message_rejected returns true after action_tempfail');
  unlink('./RESULTS') if -f './RESULTS';

  init_globals();
  $InMessageContext = 1;
  undef $results_fh;
  unlink('./RESULTS') if -f './RESULTS';
  action_discard();
  is(message_rejected(), 1, 'message_rejected returns true after action_discard');
  unlink('./RESULTS') if -f './RESULTS';
}

sub t_add_part_and_process : Test(3)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);

  my $parser = MIME::Parser->new();
  $parser->extract_nested_messages(1);
  $parser->extract_uuencode(1);
  $parser->output_to_core(0);
  $parser->tmp_to_core(0);
  my $filer = MIME::Parser::FileInto->new('t/tmp');
  $filer->ignore_filename(1);
  $parser->filer($filer);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  $InFilterWrapUp   = 0;

  my $entity = $parser->parse_open('t/data/uri.eml');
  my $added = action_add_part($entity, 'text/plain', '-suggest', 'disclaimer text', 'disclaimer.txt', 'inline');
  ok(defined $added, 'action_add_part returns an entity');
  is(scalar @AddedParts, 1, 'action_add_part queued one part in @AddedParts');

  my $rebuilt = process_added_parts($entity);
  is(lc($rebuilt->head->mime_type), 'multipart/mixed', 'process_added_parts wraps entity in multipart/mixed');

  system('rm', '-rf', 't/tmp');
}

__PACKAGE__->runtests();
