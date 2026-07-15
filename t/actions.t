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

sub t_insert_header_now : Test(4)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';

  open(my $fh, '>', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  print $fh "Subject: Hello\nFrom: sender\@example.com\n\nBody line 1\nBody line 2\n";
  close($fh);

  my $ret = action_insert_header_now('X-Test', 'insertedvalue');
  is($ret, 1, 'action_insert_header_now returns 1');
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }

  open(my $rfh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  my $raw = do { local $/; <$rfh> };
  close($rfh);
  like($raw, qr/^NX-Test 0 insertedvalue$/m, 'action_insert_header_now wrote N line');

  open(my $ifh, '<', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  my $msg = do { local $/; <$ifh> };
  close($ifh);
  is($msg, "X-Test: insertedvalue\nSubject: Hello\nFrom: sender\@example.com\n\nBody line 1\nBody line 2\n",
     'action_insert_header_now put the new header first and left the body untouched');
  like($msg, qr/\n\nBody line 1\nBody line 2\n$/, 'body is unchanged');

  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';
}

sub t_add_header_now : Test(3)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';

  open(my $fh, '>', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  print $fh "Subject: Hello\nFrom: sender\@example.com\n\nBody line 1\n";
  close($fh);

  my $ret = action_add_header_now('X-Added', 'addedvalue');
  is($ret, 1, 'action_add_header_now returns 1');
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }

  open(my $rfh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  my $raw = do { local $/; <$rfh> };
  close($rfh);
  like($raw, qr/^HX-Added addedvalue$/m, 'action_add_header_now wrote H line');

  open(my $ifh, '<', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  my $msg = do { local $/; <$ifh> };
  close($ifh);
  is($msg, "Subject: Hello\nFrom: sender\@example.com\nX-Added: addedvalue\n\nBody line 1\n",
     'action_add_header_now appended the new header at the end of the header block');

  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';
}

sub t_change_header_now : Test(4)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';

  open(my $fh, '>', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  print $fh "X-Dup: one\nX-Folded: line1\n continuation\nX-Dup: two\n\nBody\n";
  close($fh);

  my $ret = action_change_header_now('X-Dup', 'changed', 2);
  is($ret, 1, 'action_change_header_now returns 1');
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }

  open(my $rfh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  my $raw = do { local $/; <$rfh> };
  close($rfh);
  like($raw, qr/^IX-Dup 2 changed$/m, 'action_change_header_now wrote I line');

  open(my $ifh, '<', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  my $msg = do { local $/; <$ifh> };
  close($ifh);
  is($msg, "X-Dup: one\nX-Folded: line1\n continuation\nX-Dup: changed\n\nBody\n",
     'action_change_header_now changed only the 2nd X-Dup instance and preserved the folded header');
  like($msg, qr/X-Dup: one\n/, 'first X-Dup instance is untouched');

  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';
}

sub t_delete_header_now : Test(3)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';

  open(my $fh, '>', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  print $fh "X-Dup: one\nX-Folded: line1\n continuation\nX-Dup: two\n\nBody\n";
  close($fh);

  my $ret = action_delete_header_now('X-Dup', 1);
  is($ret, 1, 'action_delete_header_now returns 1');
  if (defined $results_fh) {
    close $results_fh;
    undef $results_fh;
  }

  open(my $rfh, '<', './RESULTS') or die "Cannot open RESULTS: $!";
  my $raw = do { local $/; <$rfh> };
  close($rfh);
  like($raw, qr/^JX-Dup 1$/m, 'action_delete_header_now wrote J line');

  open(my $ifh, '<', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  my $msg = do { local $/; <$ifh> };
  close($ifh);
  is($msg, "X-Folded: line1\n continuation\nX-Dup: two\n\nBody\n",
     'action_delete_header_now removed only the 1st X-Dup instance and preserved the folded header');

  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';
}

sub t_delete_all_headers_now : Test(2)
{
  no warnings qw(redefine once);
  local *::md_syslog = sub {};
  use warnings qw(redefine once);

  init_globals();
  $CWD = '.';
  $InMessageContext = 1;
  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';
  unlink('./HEADERS') if -f './HEADERS';

  open(my $fh, '>', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  print $fh "X-Dup: one\nX-Folded: line1\n continuation\nX-Dup: two\nX-Dup: three\n\nBody\n";
  close($fh);

  open(my $hfh, '>', './HEADERS') or die "Cannot open HEADERS: $!";
  print $hfh "X-Dup: one\nX-Folded: line1\nX-Dup: two\nX-Dup: three\n";
  close($hfh);

  my $ret = action_delete_all_headers_now('X-Dup');
  is($ret, 1, 'action_delete_all_headers_now returns 1');

  open(my $ifh, '<', './INPUTMSG') or die "Cannot open INPUTMSG: $!";
  my $msg = do { local $/; <$ifh> };
  close($ifh);
  is($msg, "X-Folded: line1\n continuation\n\nBody\n",
     'action_delete_all_headers_now removed every X-Dup instance and preserved the folded header');

  unlink('./RESULTS') if -f './RESULTS';
  unlink('./INPUTMSG') if -f './INPUTMSG';
  unlink('./HEADERS') if -f './HEADERS';
}

__PACKAGE__->runtests();
