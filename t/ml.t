package Mail::MIMEDefang::Unit::ML;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang::ML;

my $real_post = \&Mail::MIMEDefang::ML::http_post_json;

# Replace the HTTP layer with a canned response, recording the request.
my ($last_url, $last_payload, $last_headers);
sub _stub {
  my ($resp) = @_;
  no warnings 'redefine';
  *Mail::MIMEDefang::ML::http_post_json = sub {
    ($last_url, $last_payload, $last_headers) = @_;
    return $resp;
  };
}

sub _state {
  return ml_build_state(From => 'a@example.com', Subject => 'hi', Body => 'hello', SPF => 'pass');
}

sub t_build_state : Test(5)
{
  local $Mail::MIMEDefang::ML::Config{body_head_chars} = 10;
  local $Mail::MIMEDefang::ML::Config{body_tail_chars} = 5;

  my $state = ml_build_state(From => 'a@example.com', Body => ('x' x 10) . ('y' x 20) . 'zzzzz',
                              SARules => [qw(A B C)], SAScore => '5.5');
  is($state->{body}, ('x' x 10) . "\n[...truncated...]\nzzzzz", 'body truncated head+tail');
  is($state->{subject}, '', 'missing subject defaults to empty');
  is($state->{dkim}, 'unknown', 'missing DKIM defaults to unknown');
  is($state->{sa_score}, 5.5, 'SA score included when passed');

  $state = ml_build_state(From => 'a@example.com');
  ok(!exists $state->{sa_score} && !exists $state->{sa_rules}, 'no SA keys when not passed');
}

sub t_build_state_spam_results : Test(7)
{
  local $Mail::MIMEDefang::ML::Config{spam_top_rules} = 2;

  my $state = ml_build_state(From => 'a@example.com', Body => 'hello',
                              SAScore => '5.5', SARules => [qw(A B C)],
                              RspamdScore => 7, RspamdSymbols => 'R_ONE, R_TWO,R_THREE');
  is($state->{sa_score}, 5.5, 'SA score numified');
  is_deeply($state->{sa_rules}, [qw(A B)], 'SA rules capped');
  is($state->{rspamd_score}, 7, 'Rspamd score');
  is_deeply($state->{rspamd_rules}, [qw(R_ONE R_TWO)], 'Rspamd symbols split from string and capped');

  my $text = Mail::MIMEDefang::ML::state_to_text($state);
  like($text, qr/^SpamAssassin score: 5\.5\nSpamAssassin rules: A, B$/m, 'SA in text');
  like($text, qr/^Rspamd score: 7\nRspamd rules: R_ONE, R_TWO$/m, 'Rspamd in text');

  $state = ml_build_state(From => 'a@example.com', SARules => 'A');
  ok(!exists $state->{sa_score} && !exists $state->{sa_rules}, 'rules without a score are dropped');
}

sub t_build_state_entity : Test(9)
{
  require MIME::Entity;
  my $entity = MIME::Entity->build(
    From          => '=?UTF-8?Q?Jane_D=C3=B6e?= <admin@example.org>',
    'Reply-To'    => 'sales@example.com',
    To            => 'a@example.com',
    Subject       => '=?UTF-8?B?Q2FwaXRhbCDigJQgcGxhbm5pbmc=?=',
    'X-Mailer'    => 'Mass Mailer ' . ('x' x 300),
    'X-Spam-Flag' => 'YES',
    Type          => 'text/plain',
    Charset       => 'utf-8',
    Data          => ["Hello there\n"],
  );
  my $state = ml_build_state(Entity => $entity, MailFrom => 'bounce@example.org', SPF => 'pass');
  is($state->{from}, "Jane D\x{f6}e <admin\@example.org>", 'From decoded from header');
  is($state->{reply_to}, 'sales@example.com', 'Reply-To from header');
  is($state->{subject}, "Capital \x{2014} planning", 'Subject decoded from header');
  like($state->{body}, qr/^Hello there/, 'body from entity');
  is($state->{headers}{To}, 'a@example.com', 'configured header read');
  ok(!exists $state->{headers}{'X-Spam-Flag'} && !exists $state->{headers}{From}, 'unlisted and dedicated headers left out');
  is(length($state->{headers}{'X-Mailer'}), $Mail::MIMEDefang::ML::Config{header_max_chars} + 3, 'header capped');

  my $text = Mail::MIMEDefang::ML::state_to_text($state);
  like($text, qr/^Envelope-From: bounce\@example\.org\n.*^To: a\@example\.com\n.*^X-Mailer: Mass/ms, 'headers rendered in order');

  $state = ml_build_state(Entity => $entity, Subject => 'explicit');
  is($state->{subject}, 'explicit', 'explicit args win over the entity');
}

sub t_dispatch_errors : Test(3)
{
  local $Mail::MIMEDefang::ML::Config{backend} = 'nosuch';
  like(ml_classify(_state())->{error}, qr/unknown backend/, 'unknown backend');

  local $Mail::MIMEDefang::ML::Config{enabled} = 0;
  is(ml_classify(_state())->{error}, 'disabled', 'disabled');

  $Mail::MIMEDefang::ML::Config{enabled} = 1;
  is(ml_classify(undef)->{error}, 'no state', 'no state');
}

sub t_chdir : Test(4)
{
  # mimedefang.pl and mimedefang-test-mail chdir() into the work directory
  # before filter_end; with a relative @INC (use lib 'modules/lib') the
  # backends must already be loaded by then.
  require Cwd;
  require File::Temp;
  my $cwd = Cwd::getcwd();
  chdir(File::Temp::tempdir(CLEANUP => 1)) or die "chdir: $!";

  for my $mod (qw(Laya GLiClass OpenAI)) {
    ok("Mail::MIMEDefang::ML::$mod"->can('classify'), "$mod loaded before chdir");
  }
  local $Mail::MIMEDefang::ML::Config{backend} = 'gliclass';
  _stub({ scores => { is_spam => 0.9, is_phishing => 0.1 } });
  my $v = ml_classify(_state());
  chdir($cwd) or die "chdir: $!";
  ok(!$v->{error}, 'classify works after chdir');
}

sub t_laya : Test(7)
{
  local $Mail::MIMEDefang::ML::Config{backend} = 'laya';

  _stub({ answers => {
    is_spam     => { noul => 0.9, confidence => 0.85 },
    is_phishing => { noul => 0.2, confidence => 0.40 },
  } });
  my $v = ml_classify(_state());
  like($last_url, qr{:8687/predict$}, 'laya url');
  is($last_payload->{questions}{is_spam}{type}, 'noul', 'noul questions');
  is($v->{backend}, 'laya', 'backend reported');
  is($v->{is_spam}{answer}, 1, 'spam yes');
  is($v->{is_spam}{confidence}, 0.85, 'spam confidence');
  ok(!defined $v->{is_phishing}{answer}, 'low confidence -> no opinion');

  _stub({ error => '500 Internal Server Error' });
  is(ml_classify(_state())->{error}, '500 Internal Server Error', 'http error passed through');
}

sub t_gliclass : Test(7)
{
  local $Mail::MIMEDefang::ML::Config{backend} = 'gliclass';

  _stub({ scores => { is_spam => 0.1, is_phishing => 0.6 } });
  my $v = ml_classify(_state());
  like($last_url, qr{:8688/predict$}, 'gliclass url');
  like($last_payload->{text}, qr/^From: a\@example\.com\n.*SPF: pass.*\n\nhello$/s, 'state rendered as text');
  ok(exists $last_payload->{labels}{is_spam} && exists $last_payload->{labels}{is_phishing}, 'labels sent');
  is($v->{is_spam}{answer}, 0, 'spam no');
  cmp_ok(abs($v->{is_spam}{confidence} - 0.9), '<', 1e-9, 'no-confidence is 1-p');
  is($v->{is_phishing}{answer}, 1, 'p=0.6 -> yes, confidence 0.6 passes default gate');

  _stub({ nothing => 1 });
  is(ml_classify(_state())->{error}, 'bad response', 'missing scores');
}

sub t_openai : Test(15)
{
  local $Mail::MIMEDefang::ML::Config{backend} = 'openai';
  local $Mail::MIMEDefang::ML::Config{openai}{model};
  is(ml_classify(_state())->{error}, 'no model configured', 'model required');

  $Mail::MIMEDefang::ML::Config{openai}{model} = 'test-model';
  local $Mail::MIMEDefang::ML::Config{openai}{base_url} = 'http://127.0.0.1:11434/v1/';

  _stub({ choices => [ { message => { content =>
    "<think>hmm {not json}</think>```json\n"
    . '{"is_spam": 0.95, "is_phishing": 0.3}'
    . "\n```" } } ] });
  my $v = ml_classify(_state());
  is($last_url, 'http://127.0.0.1:11434/v1/chat/completions', 'chat completions url');
  is($last_payload->{model}, 'test-model', 'model sent');
  is($last_payload->{reasoning_effort}, 'none', 'thinking disabled by default');
  is($v->{is_spam}{answer}, 1, 'spam yes');
  is($v->{is_phishing}{answer}, 0, 'phishing no');
  cmp_ok(abs($v->{is_phishing}{confidence} - 0.7), '<', 1e-9, 'no-confidence is 1-p');

  _stub({ choices => [ { message => { content => 'I think it is spam' } } ] });
  is(ml_classify(_state())->{error}, 'bad json', 'prose reply -> error');

  _stub({ choices => [ { message => { content =>
    '{"is_spam": 7}' } } ] });
  is(ml_classify(_state())->{is_spam}{confidence}, 1, 'confidence clamped');

  _stub({ choices => [ { message => { content =>
    '{"is_spam": false, "is_phishing": "maybe"}' } } ] });
  $v = ml_classify(_state());
  is_deeply([$v->{is_spam}{answer}, $v->{is_spam}{confidence}], [0, 1], 'bare boolean accepted');
  ok(!defined $v->{is_phishing}{answer}, 'non-numeric -> no opinion');

  _stub({ choices => [ { finish_reason => 'length',
    message => { content => '', reasoning => 'Okay, let me think about' } } ] });
  like(ml_classify(_state())->{error}, qr/^empty reply \(max_tokens reached/, 'thinking ran out of tokens');

  _stub({ choices => [ { message => { content => '' } } ] });
  is(ml_classify(_state())->{error}, 'empty reply', 'empty reply');

  _stub({ choices => [ { message => { content => '', reasoning =>
    'Spammy. {"is_spam": 0.9, "is_phishing": 0.2}' } } ] });
  is(ml_classify(_state())->{is_spam}{confidence}, 0.9, 'verdict taken from reasoning field');

  local $Mail::MIMEDefang::ML::Config{openai}{reasoning_effort} = '';
  ml_classify(_state());
  ok(!exists $last_payload->{reasoning_effort}, 'reasoning_effort can be omitted');
}

sub t_live : Test(1)
{
  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )
         or not defined $ENV{'ML_TEST_BACKEND'}) {
      skip "Net test disabled or ML_TEST_BACKEND not set", 1
    }
    # Needs the real HTTP layer.
    { no warnings 'redefine'; *Mail::MIMEDefang::ML::http_post_json = $real_post; }
    local $Mail::MIMEDefang::ML::Config{backend} = $ENV{'ML_TEST_BACKEND'};
    local $Mail::MIMEDefang::ML::Config{openai}{model} = $ENV{'ML_TEST_MODEL'}
      if defined $ENV{'ML_TEST_MODEL'};
    local $Mail::MIMEDefang::ML::Config{openai}{base_url} = $ENV{'ML_TEST_BASE_URL'}
      if defined $ENV{'ML_TEST_BASE_URL'};
    my $v = ml_classify(ml_build_state(From => 'winner@example.com',
      Subject => 'You won 1,000,000 USD!!!',
      Body => 'Click here to claim your prize, send your bank details today.'));
    ok(!$v->{error}, 'live verdict: ' . ($v->{error} // "spam=$v->{is_spam}{confidence}"));
  };
}

__PACKAGE__->runtests();
