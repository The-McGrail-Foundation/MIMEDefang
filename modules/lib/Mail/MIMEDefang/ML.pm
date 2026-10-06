#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

package Mail::MIMEDefang::ML;

=head1 NAME

Mail::MIMEDefang::ML - provider-neutral ham/spam/phishing verdicts from
machine-learning models.

=head1 SYNOPSIS

  use Mail::MIMEDefang::ML;

  # Pick a backend, once, at the top of mimedefang-filter:
  $Mail::MIMEDefang::ML::Config{backend} = 'gliclass';   # or 'laya', 'openai'

  my $state = ml_build_state(
      From    => $Sender,
      Subject => $subject,                    # RFC 2047-decoded
      Body    => md_get_plain_text_body($entity),
      SPF     => $SPFResult,
      DKIM    => $DKIMResult,
      DMARC   => $DMARCResult,
      SAScore => $hits,                       # optional, see ml_build_state()
      SARules => $names,
  );

  my $verdict = ml_classify($state);
  # $verdict->{is_spam}{answer}      -> 1, 0, or undef (no opinion)
  # $verdict->{is_spam}{confidence}  -> 0.0 .. 1.0
  # $verdict->{is_phishing}{answer}
  # $verdict->{is_phishing}{confidence}
  # $verdict->{backend}              -> name of the backend that answered
  # $verdict->{error}                -> set, and the rest absent, on failure

=head1 DESCRIPTION

C<Mail::MIMEDefang::ML> is a single interface to several machine-learning
classification backends, so that a filter keeps the same code whichever
model gives the verdict.  Laya and GLiClass are encoder classifiers, small
and fast because they classify in one forward pass instead of generating
text; the C<openai> backend talks to a generative LLM.

Each backend lives in C<Mail::MIMEDefang::ML::E<lt>NameE<gt>>.  All backends
are loaded together with this module, i.e. when the filter is loaded,
before MIMEDefang changes into the per-message work directory.

=over 4

=item C<laya>

L<Mail::MIMEDefang::ML::Laya>, a non-autoregressive Laya decision model
served by C<mimedefang-laya-server>.

=item C<gliclass>

L<Mail::MIMEDefang::ML::GLiClass>, a GLiClass zero-shot encoder served by
C<mimedefang-gliclass-server>.  Like Laya it answers in a single forward
pass, so it is fast enough to run on every message.

=item C<openai>

L<Mail::MIMEDefang::ML::OpenAI>, a self-hosted generative model served through
the OpenAI-compatible chat completions API by Ollama, llama.cpp, vLLM or
LM Studio.  Use a model with at least 7-8 billion parameters, smaller ones
miss all but blatant spam (see L<Mail::MIMEDefang::ML::OpenAI/CHOOSING A MODEL>).
Generative models take seconds per message on CPU: raise C<timeout>, see
L<Mail::MIMEDefang::ML::OpenAI/TIMEOUT>.

=back

This module never blocks mail flow on a backend's availability: any failure
to reach the backend, or a low-confidence verdict, is treated as "no
opinion" so callers can fall back to their existing SpamAssassin/rspamd-only
path.

The stock models are not trained on your mail and their accuracy varies
a lot from site to site: for good results, train them first, see
L</TRAINING A MODEL>.

Backends are self-hosted model servers; see L</SECURITY> for how to keep
them safe.  C<mimedefang-laya-server> and C<mimedefang-gliclass-server>,
with instructions for installing their Python modules and models, are in
the F<script/ml-servers/> directory of the MIMEDefang sources.

The body truncation limits below are the defaults for every backend;
each backend's section can override them.

=head1 CONFIGURATION

Site admins override C<%Mail::MIMEDefang::ML::Config> from
F<mimedefang-filter>.  The keys, with their defaults:

  # Common settings
  $Mail::MIMEDefang::ML::Config{enabled}         = 1;       # 0 turns ml_classify() into a no-op
  $Mail::MIMEDefang::ML::Config{backend}         = 'laya';  # 'laya', 'gliclass' or 'openai'
  $Mail::MIMEDefang::ML::Config{timeout}         = 30;      # seconds per HTTP request
  $Mail::MIMEDefang::ML::Config{connect_retries} = 1;       # retries when the server can't be
                                                            # reached, never after a timeout
  $Mail::MIMEDefang::ML::Config{min_confidence}  = 0.55;    # below this -> no opinion
  $Mail::MIMEDefang::ML::Config{questions}       = [qw(is_spam is_phishing)];
                                                            # questions asked, e.g.
                                                            # ['is_phishing'] alone
  $Mail::MIMEDefang::ML::Config{question_texts}  = {};      # question wording, see below

  # What ml_build_state() puts in the state, and what backends get of it
  $Mail::MIMEDefang::ML::Config{body_head_chars} = 1500;    # body kept: first N chars ...
  $Mail::MIMEDefang::ML::Config{body_tail_chars} = 500;     # ... plus last N chars
  $Mail::MIMEDefang::ML::Config{spam_top_rules}  = 8;       # rules kept per engine
  $Mail::MIMEDefang::ML::Config{url_max_chars}   = 80;      # longer URLs are cut, 0: never
  $Mail::MIMEDefang::ML::Config{max_link_domains} = 5;      # link domains listed in the signals
  $Mail::MIMEDefang::ML::Config{max_attachments}  = 5;      # attachments listed in the signals

  # Laya (mimedefang-laya-server)
  $Mail::MIMEDefang::ML::Config{laya}{server_url}     = 'http://127.0.0.1:8687';
  $Mail::MIMEDefang::ML::Config{laya}{send_signals}   = 0;

  # GLiClass (mimedefang-gliclass-server)
  $Mail::MIMEDefang::ML::Config{gliclass}{server_url} = 'http://127.0.0.1:8688';
  $Mail::MIMEDefang::ML::Config{gliclass}{body_head_chars} = 6000;
  $Mail::MIMEDefang::ML::Config{gliclass}{body_tail_chars} = 1500;

  # Self-hosted generative model (Ollama, llama.cpp, vLLM, LM Studio)
  $Mail::MIMEDefang::ML::Config{openai}{base_url}     = 'http://127.0.0.1:11434/v1';
  $Mail::MIMEDefang::ML::Config{openai}{model}        = undef;   # required, e.g. 'qwen3:8b' (>= 7-8B parameters)
  $Mail::MIMEDefang::ML::Config{openai}{max_tokens}   = 100;
  $Mail::MIMEDefang::ML::Config{openai}{body_head_chars} = 6000;
  $Mail::MIMEDefang::ML::Config{openai}{body_tail_chars} = 1500;

Model latency grows faster than linearly with the text length: the
defaults assume a GPU, or a fast CPU.  On slower hardware lower the
per-backend budgets, or raise C<timeout>; C<ml_classify> can wait up to
C<timeout> seconds (C<connect_retries> only retries requests that could
not connect, which fail at once), keep that below the
multiplexor's busy timeout (see L<Mail::MIMEDefang::ML::OpenAI/TIMEOUT>).

C<questions> lists the questions the backend is asked, C<is_spam> and/or
C<is_phishing>.  Asking only one of them makes the request lighter
(fewer GLiClass labels, a shorter prompt and reply for generative models),
e.g. to use the model only as a phishing detector and leave spam to
SpamAssassin or rspamd.  It can also be set per call, see L</ml_classify($state, %opts)>.

C<question_texts> rewords the questions put to the backends that take
free-text instructions (Laya, generative models), keyed by question; a
question not in it keeps its default text from
C<%Mail::MIMEDefang::ML::QUESTIONS>.  Each of these backends can have its
own, which wins over the global one: Laya reads 512 tokens in all and
wants short texts, a generative model can take longer ones.

  $Mail::MIMEDefang::ML::Config{question_texts}{is_phishing} =
      'Is this email phishing?  ...';
  $Mail::MIMEDefang::ML::Config{laya}{question_texts}{is_spam} =
      'Is this email unsolicited bulk mail or a scam?';

GLiClass scores labels instead of answering questions: set them with
C<$Mail::MIMEDefang::ML::Config{gliclass}{labels}> and C<{ham_labels}>,
see L<Mail::MIMEDefang::ML::GLiClass/CONFIGURATION>.

See each backend's documentation for its remaining keys.

=head1 INTEGRATION EXAMPLE

A C<filter_end> in F<mimedefang-filter> that runs SpamAssassin as usual and
then asks the model for a second, independent opinion.  The model is additive,
not a replacement for the existing spam path: it only acts on confident
verdicts, and any error falls back to SpamAssassin alone.  This assumes
C<$SPFResult>, C<$DKIMResult> and C<$DMARCResult> were set earlier, in
C<filter_sender> and C<filter_begin>; see F<examples/example-filter-with-ml>
in the MIMEDefang sources for the complete filter.

  use Mail::MIMEDefang::ML;

  $Mail::MIMEDefang::ML::Config{backend} = 'gliclass';

  sub filter_end {
      my ($entity) = @_;
      return if message_rejected();

      my ($hits, $req, $names, $report);
      ($hits, $req, $names, $report) = spam_assassin_check()
          if $Features{"SpamAssassin"};

      # The SpamAssassin results are not sent here, so the verdict stays
      # independent: a model that sees them tends to follow them and
      # amplify their false positives.  Uncomment SAScore/SARules to send
      # them anyway (or pass RspamdScore/RspamdSymbols from rspamd_check()).
      my $verdict = ml_classify(ml_build_state(
          Entity   => $entity,     # headers, subject and body
          MailFrom => $Sender,
          SPF      => $SPFResult,
          DKIM     => $DKIMResult,
          DMARC    => $DMARCResult,
          # SAScore => $hits,
          # SARules => $names,
      ));

      if ($verdict->{error}) {
          md_syslog('info', "ml: no verdict ($verdict->{error}), "
                           . "falling back to SpamAssassin only");
          return;
      }

      my $phishing = $verdict->{is_phishing}{answer}
                  && $verdict->{is_phishing}{confidence} >= 0.90;
      my $spam     = $verdict->{is_spam}{answer}
                  && $verdict->{is_spam}{confidence} >= 0.80;

      if ($phishing) {
          md_syslog('info', sprintf('ml(%s): phishing, confidence %.2f',
              $verdict->{backend}, $verdict->{is_phishing}{confidence}));
          action_quarantine_entire_message("Suspected phishing");
      } elsif ($spam) {
          action_change_header('Subject', "[SPAM] $Subject");
      }

      # Per question: a signed score (positive leans yes, negative leans
      # no, 0.00 for no opinion) and yes/no/unsure.
      my %acted = (is_spam => $spam, is_phishing => $phishing);
      foreach my $q (['is_spam', 'Spam'], ['is_phishing', 'Phishing']) {
          my ($key, $name) = @$q;
          next unless grep { $_ eq $key } @{ $verdict->{questions} };
          my $answer = $verdict->{$key}{answer};
          my $sign = !defined $answer ? 0 : $answer ? 1 : -1;
          action_change_header("X-MIMEDefang-ML-$name-Score",
              sprintf('%.2f', $sign * $verdict->{$key}{confidence}));
          action_change_header("X-MIMEDefang-ML-$name-Answer",
              $acted{$key} ? 'yes' : $sign < 0 ? 'no' : 'unsure');
      }
      action_change_header('X-MIMEDefang-ML-Backend', $verdict->{backend});
  }

To use the model only against phishing, ask just that question; the
C<is_spam> answer is then always C<undef>:

  $Mail::MIMEDefang::ML::Config{questions} = ['is_phishing'];

or, for one call only:

  my $verdict = ml_classify($state, questions => ['is_phishing']);

Change the confidence thresholds, the actions (C<action_quarantine_entire_message>,
C<action_change_header>, C<action_bounce>, C<action_discard>, ...) and where in
the filter this runs to match your site's policy.  Phishing uses a higher
threshold than spam because legitimate bulk marketing mail (tracking links,
redirects) can look like phishing to a model.

=head1 TRAINING A MODEL

The stock models are zero-shot: they classify mail they were never
trained on, from the label texts or the questions alone.  Out of the box
their accuracy is modest and varies a lot from site to site, especially
on mail that is not in English; do not act on their verdicts before
checking them against your own mail.  To get good results, train the
model on a corpus of your own ham and spam (a few hundred labelled
messages at least, ideally thousands), and retrain it as your mail
changes.

=over 4

=item C<gliclass>

F<contrib/ml-benchmark/gliclass-train> fine-tunes a GLiClass model on a
directory of ham and one of spam (and, optionally, one of phishing with
C<--phishing-dir>), using the exact text and labels this module sends.
It reports false positives and false negatives on a held-out part of the
corpus before and after training.  Serve the result with
C<mimedefang-gliclass-server --model DIR>, with the labels it was trained
on (see L<Mail::MIMEDefang::ML::GLiClass>).  Training needs a GPU in
practice.

=item C<laya>

The C<laya> Python package contains no training code; a Laya model
trained with the Laya project's own tools can be served with
C<mimedefang-laya-server --checkpoint>.

=item C<openai>

Fine-tuning a generative model (LoRA training with tools such as Unsloth
or LLaMA-Factory, then importing the result into Ollama) is outside the
scope of MIMEDefang.

=back

F<contrib/ml-benchmark/ml-benchmark> measures the false positive and
false negative rates of every backend on a directory of ham and one of
spam: use it before and after training, and to choose the confidence
thresholds used in the filter.  See "Training a model" in
F<script/ml-servers/README.md> for details.

=head1 SECURITY

The model servers (C<mimedefang-laya-server>, C<mimedefang-gliclass-server>,
Ollama, llama.cpp, vLLM, ...) have no authentication of their own, and every
request carries message content.  Run them on the MIMEDefang host or on a
trusted network, and keep them secure by limiting access with a firewall so
that only the MIMEDefang host(s) can reach their ports.  Never expose them
to the Internet.  Any host name or IP address can be configured as a
backend URL; this module does not restrict where requests go.

=head1 FUNCTIONS

=over 4

=cut

use strict;
use warnings;

use Exporter qw(import);
our @EXPORT_OK = qw(
    ml_build_state
    ml_classify
);
our @EXPORT = @EXPORT_OK;

use LWP::UserAgent ();
use HTTP::Request  ();
use JSON::PP        qw(encode_json decode_json);
use Encode          ();

use Mail::MIMEDefang qw(md_syslog);
use Mail::MIMEDefang::Utils qw(md_get_plain_text_body);

our %Config = (
    enabled            => 1,
    backend            => 'laya',
    timeout            => 30,
    connect_retries    => 1,

    # Body kept when the state is handed to a backend: the first
    # body_head_chars plus the last body_tail_chars characters.  These are
    # the defaults, each backend's section may override them.  Laya's
    # English checkpoint has a 512-token context (1024 for
    # laya-typed-decisions); keep well under that.
    body_head_chars    => 1500,
    body_tail_chars    => 500,
    spam_top_rules     => 8,

    # URLs in the body longer than this are cut (the host is always kept),
    # so tracking links don't eat the body budget.
    url_max_chars      => 80,
    # Link domains and attachments listed in the signals, see
    # ml_build_state().
    max_link_domains   => 10,
    max_attachments    => 5,

    # Headers read from the entity passed to ml_build_state(), in the order
    # they are shown to the model.  From, Reply-To and Subject have their
    # own state fields and are always read.  Upstream X-Spam-* and
    # Authentication-Results headers are deliberately left out: they can be
    # forged by the sender, and would make the verdict follow earlier
    # filters instead of being independent.
    headers            => [qw(To Cc Date Message-ID Return-Path Sender
                              List-Id List-Unsubscribe Precedence
                              X-Mailer User-Agent)],
    header_max_chars   => 200,

    # Verdicts below this confidence are treated as "no opinion".
    min_confidence     => 0.55,

    # Questions asked (keys of %QUESTIONS).
    questions          => [qw(is_spam is_phishing)],
    # Question wording overrides (key of %QUESTIONS -> text), see
    # question_text().
    question_texts     => {},

    laya => {
        server_url   => 'http://127.0.0.1:8687',
        predict_path => '/predict',
        # Laya picks its checkpoint by the language of the whole state,
        # and the English signal lines make it misjudge non-English mail.
        send_signals => 0,
    },
    gliclass => {
        server_url   => 'http://127.0.0.1:8688',
        predict_path => '/predict',
        # About 2500 tokens with the headers; ModernBERT reads up to 8k,
        # see the server's --max-length.
        body_head_chars => 6000,
        body_tail_chars => 1500,
    },
    openai => {
        base_url     => 'http://127.0.0.1:11434/v1',
        model        => undef,    # required, e.g. 'qwen3:8b' (>= 7-8B parameters)
        max_tokens   => 100,
        body_head_chars => 6000,
        body_tail_chars => 1500,
    },
);

# Backend name -> module suffix.
my %BACKENDS = (
    laya     => 'Laya',
    gliclass => 'GLiClass',
    openai   => 'OpenAI',
);

# The questions every backend answers, phrased for the ones that take
# free-text instructions (Laya, chat LLMs): the question, what counts,
# then what doesn't.  Keep them short, Laya reads 512 tokens in all.
our %QUESTIONS = (
    is_spam     => 'Is this email spam?  Spam is mail the recipient did not ask for, '
                 . 'from a sender they have no relationship with: scams and fraud '
                 . '(advance-fee, fake prizes, fake invoices or orders), malware, and '
                 . 'bulk or cold commercial pitches (sales, services, SEO, loans, '
                 . 'pills, dating, crypto).  Not spam: personal or business '
                 . 'correspondence and replies, receipts and account or delivery '
                 . 'notices from services the recipient uses, and newsletters, '
                 . 'mailing lists or marketing from organisations they deal with.',
    is_phishing => 'Is this email phishing?  Phishing pretends to come from a bank, '
                 . 'company, courier, service, colleague or executive the recipient '
                 . 'trusts, to trick them into entering a password, paying or wiring '
                 . 'money, giving out payment or personal details, or opening a '
                 . 'malicious link or attachment (fake account, mailbox or delivery '
                 . 'alerts, fake invoices or bank detail changes, urgent requests '
                 . 'from a "boss").  Not phishing: genuine notices from the real '
                 . 'service, and spam that sells something without pretending to be '
                 . 'someone else.',
);

my $_ua;

# Backend package -> error from loading it at startup (see the end of
# this file), and whether that error has been logged yet.
my (%LOAD_ERROR, %LOAD_LOGGED);

sub _ua {
    return $_ua if $_ua;
    $_ua = LWP::UserAgent->new(
        timeout    => $Config{timeout},
        agent      => 'mimedefang-ml/1.0',
        keep_alive => 4,
    );
    return $_ua;
}

=item ml_build_state(%args)

Assembles the truncated, structured state hash the backends are given.
Callers supply already-decoded/HTML-stripped text; this function does not
touch MIME parsing or auth-result computation.

Pass the message as C<Entity> (the C<MIME::Entity> given to C<filter_end>)
and the state is filled from it: C<From>, C<ReplyTo> and C<Subject> from
their headers, C<Body> from C<md_get_plain_text_body>, plus the headers
listed in C<$Config{headers}> (decoded, unfolded and capped at
C<header_max_chars> each) under C<headers>.
Arguments passed explicitly override the values read from the entity.

The text is normalized for the models: HTML entities are decoded,
invisible (zero-width, bidi-control, soft-hyphen) characters removed,
blanks and separator lines collapsed and URLs longer than
C<url_max_chars> cut.  The whole body is kept in the state (up to 64k
characters); each backend cuts it to its own C<body_head_chars> and
C<body_tail_chars> when it sends it.

C<signals> summarizes, as short lines of text, the domains the body
links to (up to C<max_link_domains>, with the number of links to each)
and the names and types of the attachments (up to C<max_attachments>).
Everything else about the message (authentication, sender reputation,
header anomalies, ...) is left to SpamAssassin, whose results can be
passed in as C<SAScore>/C<SARules>.

Args: C<Entity>, C<From>, C<ReplyTo>, C<Subject>, C<Body>, C<MailFrom> (the
envelope sender, C<$Sender>), C<SPF>, C<DKIM>, C<DMARC>.

Optional spam-filter results: C<SAScore>, C<SARules>, C<RspamdScore>,
C<RspamdSymbols>.  Rules/symbols may be an arrayref or the comma- or
space-separated string returned by C<spam_assassin_check> /
C<rspamd_check>, and are capped at C<spam_top_rules> entries each.  They
are put in the state, and so sent to the model, whenever they are passed
(rules only together with their score); whether to pass them is up to the
caller.  Leaving them out keeps the model's verdict independent of
SpamAssassin/Rspamd, since a model that sees them tends to follow them and
amplify their false positives; passing them can help a model that would
otherwise lack context, at the cost of repeating their mistakes.

=cut

sub ml_build_state {
    my (%args) = @_;

    my (%headers, @attachments);
    if (my $entity = $args{Entity}) {
        my $head = $entity->head;
        my %seen;
        for my $name ('From', 'Reply-To', 'Subject', @{ $Config{headers} || [] }) {
            next if $seen{lc $name}++;
            my @values = map { _header_text($_) } $head->get_all($name);
            @values = grep { length } @values;
            next unless @values;
            my $value = join(', ', @values);
            $value = substr($value, 0, $Config{header_max_chars}) . '...'
                if length($value) > $Config{header_max_chars};
            $headers{$name} = $value;
        }
        $args{From}    //= delete $headers{From};
        $args{ReplyTo} //= delete $headers{'Reply-To'};
        $args{Subject} //= delete $headers{Subject};
        delete @headers{qw(From Reply-To Subject)};
        $args{Body}    //= md_get_plain_text_body($entity);

        @attachments = _attachments($entity);
    }

    my $body = _normalize_text($args{Body} // '');
    my %links = _link_domains($body);
    $body = _shorten_urls($body);
    # md_get_plain_text_body() already caps what it returns at 64k.
    $body = substr($body, 0, 65536) if length($body) > 65536;

    my %state = (
        from         => $args{From}    // '',
        reply_to     => $args{ReplyTo} // '',
        mail_from    => $args{MailFrom} // '',
        subject      => $args{Subject} // '',
        body         => $body,
        spf          => $args{SPF}   // 'unknown',
        dkim         => $args{DKIM}  // 'unknown',
        dmarc        => $args{DMARC} // 'unknown',
    );
    $state{$_} = _normalize_text($state{$_}) for qw(from reply_to subject);

    for my $f (['sa', 'SAScore', 'SARules'], ['rspamd', 'RspamdScore', 'RspamdSymbols']) {
        my ($prefix, $score, $rules) = @$f;
        next unless defined $args{$score};
        $state{"${prefix}_score"} = $args{$score} + 0;
        $state{"${prefix}_rules"} = _rule_list($args{$rules});
    }

    $state{headers} = \%headers if %headers;

    my @signals = _signals(\%links, \@attachments);
    $state{signals} = \@signals if @signals;

    return \%state;
}

# Zero-width, joiner, bidi-control and soft-hyphen characters: invisible
# when rendered, used to break up words so that filters don't match them.
my $INVISIBLE = qr/[\x{00AD}\x{034F}\x{061C}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180E}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{206A}-\x{206F}\x{3164}\x{FEFF}\x{FFA0}]/;

my $HAVE_ENTITIES = eval { require HTML::Entities; 1 };

# Used when HTML::Entities is not installed.
my %ENTITY = (amp => '&', lt => '<', gt => '>', quot => '"', apos => "'",
              nbsp => ' ', zwnj => "\x{200C}", zwj => "\x{200D}", shy => "\x{00AD}");

# Text as a model should read it: HTML entities decoded, invisible
# characters removed, runs of blanks and blank lines collapsed.
sub _normalize_text {
    my ($text) = @_;
    return '' unless defined $text && length $text;

    if ($HAVE_ENTITIES) {
        HTML::Entities::decode_entities($text);
    } else {
        $text =~ s{&(?:#[xX]([0-9a-fA-F]{1,6})|#([0-9]{1,7})|([a-zA-Z]+));}{
            defined $1 ? _chr(hex $1) : defined $2 ? _chr($2) : ($ENTITY{$3} // "&$3;")
        }ge;
    }

    $text =~ s/$INVISIBLE+//g;

    $text =~ s/\r\n?/\n/g;
    # Separator lines (HTML::FormatText draws <hr> as a 9999-wide rule).
    $text =~ s/([\-=_*~#.+])\1{9,}/$1 x 10/ge;
    $text =~ s/(?:[^\S\n]|\x{A0})+/ /g;
    $text =~ s/ ?\n ?/\n/g;
    $text =~ s/\n{3,}/\n\n/g;
    $text =~ s/^\s+|\s+$//g;
    return $text;
}

sub _chr {
    my ($cp) = @_;
    return ($cp > 0 && $cp <= 0x10FFFF && ($cp < 0xD800 || $cp > 0xDFFF)) ? chr($cp) : '';
}

# A raw header value as readable text: RFC 2047 decoded, unfolded,
# invisible characters removed, trimmed.
sub _header_text {
    my ($value) = @_;
    return '' unless defined $value;
    my $text = eval { Encode::decode('MIME-Header', $value) } // $value;
    $text =~ s/$INVISIBLE+//g;
    $text =~ s/\s+/ /g;
    $text =~ s/^ | $//g;
    return $text;
}

my $URL = qr{\bhttps?://[^\s<>"'`{}|\\^\[\]]+}i;

# Registered domain -> number of links to it.
sub _link_domains {
    my ($text) = @_;
    my %count;
    while ($text =~ /($URL)/g) {
        my ($host) = $1 =~ m{^https?://(?:[^/\@?#]*\@)?([^/:?#]+)}i;
        next unless defined $host;
        $host = lc $host;
        $host =~ s/\.+$//;
        $count{ _org_domain($host) }++ if length $host;
    }
    return %count;
}

sub _shorten_urls {
    my ($text) = @_;
    my $max = $Config{url_max_chars};
    return $text unless $max;
    $text =~ s{($URL)}{
        my $url = $1;
        if (length($url) > $max) {
            my ($site) = $url =~ m{^(https?://[^/?#]+)}i;
            $url = length($site) >= $max ? "$site/..." : substr($url, 0, $max) . '...';
        }
        $url
    }ge;
    return $text;
}

# Registered domain, approximately: the last two labels, or three under a
# two-letter country code with a generic second level (example.co.uk).
sub _org_domain {
    my ($domain) = @_;
    return '' unless defined $domain && length $domain;
    my @labels = split(/\./, lc $domain);
    my $n = (@labels >= 3 && $labels[-1] =~ /^[a-z]{2}$/
             && $labels[-2] =~ /^(?:co|com|net|org|gov|edu|ac|ne|or|go|gob|gv)$/) ? 3 : 2;
    return join('.', @labels > $n ? @labels[-$n .. -1] : @labels);
}

# "name (type)" of the parts sent as attachments or carrying a file name.
sub _attachments {
    my ($entity) = @_;
    my @found;
    my @todo = ($entity);
    while (my $part = shift @todo) {
        if ($part->is_multipart) {
            push @todo, $part->parts;
            next;
        }
        my $head = $part->head;
        my $name = $head->recommended_filename;
        my $disposition = lc($head->mime_attr('content-disposition') || '');
        next unless defined $name || $disposition eq 'attachment';
        $name = defined $name ? _header_text($name) : '(no name)';
        push @found, "$name (" . lc($head->mime_type || 'unknown') . ')';
    }
    return @found;
}

# The domains the body links to and the attachments, as short lines of
# text.
sub _signals {
    my ($links, $attachments) = @_;
    my @signals;

    if (%$links) {
        my @hosts = sort { $links->{$b} <=> $links->{$a} || $a cmp $b } keys %$links;
        my $max = $Config{max_link_domains} || 5;
        my $more = @hosts > $max ? @hosts - $max : 0;
        splice(@hosts, $max) if $more;
        push @signals, 'Link domains: ' . join(', ', map { "$_ ($links->{$_})" } @hosts)
                     . ($more ? ", and $more more" : '');
    }

    if (@$attachments) {
        my $max = $Config{max_attachments} || 5;
        my @list = @$attachments > $max ? (@$attachments[0 .. $max - 1], '...') : @$attachments;
        push @signals, 'Attachments: ' . join(', ', @list);
    }

    return @signals;
}

# Rules as an arrayref or a comma/space-separated string -> capped arrayref.
sub _rule_list {
    my ($rules) = @_;
    my @rules = ref($rules) eq 'ARRAY' ? @$rules
              : defined $rules         ? split(/[\s,]+/, $rules)
              :                          ();
    @rules = grep { defined && length } @rules;
    splice(@rules, $Config{spam_top_rules}) if @rules > $Config{spam_top_rules};
    return \@rules;
}

=item ml_classify($state, %opts)

Hands the state to the configured backend and returns a verdict hashref.
C<%opts> may hold C<questions>, overriding C<$Config{questions}> for this
call, e.g. C<questions =E<gt> ['is_phishing']>.  Questions not asked are
returned with C<answer> set to C<undef> and C<confidence> 0, as for no
opinion; C<questions> in the verdict lists the ones that were asked.
Returns C<{ error => $reason }> on any failure, callers should treat that
the same as "no opinion" and fall back to SA/rspamd-only handling.

Answers whose confidence is below C<min_confidence> are returned with
C<answer> set to C<undef>, whichever backend produced them.

When the backend reports its raw scores (see L</BACKEND API>), they are
copied to C<scores>, for diagnostics; don't base filtering decisions on
them, their meaning is backend specific.

=cut

sub ml_classify {
    my ($state, %opts) = @_;

    return { error => 'disabled' } unless $Config{enabled};
    return { error => 'no state' } unless $state && ref($state) eq 'HASH';

    my $asked = exists $opts{questions} ? $opts{questions} : $Config{questions};
    my @questions = active_questions({ questions => $asked });
    return { error => 'no questions' } unless @questions;
    my %cfg = (%Config, questions => \@questions);

    my $name = lc($Config{backend} // '');
    my $mod  = $BACKENDS{$name};
    return { error => "unknown backend '$name'" } unless $mod;

    my $pkg = "Mail::MIMEDefang::ML::$mod";
    if ($LOAD_ERROR{$pkg}) {
        md_syslog('err', "ml: cannot load $pkg: $LOAD_ERROR{$pkg}")
            unless $LOAD_LOGGED{$pkg}++;
        return { error => "cannot load backend '$name'" };
    }

    my $raw = eval { $pkg->can('classify')->($state, \%cfg) };
    if ($@ || !$raw || ref($raw) ne 'HASH') {
        md_syslog('info', "ml: $name backend failed: " . ($@ || 'no result'));
        return { error => 'backend failure' };
    }
    return { error => $raw->{error}, backend => $name } if $raw->{error};

    my %verdict = (backend => $name, questions => [@questions]);
    my %ask = map { $_ => 1 } @questions;
    for my $key (keys %QUESTIONS) {
        my $a = $ask{$key} ? $raw->{$key} : undef;
        if (!$a || !defined $a->{answer} || !defined $a->{confidence}) {
            $verdict{$key} = { answer => undef, confidence => 0 };
            next;
        }
        my $conf = _clamp($a->{confidence});
        $verdict{$key} = {
            answer     => ($conf < $Config{min_confidence} ? undef : ($a->{answer} ? 1 : 0)),
            confidence => $conf,
        };
    }
    # Raw backend scores, for diagnostics only.
    $verdict{scores} = { %{ $raw->{scores} } } if ref($raw->{scores}) eq 'HASH';
    return \%verdict;
}

=back

=head1 BACKEND API

A backend is a module C<Mail::MIMEDefang::ML::E<lt>NameE<gt>> with a
C<classify($state, \%Config)> function returning either C<{ error =E<gt> $reason }>
or C<{ is_spam =E<gt> { answer =E<gt> 0|1, confidence =E<gt> 0..1 }, is_phishing =E<gt> {...} }>.
Confidence gating is done here, not in the backend.  A backend may also
return C<scores =E<gt> { name =E<gt> number, ... }> with its raw scores,
passed on as they are for diagnostics.  Backends may use the
helpers C<http_post_json($url, $payload, \%headers)>,
C<state_body($state, \%backend_cfg)> (the body cut to the backend's
C<body_head_chars>/C<body_tail_chars>),
C<state_to_text($state, \%backend_cfg)> (the state as text, with the
signals and that body), C<active_questions(\%Config)> (the questions to
answer, in order) and C<question_text(\%Config, $question, \%backend_cfg)>
(the question's text, see C<question_texts>) from this package.  A backend asks the model only the
questions C<active_questions> returns; answers to other questions are
ignored.

=cut

sub _clamp {
    my ($v) = @_;
    $v += 0;
    return 0 if $v < 0;
    return 1 if $v > 1;
    return $v;
}

# The questions to ask: $cfg->{questions} (a list, or one name) cut to
# the known ones, in order and without duplicates.  Undefined -> all of
# them; a list of unknown names only -> none.
sub active_questions {
    my ($cfg) = @_;
    my $q = $cfg ? $cfg->{questions} : undef;
    unless (defined $q) {
        my @all = sort keys %QUESTIONS;
        return @all;
    }
    my %seen;
    return grep { defined && exists $QUESTIONS{$_} && !$seen{$_}++ }
           (ref($q) eq 'ARRAY' ? @$q : split(/[\s,]+/, $q));
}

# A question's text: the backend's question_texts, else the global
# ones, else the default in %QUESTIONS.
sub question_text {
    my ($cfg, $key, $bcfg) = @_;
    for my $texts (($bcfg || {})->{question_texts}, ($cfg || {})->{question_texts}) {
        next unless ref($texts) eq 'HASH';
        my $t = $texts->{$key};
        return $t if defined $t && !ref($t) && length $t;
    }
    return $QUESTIONS{$key};
}

# The state's body cut to the backend's budget: its own body_head_chars /
# body_tail_chars if set in \%backend_cfg, else the global ones.
sub state_body {
    my ($state, $bcfg) = @_;
    $bcfg ||= {};
    my $head = $bcfg->{body_head_chars} // $Config{body_head_chars};
    my $tail = $bcfg->{body_tail_chars} // $Config{body_tail_chars};

    my $body = $state->{body} // '';
    return $body if length($body) <= $head + $tail;
    return substr($body, 0, $head) . "\n[...truncated...]\n"
         . ($tail ? substr($body, -$tail) : '');
}

# Render the state as plain text for backends that take a single string,
# with the body cut to the budget in \%backend_cfg (see state_body()).
sub state_to_text {
    my ($state, $bcfg) = @_;

    my @lines = (
        "From: $state->{from}",
        (length $state->{reply_to} ? "Reply-To: $state->{reply_to}" : ()),
        (length($state->{mail_from} // '') ? "Envelope-From: $state->{mail_from}" : ()),
        "Subject: $state->{subject}",
        "SPF: $state->{spf}",
        "DKIM: $state->{dkim}",
        "DMARC: $state->{dmarc}",
    );
    my $headers = $state->{headers} || {};
    my %order;
    @order{ @{ $Config{headers} || [] } } = (0 .. $#{ $Config{headers} || [] });
    for my $name (sort { ($order{$a} // 1e9) <=> ($order{$b} // 1e9) || $a cmp $b } keys %$headers) {
        push @lines, "$name: $headers->{$name}";
    }
    for my $f (['sa', 'SpamAssassin'], ['rspamd', 'Rspamd']) {
        my ($prefix, $name) = @$f;
        next unless defined $state->{"${prefix}_score"};
        push @lines, "$name score: " . $state->{"${prefix}_score"};
        my $rules = $state->{"${prefix}_rules"} || [];
        push @lines, "$name rules: " . join(', ', @$rules) if @$rules;
    }
    my @signals = @{ $state->{signals} || [] };
    push @lines, 'Signals computed by the mail filter:', map { "- $_" } @signals
        if @signals;
    return join("\n", @lines) . "\n\n" . state_body($state, $bcfg);
}

# LWP reports errors of its own as a 500 response with this header.
sub _connect_failed {
    my ($resp) = @_;
    return 0 unless $resp && !$resp->is_success
        && ($resp->header('Client-Warning') // '') eq 'Internal response';
    my $msg = $resp->message // '';
    return $msg =~ /^Can't connect/ && $msg !~ /time(?:d )?out/i ? 1 : 0;
}

sub http_post_json {
    my ($url, $payload, $headers) = @_;


    my $req = HTTP::Request->new(POST => $url);
    $req->header('Content-Type' => 'application/json');
    $req->header($_ => $headers->{$_}) for keys %{ $headers || {} };
    $req->content(encode_json($payload));

    # Retry only when the server could not be reached at all (e.g. while
    # it restarts).  A server that took the request and timed out or
    # failed is busy or broken: sending the message again would only
    # double the wait and its load.
    my $tries = 1 + $Config{connect_retries};
    my $resp;
    while ($tries-- > 0) {
        $resp = _ua()->request($req);
        last unless _connect_failed($resp);
    }

    unless ($resp && $resp->is_success) {
        my $reason = $resp ? $resp->status_line : 'no response';
        # Servers explain errors in the body, e.g. Ollama's 404 is
        # {"error":{"message":"model \"x\" not found, try pulling it first"}}.
        if ($resp && (my $content = $resp->decoded_content)) {
            my $err = eval { decode_json($content) };
            $err = $err->{error} if ref($err) eq 'HASH';
            $err = $err->{message} // $err->{detail} if ref($err) eq 'HASH';
            $reason .= ": $err" if defined $err && !ref($err) && length $err;
        }
        md_syslog('info', "ml: request to $url failed: $reason");
        return { error => $reason };
    }

    my $data = eval { decode_json($resp->decoded_content) };
    if ($@ || !$data || ref($data) ne 'HASH') {
        md_syslog('info', "ml: malformed JSON from $url: $@");
        return { error => 'bad json' };
    }
    return $data;
}

# Load every backend now, while the filter is being loaded: mimedefang.pl
# and mimedefang-test-mail chdir() into the per-message work directory
# before filter_end runs, which breaks relative @INC entries
# (e.g. perl -I modules/lib) for anything required later.
for my $mod (values %BACKENDS) {
    my $pkg = "Mail::MIMEDefang::ML::$mod";
    $LOAD_ERROR{$pkg} = $@ unless eval "require $pkg; 1";  ## no critic (ProhibitStringyEval)
}

1;

__END__

=head1 SEE ALSO

L<Mail::MIMEDefang::ML::Laya>, L<Mail::MIMEDefang::ML::GLiClass>,
L<Mail::MIMEDefang::ML::OpenAI>, C<mimedefang-laya-server>,
C<mimedefang-gliclass-server>, F<script/ml-servers/README.md> in the MIMEDefang
sources.

=cut
