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
LM Studio.

=back

This module never blocks mail flow on a backend's availability: any failure
to reach the backend, or a low-confidence verdict, is treated as "no
opinion" so callers can fall back to their existing SpamAssassin/rspamd-only
path.

Backends are self-hosted model servers; see L</SECURITY> for how to keep
them safe.  C<mimedefang-laya-server> and C<mimedefang-gliclass-server>,
with instructions for installing their Python modules and models, are in
the F<script/ml-servers/> directory of the MIMEDefang sources.

The body truncation limits below apply to every backend.

=head1 CONFIGURATION

Site admins override C<%Mail::MIMEDefang::ML::Config> from
F<mimedefang-filter>.  The keys, with their defaults:

  # Common settings
  $Mail::MIMEDefang::ML::Config{enabled}         = 1;       # 0 turns ml_classify() into a no-op
  $Mail::MIMEDefang::ML::Config{backend}         = 'laya';  # 'laya', 'gliclass' or 'openai'
  $Mail::MIMEDefang::ML::Config{timeout}         = 10;      # seconds per HTTP request
  $Mail::MIMEDefang::ML::Config{connect_retries} = 1;
  $Mail::MIMEDefang::ML::Config{min_confidence}  = 0.55;    # below this -> no opinion

  # What ml_build_state() puts in the state
  $Mail::MIMEDefang::ML::Config{body_head_chars} = 1500;    # body kept: first N chars ...
  $Mail::MIMEDefang::ML::Config{body_tail_chars} = 500;     # ... plus last N chars
  $Mail::MIMEDefang::ML::Config{spam_top_rules}  = 8;       # rules kept per engine

  # Laya (mimedefang-laya-server)
  $Mail::MIMEDefang::ML::Config{laya}{server_url}     = 'http://127.0.0.1:8687';

  # GLiClass (mimedefang-gliclass-server)
  $Mail::MIMEDefang::ML::Config{gliclass}{server_url} = 'http://127.0.0.1:8688';
  $Mail::MIMEDefang::ML::Config{gliclass}{labels}{is_spam}
      = 'spam, unsolicited bulk mail, advertising or scam';
  $Mail::MIMEDefang::ML::Config{gliclass}{labels}{is_phishing}
      = 'phishing, impersonation to steal credentials or payment details';

  # Self-hosted generative model (Ollama, llama.cpp, vLLM, LM Studio)
  $Mail::MIMEDefang::ML::Config{openai}{base_url}     = 'http://127.0.0.1:11434/v1';
  $Mail::MIMEDefang::ML::Config{openai}{model}        = undef;   # required, e.g. 'qwen3:1.7b'
  $Mail::MIMEDefang::ML::Config{openai}{max_tokens}   = 100;

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
  use MIME::Words qw(decode_mimewords);

  $Mail::MIMEDefang::ML::Config{backend} = 'gliclass';

  sub filter_end {
      my ($entity) = @_;
      return if message_rejected();

      my ($hits, $req, $names, $report);
      ($hits, $req, $names, $report) = spam_assassin_check()
          if $Features{"SpamAssassin"};

      # $Subject may still be RFC 2047 encoded.
      my $subject = join('', map { $_->[0] // '' } decode_mimewords($Subject // ''));

      # The SpamAssassin results are not sent here, so the verdict stays
      # independent: a model that sees them tends to follow them and
      # amplify their false positives.  Uncomment SAScore/SARules to send
      # them anyway (or pass RspamdScore/RspamdSymbols from rspamd_check()).
      my $verdict = ml_classify(ml_build_state(
          From    => $Sender,
          Subject => $subject,
          Body    => md_get_plain_text_body($entity),
          SPF     => $SPFResult,
          DKIM    => $DKIMResult,
          DMARC   => $DMARCResult,
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

      # Signed score: positive leans spam, negative leans ham.
      if (defined $verdict->{is_spam}{answer}) {
          my $sign = $verdict->{is_spam}{answer} ? 1 : -1;
          action_change_header('X-MIMEDefang-ML-Score',
              sprintf('%.2f', $sign * $verdict->{is_spam}{confidence}));
      }
      action_change_header('X-MIMEDefang-ML-Backend', $verdict->{backend});
  }

Change the confidence thresholds, the actions (C<action_quarantine_entire_message>,
C<action_change_header>, C<action_bounce>, C<action_discard>, ...) and where in
the filter this runs to match your site's policy.  Phishing uses a higher
threshold than spam because legitimate bulk marketing mail (tracking links,
redirects) can look like phishing to a model.

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

use Mail::MIMEDefang qw(md_syslog);

our %Config = (
    enabled            => 1,
    backend            => 'laya',
    timeout            => 10,
    connect_retries    => 1,

    # State-building limits, Laya's English checkpoint has a 512-token
    # context (1024 for laya-typed-decisions); keep well under that.
    body_head_chars    => 1500,
    body_tail_chars    => 500,
    spam_top_rules     => 8,

    # Verdicts below this confidence are treated as "no opinion".
    min_confidence     => 0.55,

    laya => {
        server_url   => 'http://127.0.0.1:8687',
        predict_path => '/predict',
    },
    gliclass => {
        server_url   => 'http://127.0.0.1:8688',
        predict_path => '/predict',
        labels       => {
            is_spam     => 'spam, unsolicited bulk mail, advertising or scam',
            is_phishing => 'phishing, impersonation to steal credentials or payment details',
        },
    },
    openai => {
        base_url     => 'http://127.0.0.1:11434/v1',
        model        => undef,    # required, e.g. 'qwen3:1.7b'
        max_tokens   => 100,
    },
);

# Backend name -> module suffix.
my %BACKENDS = (
    laya     => 'Laya',
    gliclass => 'GLiClass',
    openai   => 'OpenAI',
);

# The questions every backend answers, phrased for the ones that take
# free-text instructions (Laya, chat LLMs).
our %QUESTIONS = (
    is_spam     => 'Is this email unsolicited bulk mail, advertising, or a scam?',
    is_phishing => 'Does this email attempt to impersonate a person, brand, or '
                 . 'service to steal credentials, payment details, or other '
                 . 'sensitive information?',
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

Required args: C<From>, C<Subject>, C<Body>.
Optional: C<SPF>, C<DKIM>, C<DMARC>, C<ReplyTo>.

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

    my $body = defined $args{Body} ? $args{Body} : '';
    if (length($body) > $Config{body_head_chars} + $Config{body_tail_chars}) {
        $body = substr($body, 0, $Config{body_head_chars})
              . "\n[...truncated...]\n"
              . substr($body, -$Config{body_tail_chars});
    }

    my %state = (
        from         => $args{From}    // '',
        reply_to     => $args{ReplyTo} // '',
        subject      => $args{Subject} // '',
        body         => $body,
        spf          => $args{SPF}   // 'unknown',
        dkim         => $args{DKIM}  // 'unknown',
        dmarc        => $args{DMARC} // 'unknown',
    );

    for my $f (['sa', 'SAScore', 'SARules'], ['rspamd', 'RspamdScore', 'RspamdSymbols']) {
        my ($prefix, $score, $rules) = @$f;
        next unless defined $args{$score};
        $state{"${prefix}_score"} = $args{$score} + 0;
        $state{"${prefix}_rules"} = _rule_list($args{$rules});
    }

    return \%state;
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

=item ml_classify($state)

Hands the state to the configured backend and returns a verdict hashref.
Returns C<{ error => $reason }> on any failure, callers should treat that
the same as "no opinion" and fall back to SA/rspamd-only handling.

Answers whose confidence is below C<min_confidence> are returned with
C<answer> set to C<undef>, whichever backend produced them.

=cut

sub ml_classify {
    my ($state) = @_;

    return { error => 'disabled' } unless $Config{enabled};
    return { error => 'no state' } unless $state && ref($state) eq 'HASH';

    my $name = lc($Config{backend} // '');
    my $mod  = $BACKENDS{$name};
    return { error => "unknown backend '$name'" } unless $mod;

    my $pkg = "Mail::MIMEDefang::ML::$mod";
    if ($LOAD_ERROR{$pkg}) {
        md_syslog('err', "ml: cannot load $pkg: $LOAD_ERROR{$pkg}")
            unless $LOAD_LOGGED{$pkg}++;
        return { error => "cannot load backend '$name'" };
    }

    my $raw = eval { $pkg->can('classify')->($state, \%Config) };
    if ($@ || !$raw || ref($raw) ne 'HASH') {
        md_syslog('info', "ml: $name backend failed: " . ($@ || 'no result'));
        return { error => 'backend failure' };
    }
    return { error => $raw->{error}, backend => $name } if $raw->{error};

    my %verdict = (backend => $name);
    for my $key (keys %QUESTIONS) {
        my $a = $raw->{$key};
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
    return \%verdict;
}

=back

=head1 BACKEND API

A backend is a module C<Mail::MIMEDefang::ML::E<lt>NameE<gt>> with a
C<classify($state, \%Config)> function returning either C<{ error =E<gt> $reason }>
or C<{ is_spam =E<gt> { answer =E<gt> 0|1, confidence =E<gt> 0..1 }, is_phishing =E<gt> {...} }>.
Confidence gating is done here, not in the backend.  Backends may use the
helpers C<http_post_json($url, $payload, \%headers)> and
C<state_to_text($state)> from this package.

=cut

sub _clamp {
    my ($v) = @_;
    $v += 0;
    return 0 if $v < 0;
    return 1 if $v > 1;
    return $v;
}

# Render the state as plain text for backends that take a single string.
sub state_to_text {
    my ($state) = @_;

    my @lines = (
        "From: $state->{from}",
        (length $state->{reply_to} ? "Reply-To: $state->{reply_to}" : ()),
        "Subject: $state->{subject}",
        "SPF: $state->{spf}",
        "DKIM: $state->{dkim}",
        "DMARC: $state->{dmarc}",
    );
    for my $f (['sa', 'SpamAssassin'], ['rspamd', 'Rspamd']) {
        my ($prefix, $name) = @$f;
        next unless defined $state->{"${prefix}_score"};
        push @lines, "$name score: " . $state->{"${prefix}_score"};
        my $rules = $state->{"${prefix}_rules"} || [];
        push @lines, "$name rules: " . join(', ', @$rules) if @$rules;
    }
    return join("\n", @lines) . "\n\n" . ($state->{body} // '');
}

sub http_post_json {
    my ($url, $payload, $headers) = @_;


    my $req = HTTP::Request->new(POST => $url);
    $req->header('Content-Type' => 'application/json');
    $req->header($_ => $headers->{$_}) for keys %{ $headers || {} };
    $req->content(encode_json($payload));

    my $tries = 1 + $Config{connect_retries};
    my $resp;
    while ($tries-- > 0) {
        $resp = _ua()->request($req);
        last if $resp->is_success;
    }

    unless ($resp && $resp->is_success) {
        my $reason = $resp ? $resp->status_line : 'no response';
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
