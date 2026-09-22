#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

package Mail::MIMEDefang::LLM::Laya;

=head1 NAME

Mail::MIMEDefang::LLM::Laya - ham/spam/phishing verdicts from a resident Laya
decision model.

=head1 SYNOPSIS

  use Mail::MIMEDefang::Laya;

  # In filter_begin / filter, once headers + SA report are known:
  my $state = laya_build_state(
      From        => $Sender,
      Subject     => $Subject,
      Body        => $body_text,           # already MIME/HTML-stripped
      SAScore     => $sa_score,
      SARules     => \@sa_rule_names,
      SPF         => $spf_result,
      DKIM        => $dkim_result,
      DMARC       => $dmarc_result,
  );

  my $verdict = laya_classify($state);
  # $verdict->{is_spam}{answer}      -> 1, 0, or undef (no opinion)
  # $verdict->{is_spam}{confidence}  -> 0.0 .. 1.0
  # $verdict->{is_phishing}{answer}
  # $verdict->{is_phishing}{confidence}
  # $verdict->{error}                -> set, and the rest absent, on failure

=head1 DESCRIPTION

Laya (L<https://github.com/NandhaKishorM/laya>) is a non-autoregressive
encoder-based decision model: one forward pass returns typed, calibrated
answers instead of generated text, which avoids both the latency and the
parsing/hallucination risk of an autoregressive LLM for a simple ham/spam/
phishing verdict.

Because Laya is a Python library, this module talks to a small resident
Python inference server (see C<mimedefang-laya-server>).

This module never blocks mail flow on Laya's availability: any failure to
reach the server, or a low-confidence verdict, is treated as "no opinion"
so callers can fall back to their existing SpamAssassin/rspamd-only path.

=head1 INTEGRATION EXAMPLE

A typical C<filter> in F<mimedefang-filter.pl>, called after SpamAssassin
has already scored the message and its plain-text/HTML-stripped body is
available. This only acts on confident verdicts and otherwise leaves the
message to whatever SA-based handling already exists, Laya is additive,
not a replacement for the existing spam path.

  use Mail::MIMEDefang::LLM::Laya;

  sub filter {
      my ($entity, $fname, $ext, $type) = @_;

      # ... existing MIME/attachment checks ...

      return unless $type eq 'multipart-once';  # run this part once per message

      my $state = laya_build_state(
          From    => $Sender,
          Subject => $Subject,
          Body    => md_get_plain_text_body($entity),
          SAScore => $SAScore,                   # from your existing SA integration
          SARules => [ split ' ', $SARuleNames ],
          SPF     => $SPFResult,
          DKIM    => $DKIMResult,
          DMARC   => $DMARCResult,
      );

      my $verdict = laya_classify($state);

      if ($verdict->{error}) {
          md_syslog('info', "laya: no verdict ($verdict->{error}), "
                           . "falling back to SpamAssassin only");
          return;
      }

      if ($verdict->{is_phishing}{answer} && $verdict->{is_phishing}{confidence} >= 0.80) {
          md_syslog('info', sprintf(
              'laya: phishing, confidence %.2f -- quarantining',
              $verdict->{is_phishing}{confidence}));
          action_quarantine_entire_message("Suspected phishing (Laya)");
          return;
      }

      if ($verdict->{is_spam}{answer} && $verdict->{is_spam}{confidence} >= 0.80) {
          md_syslog('info', sprintf(
              'laya: spam, confidence %.2f -- tagging subject',
              $verdict->{is_spam}{confidence}));
          action_change_header('Subject', "[SPAM] $Subject");
      }

      # $verdict->{is_spam}{answer} == 0, or confidence below threshold:
      # no action, let SpamAssassin's own scoring make the call.

      # Expose Laya's opinion as a signed header: positive leans spam,
      # negative leans ham.
      if (defined $verdict->{is_spam}{answer}) {
          my $sign  = $verdict->{is_spam}{answer} ? 1 : -1;
          my $score = $sign * $verdict->{is_spam}{confidence};
          action_change_header('X-MIMEDefang-Laya-Score', sprintf('%.2f', $score));
      }
  }

Adjust the confidence thresholds, the actions taken (C<action_quarantine_entire_message>,
C<action_change_header>, C<action_bounce>, C<action_drop_message>, etc. are all
standard MIMEDefang actions), and where in your existing filter this runs, to
match your site's policy.

=cut

use strict;
use warnings;

use Exporter qw(import);
our @EXPORT_OK = qw(
    laya_build_state
    laya_classify
);
our @EXPORT = @EXPORT_OK;

use LWP::UserAgent ();
use HTTP::Request  ();
use JSON::PP        qw(encode_json decode_json);

use Mail::MIMEDefang qw(md_syslog);

# Site admins override these from mimedefang-filter.pl, e.g.:
#   $Mail::MIMEDefang::LLM::Laya::Config{enabled} = 1;
our %Config = (
    enabled            => 1,
    server_url         => 'http://127.0.0.1:8687',
    predict_path       => '/predict',
    health_path        => '/health',
    timeout            => 10,
    connect_retries    => 1,

    # State-building limits, Laya's English checkpoint has a 512-token
    # context (1024 for laya-typed-decisions); keep well under that.
    body_head_chars    => 1500,
    body_tail_chars    => 500,
    sa_top_rules       => 8,

    # Verdicts below this confidence are treated as "no opinion".
    min_confidence     => 0.55,
);

my $_ua;

sub _ua {
    return $_ua if $_ua;
    $_ua = LWP::UserAgent->new(
        timeout    => $Config{timeout},
        agent      => 'mimedefang-laya/1.0',
        keep_alive => 4,
    );
    return $_ua;
}

=head2 laya_build_state(%args)

Assembles the truncated, structured state hash Laya is given. Callers
supply already-decoded/HTML-stripped text; this function does not touch
MIME parsing or auth-result computation, matching the rest of the LLM
filter's division of labour (the caller does protocol work, this module
does classification).

Required args: C<From>, C<Subject>, C<Body>, C<SAScore>.
Optional: C<SARules> (arrayref), C<SPF>, C<DKIM>, C<DMARC>, C<ReplyTo>.

=cut

sub laya_build_state {
    my (%args) = @_;

    my $body = defined $args{Body} ? $args{Body} : '';
    if (length($body) > $Config{body_head_chars} + $Config{body_tail_chars}) {
        $body = substr($body, 0, $Config{body_head_chars})
              . "\n[...truncated...]\n"
              . substr($body, -$Config{body_tail_chars});
    }

    my @rules = $args{SARules} ? @{ $args{SARules} } : ();
    if (@rules > $Config{sa_top_rules}) {
        @rules = @rules[0 .. $Config{sa_top_rules} - 1];
    }

    return {
        from         => $args{From}    // '',
        reply_to     => $args{ReplyTo} // '',
        subject      => $args{Subject} // '',
        body         => $body,
        sa_score     => defined $args{SAScore} ? $args{SAScore} + 0 : undef,
        sa_rules     => \@rules,
        spf          => $args{SPF}   // 'unknown',
        dkim         => $args{DKIM}  // 'unknown',
        dmarc        => $args{DMARC} // 'unknown',
    };
}

=head2 laya_classify($state)

POSTs the state to the resident Laya server with fixed C<noul> (boolean)
questions for spam and phishing, and returns a verdict hashref. Returns
C<{ error => $reason }> on any failure, callers should treat that the
same as "no opinion" and fall back to SA/rspamd-only handling.

=cut

sub laya_classify {
    my ($state) = @_;

    return { error => 'disabled' } unless $Config{enabled};
    return { error => 'no state' } unless $state && ref($state) eq 'HASH';

    my $payload = {
        state     => $state,
        questions => {
            is_spam => {
                type         => 'noul',
                instructions => 'Is this email unsolicited bulk mail, '
                              . 'advertising, or a scam?',
            },
            is_phishing => {
                type         => 'noul',
                instructions => 'Does this email attempt to impersonate a '
                              . 'person, brand, or service to steal '
                              . 'credentials, payment details, or other '
                              . 'sensitive information?',
            },
        },
    };

    my $resp = _http_post_json($Config{predict_path}, $payload);
    return { error => $resp->{error} } if $resp->{error};

    my $answers = $resp->{answers} || {};
    my %verdict;
    for my $key (qw(is_spam is_phishing)) {
        my $a = $answers->{$key};
        # The 'noul' question type answers with its own name: $a->{noul} is
        # a probability in [0,1] that the answer is "yes", not a boolean.
        if (!$a || !defined $a->{noul} || !defined $a->{confidence}) {
            $verdict{$key} = { answer => undef, confidence => 0 };
            next;
        }
        if ($a->{confidence} < $Config{min_confidence}) {
            $verdict{$key} = { answer => undef, confidence => $a->{confidence} };
        } else {
            $verdict{$key} = {
                answer     => $a->{noul} >= 0.5 ? 1 : 0,
                confidence => $a->{confidence} + 0,
            };
        }
    }
    return \%verdict;
}

sub _http_post_json {
    my ($path, $payload) = @_;

    my $url = $Config{server_url} . $path;
    my $req = HTTP::Request->new(POST => $url);
    $req->header('Content-Type' => 'application/json');
    $req->content(encode_json($payload));

    my $tries = 1 + $Config{connect_retries};
    my $resp;
    while ($tries-- > 0) {
        $resp = _ua()->request($req);
        last if $resp->is_success;
    }

    unless ($resp && $resp->is_success) {
        my $reason = $resp ? $resp->status_line : 'no response';
        md_syslog('info', "laya: request to $url failed: $reason");
        return { error => $reason };
    }

    my $data = eval { decode_json($resp->decoded_content) };
    if ($@ || !$data) {
        md_syslog('info', "laya: malformed JSON from $url: $@");
        return { error => 'bad json' };
    }
    return $data;
}

1;

__END__

=head1 SEE ALSO

C<mimedefang-laya-server> - resident Laya inference server this module talks to.

=cut
