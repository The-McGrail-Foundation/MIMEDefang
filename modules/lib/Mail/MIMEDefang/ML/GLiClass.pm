#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

package Mail::MIMEDefang::ML::GLiClass;

=head1 NAME

Mail::MIMEDefang::ML::GLiClass - GLiClass zero-shot backend for
L<Mail::MIMEDefang::ML>.

=head1 SYNOPSIS

  use Mail::MIMEDefang::ML;

  $Mail::MIMEDefang::ML::Config{backend}              = 'gliclass';
  $Mail::MIMEDefang::ML::Config{gliclass}{server_url} = 'http://127.0.0.1:8688';

  my $verdict = ml_classify(ml_build_state(...));

=head1 DESCRIPTION

GLiClass (L<https://github.com/Knowledgator/GLiClass>) is a zero-shot
sequence classifier built on a bidirectional encoder (ModernBERT for the
C<gliclass-modern-*> checkpoints).  It scores the text against every label
in a single forward pass, so, like Laya, it avoids the latency and output
parsing of an autoregressive LLM, and it needs no fine-tuning: the labels
are plain text.

Because GLiClass is a Python library, this backend talks to a small
resident Python inference server (see C<mimedefang-gliclass-server>).  The
state is rendered as text (auth results, subject, then body) and scored in
multi-label mode against the labels of each question, plus fixed labels
describing legitimate mail (correspondence between people who know each
other, receipts, notices and newsletters from companies the recipient is
a customer of).  Each question's probability is C<p = s / (s + h)>, where
C<s> is its best label's score and C<h> the best ham label's score: on
its own a label scores high on legitimate marketing mail too.  The raw
C<s> and C<h> of every question and its C<p> are returned in the
verdict's C<scores> (C<is_spam>, C<ham>, C<p_is_spam>, ...).

C<p> is mapped to a yes answer when C<p E<gt>= 0.5>, with
confidence C<p> for a yes and C<1 - p> for a no, so the usual
C<min_confidence> gate applies.

This module is not used directly: select it with
C<$Mail::MIMEDefang::ML::Config{backend} = 'gliclass'>.

=head1 CONFIGURATION

C<$Mail::MIMEDefang::ML::Config{gliclass}>:

=over 4

=item C<server_url>

Default C<http://127.0.0.1:8688>.

=item C<predict_path>

Default C</predict>.

=item C<labels>, C<ham_labels>

Override the labels scored, C<%Mail::MIMEDefang::ML::GLiClass::LABELS>
and C<@Mail::MIMEDefang::ML::GLiClass::HAM_LABELS>.  C<labels> is a hash
keyed by question (C<is_spam>, C<is_phishing>), each value one label or
a list of labels; a question not in it keeps its default.  C<ham_labels>
is a list.  With several labels the best scoring one counts, so a
question can cover different kinds of mail:

  $Mail::MIMEDefang::ML::Config{gliclass}{labels}{is_spam} = [
      'scam email: fake invoice, fake order, fake prize, advance-fee or investment fraud',
      'unsolicited bulk advertising for pills, replica watches, loans, dating or stock tips',
  ];

A model fine-tuned with F<contrib/ml-benchmark/gliclass-train> must be
served with the labels it was trained on.

=item C<body_head_chars>, C<body_tail_chars>

Body kept for this backend, default 6000 and 1500 characters, about
2500 tokens with the headers.  The C<gliclass-modern-*> checkpoints read
up to 8192 tokens; the C<--max-length> of C<mimedefang-gliclass-server>
(default 4096 tokens, labels included) cuts anything longer.  The time
per message grows faster than the length: on CPU, 2000 tokens take
several seconds, so lower these (or raise C<timeout>) on slow hardware.

=back

=cut

use strict;
use warnings;

use Mail::MIMEDefang::ML ();

# The label scored for each question.  Concrete wording works best: a
# broad label ("spam, unsolicited bulk mail") scores high on newsletters.
# A question with several labels takes the best scoring one.
our %LABELS = (
    is_spam     => [
        'scam email: fake invoice, fake order, fake prize, advance-fee or investment fraud',
        'unsolicited sales pitch or bulk advertising from an unknown company',
    ],
    is_phishing => 'phishing: fake bank, courier, company or colleague asking for a password, payment or money transfer',
);

# Scored with the question labels; the best one is weighed against each
# question.  A bare "correspondence" or "notification" scores high on any
# mail, spam included, and "marketing" pulls spam up with newsletters.
our @HAM_LABELS = (
    'personal or business email between people who know each other',
    'receipt, account notice or newsletter from a company the recipient is a customer of',
);

# Resolve the labels to score: ({ question => [labels] }, [ham labels]).
# $cfg->{gliclass}{labels} and {ham_labels} override %LABELS and
# @HAM_LABELS; a question's labels may be one string or a list.
sub label_set {
    my ($cfg) = @_;
    my $gc = ($cfg && $cfg->{gliclass}) || {};
    my %src = (%LABELS, %{ ref($gc->{labels}) eq 'HASH' ? $gc->{labels} : {} });

    my %labels;
    for my $key (Mail::MIMEDefang::ML::active_questions($cfg)) {
        my $l = $src{$key};
        my @l = grep { defined && length } (ref($l) eq 'ARRAY' ? @$l : ($l));
        $labels{$key} = \@l if @l;
    }
    my $ham = $gc->{ham_labels};
    my @ham = grep { defined && length }
              (ref($ham) eq 'ARRAY' ? @$ham : defined $ham ? ($ham) : @HAM_LABELS);
    return (\%labels, \@ham);
}

sub classify {
    my ($state, $cfg) = @_;
    my $gc = $cfg->{gliclass} || {};
    my ($labels, $ham) = label_set($cfg);

    # Label keys can't clash with each other: "is_spam#0", "_ham0", ...
    my %send;
    for my $key (keys %$labels) {
        my $l = $labels->{$key};
        $send{"$key#$_"} = $l->[$_] for 0 .. $#$l;
    }
    $send{"_ham$_"} = $ham->[$_] for 0 .. $#$ham;

    my $resp = Mail::MIMEDefang::ML::http_post_json(
        ($gc->{server_url} // '') . ($gc->{predict_path} // '/predict'),
        { text => Mail::MIMEDefang::ML::state_to_text($state, $gc), labels => \%send },
    );
    return { error => $resp->{error} } if $resp->{error};

    my $scores = $resp->{scores};
    return { error => 'bad response' } unless $scores && ref($scores) eq 'HASH';

    # Multi-label scores are independent sigmoids, so a label alone tends
    # to score high on any mail that shares its topic.  Weigh each
    # question's best label against the best ham label instead.
    my ($ham_best) = sort { $b <=> $a } grep { defined } map { $scores->{"_ham$_"} } 0 .. $#$ham;

    my (%verdict, %raw);
    $raw{ham} = $ham_best if defined $ham_best;
    for my $key (keys %$labels) {
        my ($p) = sort { $b <=> $a } grep { defined }
                  map { $scores->{"$key#$_"} } 0 .. $#{ $labels->{$key} };
        next unless defined $p;
        $raw{$key} = $p;
        if (defined $ham_best) {
            next unless $p + $ham_best > 0;
            $p = $p / ($p + $ham_best);
        }
        $raw{"p_$key"} = $p;
        my $yes = $p >= 0.5 ? 1 : 0;
        $verdict{$key} = {
            answer     => $yes,
            confidence => $yes ? $p : 1 - $p,
        };
    }
    $verdict{scores} = \%raw;
    return \%verdict;
}

1;

__END__

=head1 SEE ALSO

L<Mail::MIMEDefang::ML>, C<mimedefang-gliclass-server>.

=cut
