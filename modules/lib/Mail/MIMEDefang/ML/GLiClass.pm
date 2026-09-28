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
multi-label mode against one label per question, plus a fixed label
describing legitimate mail (a newsletter or marketing email the recipient
subscribed to).  Each question's probability is C<p = s / (s + h)>, where
C<s> is its label's score and C<h> the ham label's score: on its own a
label scores high on legitimate marketing mail too.

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
our %LABELS = (
    is_spam     => 'fraudulent email: fake invoice, fake order, fake account alert or advance-fee scam',
    is_phishing => 'phishing, impersonation to steal credentials or payment details',
);

# Scored with the question labels, each of which is weighed against it.
# Broader ones ("correspondence", "notification") score high on any mail,
# spam included.
our @HAM_LABELS = (
    'newsletter or marketing email from a company the recipient subscribed to',
);

sub classify {
    my ($state, $cfg) = @_;
    my $gc = $cfg->{gliclass} || {};

    my %wanted = map { $_ => $LABELS{$_} }
                 grep { defined $LABELS{$_} }
                 keys %Mail::MIMEDefang::ML::QUESTIONS;

    # Ham labels go in under keys that can't clash with a question.
    my @ham = @HAM_LABELS;
    my %send = %wanted;
    $send{"_ham$_"} = $ham[$_] for 0 .. $#ham;

    my $resp = Mail::MIMEDefang::ML::http_post_json(
        ($gc->{server_url} // '') . ($gc->{predict_path} // '/predict'),
        { text => Mail::MIMEDefang::ML::state_to_text($state, $gc), labels => \%send },
    );
    return { error => $resp->{error} } if $resp->{error};

    my $scores = $resp->{scores};
    return { error => 'bad response' } unless $scores && ref($scores) eq 'HASH';

    # Multi-label scores are independent sigmoids, so a label alone tends
    # to score high on any mail that shares its topic.  Weigh each
    # question's label against the best ham label instead.
    my ($ham_best) = sort { $b <=> $a } grep { defined } map { $scores->{"_ham$_"} } 0 .. $#ham;

    my %verdict;
    for my $key (keys %wanted) {
        my $p = $scores->{$key};
        next unless defined $p;
        if (defined $ham_best) {
            next unless $p + $ham_best > 0;
            $p = $p / ($p + $ham_best);
        }
        my $yes = $p >= 0.5 ? 1 : 0;
        $verdict{$key} = {
            answer     => $yes,
            confidence => $yes ? $p : 1 - $p,
        };
    }
    return \%verdict;
}

1;

__END__

=head1 SEE ALSO

L<Mail::MIMEDefang::ML>, C<mimedefang-gliclass-server>.

=cut
