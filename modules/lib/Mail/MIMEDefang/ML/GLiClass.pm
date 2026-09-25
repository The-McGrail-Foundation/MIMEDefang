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
multi-label mode against one label per question.

A label score C<p> is mapped to a yes answer when C<p E<gt>= 0.5>, with
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

=item C<labels>

Hashref C<{ is_spam =E<gt> $text, is_phishing =E<gt> $text }> with the label
text scored for each question.  Tuning these is the main knob for accuracy.

=back

=cut

use strict;
use warnings;

use Mail::MIMEDefang::ML ();

sub classify {
    my ($state, $cfg) = @_;
    my $gc     = $cfg->{gliclass} || {};
    my $labels = $gc->{labels} || {};

    my %wanted = map { $_ => $labels->{$_} }
                 grep { defined $labels->{$_} }
                 keys %Mail::MIMEDefang::ML::QUESTIONS;
    return { error => 'no labels configured' } unless %wanted;

    my $resp = Mail::MIMEDefang::ML::http_post_json(
        ($gc->{server_url} // '') . ($gc->{predict_path} // '/predict'),
        { text => Mail::MIMEDefang::ML::state_to_text($state), labels => \%wanted },
    );
    return { error => $resp->{error} } if $resp->{error};

    my $scores = $resp->{scores};
    return { error => 'bad response' } unless $scores && ref($scores) eq 'HASH';

    my %verdict;
    for my $key (keys %wanted) {
        my $p = $scores->{$key};
        next unless defined $p;
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
