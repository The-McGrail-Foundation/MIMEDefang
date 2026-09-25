#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

package Mail::MIMEDefang::ML::Laya;

=head1 NAME

Mail::MIMEDefang::ML::Laya - Laya backend for L<Mail::MIMEDefang::ML>.

=head1 SYNOPSIS

  use Mail::MIMEDefang::ML;

  $Mail::MIMEDefang::ML::Config{backend}          = 'laya';
  $Mail::MIMEDefang::ML::Config{laya}{server_url} = 'http://127.0.0.1:8687';

  my $verdict = ml_classify(ml_build_state(...));

=head1 DESCRIPTION

Laya (L<https://github.com/NandhaKishorM/laya>) is a non-autoregressive
encoder-based decision model: one forward pass returns typed, calibrated
answers instead of generated text, which avoids both the latency and the
parsing/hallucination risk of an autoregressive LLM for a simple ham/spam/
phishing verdict.

Because Laya is a Python library, this backend talks to a small resident
Python inference server (see C<mimedefang-laya-server>), POSTing the state
with fixed C<noul> (boolean) questions for spam and phishing.

This module is not used directly: select it with
C<$Mail::MIMEDefang::ML::Config{backend} = 'laya'>.

=head1 CONFIGURATION

C<$Mail::MIMEDefang::ML::Config{laya}>: C<server_url> (default
C<http://127.0.0.1:8687>), C<predict_path> (default C</predict>).

=cut

use strict;
use warnings;

use Mail::MIMEDefang::ML ();

sub classify {
    my ($state, $cfg) = @_;
    my $lc = $cfg->{laya} || {};

    my %questions = map {
        $_ => { type => 'noul', instructions => $Mail::MIMEDefang::ML::QUESTIONS{$_} }
    } keys %Mail::MIMEDefang::ML::QUESTIONS;

    my $resp = Mail::MIMEDefang::ML::http_post_json(
        ($lc->{server_url} // '') . ($lc->{predict_path} // '/predict'),
        { state => $state, questions => \%questions },
    );
    return { error => $resp->{error} } if $resp->{error};

    my $answers = $resp->{answers} || {};
    my %verdict;
    for my $key (keys %questions) {
        my $a = $answers->{$key};
        # The 'noul' question type answers with its own name: $a->{noul} is
        # a probability in [0,1] that the answer is "yes", not a boolean.
        next if !$a || !defined $a->{noul} || !defined $a->{confidence};
        $verdict{$key} = {
            answer     => $a->{noul} >= 0.5 ? 1 : 0,
            confidence => $a->{confidence},
        };
    }
    return \%verdict;
}

1;

__END__

=head1 SEE ALSO

L<Mail::MIMEDefang::ML>, C<mimedefang-laya-server>.

=cut
