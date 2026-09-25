#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::MIME::Base64 - base64 decoder that notices concatenated streams

=head1 DESCRIPTION

A base64 part is supposed to be a single stream: padding (C<=>) may only
appear at its very end.  Some software nevertheless produces parts made of
several base64 streams glued together, and some mail clients decode every
stream separately and join the results.

Mail::MIMEDefang::MIME::Base64 is a subclass of
L<MIME::Decoder::Base64> that behaves exactly like its parent but also notes
whenever data follows padding, so that MIMEDefang can log the message and let
the filter act on it (see C<md_concatenated_base64> in
L<Mail::MIMEDefang::MIME>).  This works with any MIME-tools version.

The module is used by MIMEDefang itself and is not meant to be called from
F<mimedefang-filter>.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::MIME::Base64;

use strict;
use warnings;

use MIME::Decoder;
use MIME::Decoder::Base64;

our @ISA = qw(MIME::Decoder::Base64);

my $Count = 0;

=item activate

Class method.  Installs this decoder for the C<base64> encoding, unless
something other than the stock MIME::Decoder::Base64 has been installed
already (a site-provided decoder is left alone).  Returns 1 if the watching
decoder is in place and 0 otherwise.  Safe to call repeatedly.

=cut

sub activate {
    my $current = MIME::Decoder->supported('base64');
    if (defined($current) && $current eq 'MIME::Decoder::Base64') {
        __PACKAGE__->install('base64');
    }
    $current = MIME::Decoder->supported('base64');
    return (defined($current) && $current eq __PACKAGE__) ? 1 : 0;
}

=item reset_count

Sets the number of concatenated base64 parts seen back to zero.  MIMEDefang
calls this before parsing each message.

=cut

sub reset_count {
    $Count = 0;
    return;
}

=item count

Returns the number of base64 parts made of concatenated streams decoded since
the last call to C<reset_count>.

=cut

sub count {
    return $Count;
}

# Decode exactly like the parent, but feed it through a tap that watches
# the encoded data for padding followed by more data.
sub decode_it {
    my ($self, $in, $out) = @_;

    my $tap = Mail::MIMEDefang::MIME::Base64::Tap->new($in);
    my $ret = $self->SUPER::decode_it($tap, $out);
    $Count++ if $tap->found;
    return $ret;
}

=back

=cut

# Input wrapper handed to MIME::Decoder::Base64::decode_it, which only ever
# calls read() on it.  It passes everything through unchanged.
package Mail::MIMEDefang::MIME::Base64::Tap;

use strict;
use warnings;

sub new {
    my ($class, $in) = @_;
    return bless { in => $in, pad => 0, found => 0 }, $class;
}

sub found {
    my ($self) = @_;
    return $self->{found};
}

# Same interface as IO::Handle::read: $_[0] is the caller's buffer and $_[1]
# the length.  Keep the alias so the wrapped handle fills the caller's buffer.
sub read {
    my $self = shift;
    my $n = $self->{in}->read($_[0], $_[1]);
    $self->_inspect($_[0]) if ($n && !$self->{found});
    return $n;
}

# Padding may only end a stream, so any base64 character after it (even in
# the next chunk) means another stream has been glued on.
sub _inspect {
    my ($self, $chunk) = @_;

    (my $s = $chunk) =~ tr{A-Za-z0-9+/=}{}cd;
    return unless length($s);

    if (($self->{pad} && $s =~ m{\A[A-Za-z0-9+/]}) || $s =~ m{=[A-Za-z0-9+/]}) {
        $self->{found} = 1;
        return;
    }
    $self->{pad} = ($s =~ /=\z/) ? 1 : 0;
    return;
}

1;
