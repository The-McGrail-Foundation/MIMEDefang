#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::DKIM - DKIM interface for MIMEDefang

=head1 DESCRIPTION

Mail::MIMEDefang::DKIM is a module with a set of DKIM related methods called
from F<mimedefang-filter> to operate with DKIM.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::DKIM;

require Exporter;

use Mail::DKIM::Signer;
use Mail::DKIM::TextWrap;

use Mail::MIMEDefang;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(md_dkim_sign);

=item md_dkim_sign

Returns a mail header and the DKIM signature for the message.
The method accepts the following parameters:

=item C<$keyfile>

The path to the private DKIM key

=item C<$algorithm>

The algorithm to be used to sign the message, by default is 'rsa-sha1'

=item C<$method>

The method used to sign the message, by default is 'relaxed'

=item C<$domain>

The domain to be used when signing the message, by default it's autodetected

=item C<$selector>

The selector to be used when signing the message, by default it's 'default'

=item C<$headers>

The headers to sign, by default the headers are:
               From Sender Reply-To Subject Date
               Message-ID To Cc MIME-Version
               Content-Type Content-Transfer-Encoding Content-ID Content-Description
               Resent-Date Resent-From Resent-Sender Resent-To Resent-cc
               Resent-Message-ID
               In-Reply-To References
               List-Id List-Help List-Unsubscribe List-Subscribe
               List-Post List-Owner List-Archive

=cut

sub md_dkim_sign {

  my ($keyfile, $algorithm, $method, $domain, $selector, $headers) = @_;

  $algorithm //= 'rsa-sha1';
  $method //= 'relaxed';
  $selector //= 'default';

  if(not -f $keyfile) {
    md_syslog('err', "Could not open private DKIM key in md_dkim_sign: $!");
    return;
  }

  my $dkim = Mail::DKIM::Signer->new(
                       Algorithm => $algotithm,
                       Method => $method,
                       Domain => $domain,
                       Selector => $selector,
                       KeyFile => $keyfile,
                       Headers => $headers,
                  );
  unless (open(IN, '<', "./INPUTMSG")) {
    md_syslog('err', "Could not open INPUTMSG in md_dkim_sign: $!");
    return;
  }

  $dkim->load(*IN);
  close(IN);

  # or read an email and pass it into the signer, one line at a time
  while (<IN>) {
    # remove local line terminators
    chomp;
    s/\015$//;

    # use SMTP line terminators
    $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;

  my $signature = $dkim->signature;
  my ($h, $v);
  if($signature->as_string =~ /^(.*):\s(.*)$/s) {
    $h = $1;
    $v = $2;
    return ($h, $v);
  }
  return;
}

=back

=cut

1;
