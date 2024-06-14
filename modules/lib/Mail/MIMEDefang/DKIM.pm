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

use strict;
use warnings;

require Exporter;

use Mail::DKIM::Signer;
use Mail::DKIM::Verifier;

use Mail::MIMEDefang;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(md_dkim_sign md_dkim_verify);

sub _md_signer_policy
{
        my $dkim = shift;

        use Mail::DKIM::DkSignature;

        my $sig = Mail::DKIM::Signature->new(
                        Algorithm => $dkim->algorithm,
                        Method => $dkim->method,
                        Headers => $dkim->headers,
                        Domain => $dkim->domain,
                        Selector => $dkim->selector,
                );
        $dkim->add_signature($sig);
        return;
}

=item md_dkim_sign

Returns a mail header and the DKIM signature for the message.
The method accepts the following parameters:

=over 4

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

=item C<$wrap>

Option to disable DKIM header lines wrap.

=back

=cut

sub md_dkim_sign {

  my ($keyfile, $algorithm, $method, $domain, $selector, $headers, $wrap) = @_;

  $algorithm = defined $algorithm ? $algorithm : 'rsa-sha1';
  $method = defined $method ? $method : 'relaxed';
  $selector = defined $selector ? $selector : 'default';
  $wrap //= 1;

  eval {
    if($wrap) {
      require Mail::DKIM::TextWrap;
      Mail::DKIM::TextWrap->import();
    }
  };

  my ($fh);

  if(not -f $keyfile) {
    md_syslog('err', "Could not open private DKIM key in md_dkim_sign: $!");
    return;
  }

  my $dkim = Mail::DKIM::Signer->new(
                       Policy => \&_md_signer_policy,
                       Algorithm => $algorithm,
                       Method => $method,
                       Domain => $domain,
                       Selector => $selector,
                       KeyFile => $keyfile,
                       Headers => $headers,
                  );
  unless (open($fh, '<', "./INPUTMSG")) {
    md_syslog('err', "Could not open INPUTMSG in md_dkim_sign: $!");
    return;
  }

  # or read an email and pass it into the signer, one line at a time
  while (<$fh>) {
    # remove local line terminators
    s/\015?\012$//;

    # use SMTP line terminators
    $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;
  close($fh);

  my $signature = $dkim->signature->as_string;
  # canonicalize newlines and trim trailing newline
  $signature =~ s/\015(?=\012)//gs;
  $signature =~ s/\012$//;

  if($signature =~ /^(.*):\s(.*)$/s) {
    return ($1, $2);
  }
  return;
}

=item md_dkim_verify

Verifies the DKIM signature of an email.
Return value can be "pass", "fail", "invalid", "temperror", "none".
In case of multiple signatures, the "best" result will be returned.
Best is defined as "pass", followed by "fail", "invalid", and "none".
The second return value is the domain that has applied the signature.
The third return value is the size of the DKIM public key.
The forth return value is the value of the "b" tag of the DKIM signature.

=cut

sub md_dkim_verify {

  my $dkim = Mail::DKIM::Verifier->new();

  my $fh;

  unless (open($fh, '<', "./INPUTMSG")) {
    md_syslog('err', "Could not open INPUTMSG in md_dkim_verify: $!");
    return;
  }

  eval {
    my $warn = 0;
    local $SIG{__WARN__} = sub {
      if($warn eq 0) {
        md_syslog("Warning", "md_dkim_verify: cannot parse DKIM signature");
      }
      $warn++;
    };
    while (<$fh>) {
      # remove local line terminators
      s/\015?\012$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
    }
    $dkim->CLOSE;
  };
  close($fh);

  my $key_size;
  $key_size = eval {
    my $pk = $dkim->signature->get_public_key;
       $pk && $pk->cork && $pk->cork->size * 8 };
  if(defined $dkim->signature and defined $key_size) {
    return ($dkim->result, $dkim->signature->domain, $key_size, $dkim->signature->get_tag('b'));
  } else {
    return ($dkim->result, undef, 0, undef);
  }
}

=back

=cut

1;
