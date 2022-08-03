#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::DKIM::ARC - ARC interface for MIMEDefang

=head1 DESCRIPTION

Mail::MIMEDefang::DKIM::ARC is a module with a set of ARC related methods called
from F<mimedefang-filter> to operate with ARC signatures.
Mail::DKIM > 1.20200513 is needed for the sub to work properly.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::DKIM::ARC;

use strict;
use warnings;

require Exporter;

use Mail::DKIM::ARC::Signer;
use Mail::DKIM::TextWrap;

use Mail::MIMEDefang;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(md_arc_sign);

=item md_arc_sign

Returns an hash with mail headers and the ARC signature for the message.
If ARC sign fails the hash will contain an error message.
The method accepts the following parameters:

=over 4

=item C<$keyfile>

The path to the private ARC key

=item C<$algorithm>

The algorithm to be used to sign the message, by default is 'rsa-sha256'

=item C<$chain>

The cv= value for the Arc-Seal header.  "ar" means to copy it from an Authentication-Results header, or use none if there isn't one.

=item C<$domain>

The domain to be used when signing the message.

=item C<$srvid>

The authserv-id in the Authentication-Results headers, defaults to Domain.

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

=back

=cut

sub md_arc_sign {

  my ($keyfile, $algorithm, $chain, $domain, $srvid, $selector, $headers) = @_;

  $algorithm = defined $algorithm ? $algorithm : 'rsa-sha256';
  $selector = defined $selector ? $selector : 'default';
  $srvid = defined $srvid ? $srvid : $domain;

  my (%headers, %err, $fh, $h, $v);

  if(not -f $keyfile) {
    md_syslog('err', "Could not open private ARC key in md_arc_sign: $!");
    return;
  }
  if(not defined $chain) {
    md_syslog('err', "Could not ARC sign a message without specifying a chain");
    return;
  }
  if(not defined $domain) {
    md_syslog('err', "Could not ARC sign a message without specifying a domain");
    return;
  }

  my $arc = Mail::DKIM::ARC::Signer->new(
                       Algorithm => $algorithm,
                       Chain => $chain,
                       Domain => $domain,
                       SrvId => $srvid,
                       Selector => $selector,
                       KeyFile => $keyfile,
                       Headers => $headers,
                  );
  unless (open($fh, '<', "./INPUTMSG")) {
    md_syslog('err', "Could not open INPUTMSG in md_arc_sign: $!");
    return;
  }

  # or read an email and pass it into the signer, one line at a time
  while (<$fh>) {
    # remove local line terminators
    chomp;
    s/\015$//;

    # use SMTP line terminators
    $arc->PRINT("$_\015\012");
  }
  $arc->CLOSE;
  close($fh);

  if($arc->result eq "sealed") {
    my @pre_headers = $arc->as_strings();
    foreach my $arc_h ( @pre_headers ) {
      if($arc_h =~ /^(.*):\s(.*)$/s) {
        $h = $1;
        $v = $2;
        $v =~ s/\r//gs;
        $headers{$h} = $v;
      }
    }
    return %headers;
  } else {
    $err{error} = $arc->{details};
    return %err;
  }
  return;
}

=back

=cut

1;
