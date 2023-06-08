#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::SPF - Sender Policy Framework interface for MIMEDefang

=head1 DESCRIPTION

Mail::MIMEDefang::SPF is a module used to check for Sender Policy Framework
headers from F<mimedefang-filter>.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::SPF;

use strict;
use warnings;

require Exporter;

use Mail::SPF;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(md_spf_verify);

=item md_spf_verify

Returns code and explanation of Sender Policy Framework
check.

Possible return code values are:
"pass", "fail", "softfail", "neutral", "none", "error", "permerror", "temperror", "invalid"

The method accepts the following parameters:

=over 4

=item C<$email>

The email address of the sender

=item C<$relayip>

The relay ip address

=item C<$helo> (optional)

The MTA helo server name

=back

=cut

sub md_spf_verify {

  my ($spfmail, $relayip, $helo) = @_;

  if(not defined $spfmail and not defined $relayip) {
    md_syslog('err', "Cannot check SPF without email address and relay ip");
    return;
  }

  my $spf_server  = Mail::SPF::Server->new();
  my ($spfres, $helo_spfres);
  $spfmail =~ s/^<//;
  $spfmail =~ s/>$//;
  if(defined $spfmail and $spfmail ne '') {
    if($spfmail =~ /(.*)\+(?:.*)\@(.*)/) {
      $spfmail = $1 . '@' . $2;
    }
    my $request     = Mail::SPF::Request->new(
      scope           => 'mfrom',
      identity        => $spfmail,
      ip_address      => $relayip,
    );
    $spfres = $spf_server->process($request);
  } else {
    return ('invalid', 'Invalid mail from parameter');
  }
  if(defined $helo) {
    my $helo_request     = Mail::SPF::Request->new(
      scope           => 'helo',
      identity        => $helo,
      ip_address      => $relayip,
    );
    $helo_spfres = $spf_server->process($helo_request);
  }
  if(defined $helo) {
    return ($spfres->code, $spfres->local_explanation, $helo_spfres->code, $helo_spfres->local_explanation);
  } else {
    return ($spfres->code, $spfres->local_explanation);
  }
}

=back

=cut

1;
