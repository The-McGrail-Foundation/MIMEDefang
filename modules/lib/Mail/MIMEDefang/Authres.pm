#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Authres - Authentication Results interface for MIMEDefang

=head1 DESCRIPTION

Mail::MIMEDefang::Authres is a module used to add Authentication Results
headers from F<mimedefang-filter>.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Authres;

require Exporter;

use Mail::SPF;

use Mail::MIMEDefang::DKIM;
use Mail::MIMEDefang::Net;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(md_authres);

=item md_authres

Returns a mail Authentication-Results header value.
The method accepts the following parameters:

=over 4

=item C<$email>

The email address of the sender

=item C<$relayip>

The relay ip address

=item C<$serverdomain>

The domain name of the server where MIMEDefang is running on

=back

=cut

sub md_authres {

  my ($spfmail, $relayip, $serverdomain) = @_;

  if(not defined $spfmail and not defined $relayip and not defined $serverdomain) {
    md_syslog('err', "Cannot calculate Authentication-Results header without email address, relay ip and server domain name");
    return;
  }
  my ($authres, $spfres);
  my ($dkimres, $dkimdom, $ksize, $dkimpk) = md_dkim_verify();
  $spfmail =~ s/^<//;
  $spfmail =~ s/>$//;
  if(defined $spfmail and $spfmail =~ /\@/) {
    my $spf_server  = Mail::SPF::Server->new();
    my $request     = Mail::SPF::Request->new(
      scope           => 'mfrom',
      identity        => $spfmail,
      ip_address      => $relayip,
    );
    $spfres = $spf_server->process($request);
  }
  if(defined $spfres or $ksize > 0) {
    my $dkimb = substr($dkimpk, 0, 8);
    $authres = "$serverdomain (MIMEDefang);";
    if($ksize > 0) {
      $authres .= "\r\n\tdkim=$dkimres ($ksize-bit key) header.d=$dkimdom";
      if(defined($dkimb)) {
        $authres .= " header.b=$dkimb";
      }
      $authres .= ";";
    }
    if(defined $spfres) {
      if($spfres->code eq 'fail') {
        $authres .= "\r\n\tspf=" . $spfres->code . " (domain of $spfmail does not designate $relayip as permitted sender) smtp.mailfrom=$spfmail;";
      } elsif($spfres->code eq 'pass') {
        $authres .= "\r\n\tspf=" . $spfres->code . " (domain of $spfmail designates $relayip as permitted sender) smtp.mailfrom=$spfmail;";
      } elsif($spfres->code eq 'none') {
        $authres .= "\r\n\tspf=" . $spfres->code . " (domain of $spfmail doesn't specify if $relayip is a permitted sender) smtp.mailfrom=$spfmail;";
      }
    }
    $authres =~ s/\r//gs;
    return $authres;
  }
  return;
}

=back

=cut

1;
