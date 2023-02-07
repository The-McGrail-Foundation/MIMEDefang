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

use strict;
use warnings;

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

=item C<$helo> (optional)

The MTA helo server name

=back

=cut

sub md_authres {

  my ($spfmail, $relayip, $serverdomain, $helo) = @_;
  my $dkimoldver = 1;

  if(not defined $spfmail and not defined $relayip and not defined $serverdomain) {
    md_syslog('err', "Cannot calculate Authentication-Results header without email address, relay ip and server domain name");
    return;
  }

  if (version->parse(Mail::DKIM->VERSION) > version->parse(1.2)) {
    $dkimoldver = 0;
  }

  my ($authres, $spfres, $helo_spfres);
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
    if((defined $helo) and (defined $spfres and ($spfres->code eq 'pass'))) {
      my $helo_request     = Mail::SPF::Request->new(
        scope           => 'helo',
        identity        => $helo,
        ip_address      => $relayip,
      );
      $helo_spfres = $spf_server->process($request);
    }
  }
  if((defined $spfres and defined $spfres->code) or ((defined $dkimpk) and ($ksize > 0))) {
    # Mail::DKIM::ARC::Signer v0.54 doesn't correctly parse Authentication-Results headers,
    # add a workaround to make md_arc_sign work with our own headers.
    if($dkimoldver) {
      $authres = "$serverdomain;";
    } else {
      $authres = "$serverdomain (MIMEDefang);";
    }
    if(defined $dkimpk) {
      my $dkimb = substr($dkimpk, 0, 8);
      if($ksize > 0) {
        $authres .= "\r\n\tdkim=$dkimres ($ksize-bit key) header.d=$dkimdom";
        if(defined($dkimb)) {
          $authres .= " header.b=\"$dkimb\"";
        }
        $authres .= ";";
      }
    }
    if(defined $spfres) {
      if($spfres->code eq 'fail') {
        $authres .= "\r\n\tspf=" . $spfres->code . " (domain of $spfmail does not designate $relayip as permitted sender) smtp.mailfrom=$spfmail;";
      } elsif($spfres->code eq 'pass') {
        $authres .= "\r\n\tspf=" . $spfres->code . " (domain of $spfmail designates $relayip as permitted sender) smtp.mailfrom=$spfmail";
        if(defined $helo_spfres and $helo_spfres->code eq 'pass') {
          $authres .= " smtp.helo=$helo";
        }
        $authres .= ';';
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
