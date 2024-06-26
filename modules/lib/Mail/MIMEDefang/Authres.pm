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

use Mail::MIMEDefang::DKIM;
use Mail::MIMEDefang::Net;
use Mail::MIMEDefang::SPF;

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

  my ($spfcode, $spfexpl, $helo_spfcode, $helo_spfexpl) = md_spf_verify($spfmail, $relayip, $helo);
  if((defined $spfcode) or ((defined $dkimpk) and ($ksize > 0))) {
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
          $authres .= " header.b=$dkimb";
        }
        $authres .= ";";
      }
    }
    if(defined $spfcode) {
      if($spfcode eq 'fail') {
        $authres .= "\r\n\tspf=" . $spfcode . " (domain of $spfmail does not designate $relayip as permitted sender) smtp.mailfrom=$spfmail;";
      } elsif($spfcode eq 'pass') {
        $authres .= "\r\n\tspf=" . $spfcode . " (domain of $spfmail designates $relayip as permitted sender) smtp.mailfrom=$spfmail;";
      } elsif($spfcode eq 'none') {
        $authres .= "\r\n\tspf=" . $spfcode . " (domain of $spfmail doesn't specify if $relayip is a permitted sender) smtp.mailfrom=$spfmail;";
      }
    }
    if(defined $helo_spfcode) {
      if($helo_spfcode eq 'fail') {
        $authres .= "\r\n\tspf=" . $helo_spfcode . " (domain of $helo does not designate $relayip as permitted sender) smtp.helo=$helo;";
      } elsif($helo_spfcode eq 'pass') {
        $authres .= "\r\n\tspf=" . $helo_spfcode . " (domain of $helo designates $relayip as permitted sender) smtp.helo=$helo;";
      } elsif($helo_spfcode eq 'none') {
        $authres .= "\r\n\tspf=" . $helo_spfcode . " (domain of $helo doesn't specify if $relayip is a permitted sender) smtp.helo=$helo;";
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
