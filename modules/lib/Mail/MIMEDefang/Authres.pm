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

use Mail::MIMEDefang::BIMI;
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

=item C<$bimi_domain> (optional)

The From: header domain to use for BIMI lookup.  When provided and when DMARC
passes at enforcement level, a C<bimi=pass> (or C<bimi=fail>) result is
appended to the Authentication-Results header.

=back

=cut

sub md_authres {

  my ($spfmail, $relayip, $serverdomain, $helo, $bimi_domain) = @_;
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
    if (defined $bimi_domain && $bimi_domain ne '') {
      my $dmarc_record = md_get_dmarc_record($bimi_domain);
      my $dmarc_policy = 'none';
      if (defined $dmarc_record && $dmarc_record =~ /\bp=(\w+)/) {
        $dmarc_policy = lc($1);
      }
      # Determine an effective DMARC result using relaxed alignment:
      # pass if DKIM passes and the DKIM signing domain aligns with $bimi_domain,
      # or if SPF passes and the mail-from domain aligns.
      my $effective_dmarc = 'fail';
      my $bimi_org = _org_domain($bimi_domain);
      if (defined $dkimres && $dkimres eq 'pass' && defined $dkimdom) {
        $effective_dmarc = 'pass' if _org_domain($dkimdom) eq $bimi_org;
      }
      if ($effective_dmarc ne 'pass' && defined $spfcode && $spfcode eq 'pass') {
        my ($spf_localpart, $spf_domain) = split /\@/, $spfmail, 2;
        if (defined $spf_domain && _org_domain($spf_domain) eq $bimi_org) {
          $effective_dmarc = 'pass';
        }
      }
      my $bimi_res = md_bimi_verify($bimi_domain, $effective_dmarc, $dmarc_policy);
      $authres .= "\r\n\tbimi=" . $bimi_res . " header.d=$bimi_domain;";
    }
    $authres =~ s/\r//gs;
    return $authres;
  }
  return;
}

=back

=cut

# Return the "organizational domain" for relaxed DMARC alignment:
# strip all labels except the last two (e.g. mail.example.com -> example.com).
# This is a simplification; a production deployment may use the Public Suffix List.
sub _org_domain {
  my ($domain) = @_;
  return '' unless defined $domain && $domain ne '';
  $domain = lc $domain;
  my @labels = split /\./, $domain;
  return $domain if @labels <= 2;
  return join('.', @labels[-2..-1]);
}

1;
