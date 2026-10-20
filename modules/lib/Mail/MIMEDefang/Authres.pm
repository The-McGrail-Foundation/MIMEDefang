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
@EXPORT_OK = qw(md_org_domain);

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

The From: header domain to use for BIMI lookup.  When provided, a C<bimi=>
result (C<pass>, C<none>, C<declined>, C<skipped>, C<temperror> or C<fail>,
see C<md_bimi_verify> in L<Mail::MIMEDefang::BIMI>) is appended to the
Authentication-Results header.

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

  # The sender, HELO and domains come from the client: only well-formed
  # values go into the header
  my $ar_mailfrom = _ar_mailfrom($spfmail);
  my $ar_helo     = _ar_domain($helo);
  $dkimdom        = _ar_domain($dkimdom);
  $spfcode        = undef unless defined $ar_mailfrom;
  $helo_spfcode   = undef unless defined $ar_helo;
  if((defined $spfcode) or ((defined $dkimpk) and ($ksize > 0))) {
    # Mail::DKIM::ARC::Signer v0.54 doesn't correctly parse Authentication-Results headers,
    # add a workaround to make md_arc_sign work with our own headers.
    if($dkimoldver) {
      $authres = "$serverdomain;";
    } else {
      $authres = "$serverdomain (MIMEDefang);";
    }
    if(defined $dkimpk and defined $dkimdom) {
      my $dkimb = substr($dkimpk, 0, 8);
      $dkimb = undef unless $dkimb =~ m{^[A-Za-z0-9+/=]+$};
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
        $authres .= "\r\n\tspf=" . $spfcode . " (domain of $ar_mailfrom does not designate $relayip as permitted sender) smtp.mailfrom=$ar_mailfrom;";
      } elsif($spfcode eq 'pass') {
        $authres .= "\r\n\tspf=" . $spfcode . " (domain of $ar_mailfrom designates $relayip as permitted sender) smtp.mailfrom=$ar_mailfrom;";
      } elsif($spfcode eq 'none') {
        $authres .= "\r\n\tspf=" . $spfcode . " (domain of $ar_mailfrom doesn't specify if $relayip is a permitted sender) smtp.mailfrom=$ar_mailfrom;";
      }
    }
    if(defined $helo_spfcode) {
      if($helo_spfcode eq 'fail') {
        $authres .= "\r\n\tspf=" . $helo_spfcode . " (domain of $ar_helo does not designate $relayip as permitted sender) smtp.helo=$ar_helo;";
      } elsif($helo_spfcode eq 'pass') {
        $authres .= "\r\n\tspf=" . $helo_spfcode . " (domain of $ar_helo designates $relayip as permitted sender) smtp.helo=$ar_helo;";
      } elsif($helo_spfcode eq 'none') {
        $authres .= "\r\n\tspf=" . $helo_spfcode . " (domain of $ar_helo doesn't specify if $relayip is a permitted sender) smtp.helo=$ar_helo;";
      }
    }
    $bimi_domain = _ar_domain($bimi_domain);
    if (defined $bimi_domain) {
      my $dmarc_record = md_get_dmarc_record($bimi_domain);
      my $dmarc_policy = 'none';
      if (defined $dmarc_record && $dmarc_record =~ /\bp=(\w+)/) {
        $dmarc_policy = lc($1);
      }
      # Determine an effective DMARC result using relaxed alignment:
      # pass if DKIM passes and the DKIM signing domain aligns with $bimi_domain,
      # or if SPF passes and the mail-from domain aligns.
      my $effective_dmarc = 'fail';
      my $bimi_org = md_org_domain($bimi_domain);
      if ($bimi_org ne '' && defined $dkimres && $dkimres eq 'pass' && defined $dkimdom) {
        $effective_dmarc = 'pass' if md_org_domain($dkimdom) eq $bimi_org;
      }
      if ($bimi_org ne '' && $effective_dmarc ne 'pass' && defined $spfcode && $spfcode eq 'pass') {
        my ($spf_localpart, $spf_domain) = split /\@/, $spfmail, 2;
        if (defined $spf_domain && md_org_domain($spf_domain) eq $bimi_org) {
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

=item md_org_domain

Returns the "organizational domain" of a domain name, for use in relaxed
DMARC alignment checks (e.g. C<mail.example.com> -> C<example.com>,
C<www.bank.co.uk> -> C<bank.co.uk>), using the Public Suffix List shipped
with C<IO::Socket::SSL>.  Returns an empty string for an invalid domain or
a public suffix.  Without C<IO::Socket::SSL::PublicSuffix> the domain
itself is returned, which gives strict alignment.

=back

=cut

my $PublicSuffix;

sub md_org_domain {
  my ($domain) = @_;
  $domain = _ar_domain($domain);
  return '' unless defined $domain;
  $domain = lc $domain;
  $domain =~ s/\.$//;
  return '' if $domain =~ /^\[/;

  $PublicSuffix //= eval {
    require IO::Socket::SSL::PublicSuffix;
    IO::Socket::SSL::PublicSuffix->default;
  } // 0;
  return $domain unless $PublicSuffix;

  # A public suffix (e.g. "co.uk") has no organizational domain
  my ($rest) = $PublicSuffix->public_suffix($domain);
  return '' unless defined $rest && $rest ne '';
  my (undef, $org) = $PublicSuffix->public_suffix($domain, 1);
  return $org // '';
}

# Returns the domain if it is a well-formed host name or address literal
sub _ar_domain {
  my ($d) = @_;
  return unless defined $d;
  return $d if $d =~ /^(?=.{1,254}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$/;
  return $d if $d =~ /^\[(?:IPv6:)?[0-9A-Fa-f.:]+\]$/;
  return;
}

# Returns the envelope sender if it is safe to put in the header, else
# just its domain (RFC 8601 allows either), or undef
sub _ar_mailfrom {
  my ($addr) = @_;
  return unless defined $addr;
  $addr =~ s/^<//;
  $addr =~ s/>$//;
  my ($local, $domain) = $addr =~ /^(.*)\@([^\@]+)$/ or return;
  return unless defined _ar_domain($domain);
  return $addr if $local =~ /^[A-Za-z0-9!#\$%&'*+\/=?^_`{|}~.-]+$/;
  return $domain;
}

1;
