#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::TLSPolicy - MTA-STS and DANE/TLSA policy checks for MIMEDefang

=encoding utf8

=head1 DESCRIPTION

Mail::MIMEDefang::TLSPolicy provides methods to verify outbound TLS policy
for recipient domains from F<mimedefang-filter>.

=over 4

=item *

B<MTA-STS> (RFC 8461) - retrieve and parse a domain's MTA-STS policy
(DNS TXT + HTTPS policy file).

=item *

B<DANE/TLSA> (RFC 6698 / RFC 7671) - look up TLSA records for a domain
and port to verify certificate binding.

=back

Both functions require C<Net::DNS>.  C<md_check_mta_sts> additionally
requires C<LWP::UserAgent>.

Typical usage:

  use Mail::MIMEDefang::TLSPolicy;

  # In filter_recipient: fetch the MTA-STS policy for the recipient domain,
  # then verify the connecting MX is permitted before requiring TLS.
  my $policy = md_check_mta_sts($recipient_domain);
  if (defined $policy && $policy->{mode} eq 'enforce') {
      if (!md_verify_sts_mx($rcpt_host, $policy)) {
          action_bounce("MX host $rcpt_host not permitted by MTA-STS policy");
      }
  }

  # Look up DANE TLSA records for port 25 and validate the peer certificate.
  my @tlsa = md_check_dane_tlsa($recipient_domain, 25);
  if (@tlsa) {
      unless (md_verify_dane_cert($peer_cert_der, \@tlsa)) {
          # certificate does not match any TLSA record - reject or defer
      }
  }

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::TLSPolicy;

use strict;
use warnings;

require Exporter;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Net qw(md_dns_txt);
use Net::DNS;

our @ISA = qw(Exporter);
our @EXPORT = qw(md_check_mta_sts md_check_dane_tlsa md_verify_sts_mx md_verify_dane_cert);
our @EXPORT_OK = ();

=item md_check_mta_sts($domain [, %opts])

Retrieve and parse the MTA-STS policy for C<$domain>.

The function performs two lookups:

=over 4

=item 1.

A DNS TXT query for C<_mta-sts.$domain> to confirm the policy exists and
extract its C<id=> field.

=item 2.

An HTTPS fetch of
C<https://mta-sts.$domain/.well-known/mta-sts.txt> to retrieve the
policy document.

=back

Optional key/value pairs in C<%opts>:

=over 4

=item C<timeout>

HTTP request timeout in seconds (default: 10).

=back

On success returns a hashref with:

=over 4

=item C<mode>

Policy mode: C<enforce>, C<testing>, or C<none>.

=item C<max_age>

Cache lifetime in seconds.

=item C<mx>

Arrayref of permitted MX hostname patterns.

=item C<id>

The policy C<id> from the DNS TXT record.

=back

Returns C<undef> on any error (DNS failure, HTTP error, policy parse
failure, or if C<LWP::UserAgent> is not available).

=cut

sub md_check_mta_sts {
    my ($domain, %opts) = @_;

    unless (defined $domain && $domain ne '') {
        md_syslog('err', 'md_check_mta_sts: domain is required');
        return;
    }
    unless ($Features{"Net::DNS"}) {
        md_syslog('err', 'md_check_mta_sts: Net::DNS is not available');
        return;
    }

    # DNS TXT lookup for _mta-sts.<domain>
    my $res = Net::DNS::Resolver->new;
    $res->defnames(0);

    my $txt_record = md_dns_txt($res, "_mta-sts.$domain");
    return unless defined $txt_record && $txt_record =~ /\bv=STSv1\b/i;

    my $policy_id;
    $policy_id = $1 if $txt_record =~ /\bid=([^;]+)/i;
    $policy_id =~ s/\s+$// if defined $policy_id;

    # HTTPS fetch of the policy file
    my $ua = _init_ua($opts{timeout} // 10);
    return unless defined $ua;

    my $url  = "https://mta-sts.$domain/.well-known/mta-sts.txt";
    my $resp = $ua->get($url);

    unless ($resp->is_success) {
        md_syslog('warning', "md_check_mta_sts: HTTP fetch failed for $url: " . $resp->status_line);
        return;
    }

    my $body = $resp->decoded_content;
    return unless defined $body && $body ne '';

    my %policy = (id => $policy_id, mx => []);
    for my $line (split /\r?\n/, $body) {
        $line =~ s/^\s+|\s+$//g;
        if ($line =~ /^version\s*:\s*(.+)/i) {
            return unless lc($1) eq 'stsv1';
        } elsif ($line =~ /^mode\s*:\s*(\w+)/i) {
            $policy{mode} = lc($1);
        } elsif ($line =~ /^max_age\s*:\s*(\d+)/i) {
            $policy{max_age} = int($1);
        } elsif ($line =~ /^mx\s*:\s*(.+)/i) {
            (my $mx_val = $1) =~ s/\s+$//;
            push @{$policy{mx}}, $mx_val;
        }
    }

    return unless defined $policy{mode};
    return \%policy;
}

=item md_check_dane_tlsa($domain, $port)

Look up DANE TLSA records for C<_$port._tcp.$domain>.

Returns a list of hashrefs, one per TLSA record, each containing:

=over 4

=item C<usage>

Certificate usage field (0–3).

=item C<selector>

Selector field (0 = full certificate, 1 = SubjectPublicKeyInfo).

=item C<matching_type>

Matching type (0 = exact, 1 = SHA-256, 2 = SHA-512).

=item C<cert_data>

Hex-encoded certificate association data.

=back

Returns an empty list if no TLSA records are found, on lookup error, or
if C<Net::DNS> is not available.

=cut

sub md_check_dane_tlsa {
    my ($domain, $port) = @_;

    unless (defined $domain && $domain ne '') {
        md_syslog('err', 'md_check_dane_tlsa: domain is required');
        return ();
    }
    unless (defined $port && $port =~ /^\d+$/) {
        md_syslog('err', 'md_check_dane_tlsa: numeric port is required');
        return ();
    }
    unless ($Features{"Net::DNS"}) {
        md_syslog('err', 'md_check_dane_tlsa: Net::DNS is not available');
        return ();
    }

    my $res = Net::DNS::Resolver->new;
    $res->defnames(0);

    my $lookup = "_${port}._tcp.$domain";
    my $packet = $res->query($lookup, 'TLSA');

    return () unless defined $packet;
    return () if $packet->header->rcode eq 'NXDOMAIN';
    return () if $packet->header->rcode eq 'SERVFAIL';
    return () unless defined $packet->answer;

    my @records;
    for my $rr ($packet->answer) {
        next unless $rr->type eq 'TLSA';
        push @records, {
            usage         => $rr->usage,
            selector      => $rr->selector,
            matching_type => $rr->matchingtype,
            cert_data     => $rr->cert,
        };
    }
    return @records;
}

=item md_verify_sts_mx($mx_host, $policy)

Returns true if C<$mx_host> matches at least one MX hostname pattern
in C<$policy->{mx}> (a hashref returned by L</md_check_mta_sts($domain [, %opts])>).

Matching follows RFC 8461: a pattern beginning with C<*.> matches any
single DNS label prepended to the rest of the pattern
(e.g. C<*.example.com> matches C<mail.example.com> but not
C<a.b.example.com>).  All comparisons are case-insensitive.

Returns false if C<$policy> is undefined, has no C<mx> list, or no
pattern matches.

=cut

sub md_verify_sts_mx {
    my ($mx_host, $policy) = @_;
    return 0 unless defined $mx_host;
    return 0 unless defined $policy && ref $policy eq 'HASH';
    return 0 unless ref $policy->{mx} eq 'ARRAY';

    ($mx_host = lc $mx_host) =~ s/\.$//;

    for my $pattern (@{$policy->{mx}}) {
        (my $p = lc $pattern) =~ s/\.$//;
        if ($p =~ s/^\*\.//) {
            return 1 if $mx_host =~ /^[^.]+\.\Q$p\E$/;
        } else {
            return 1 if $mx_host eq $p;
        }
    }
    return 0;
}

=item md_verify_dane_cert($cert_der, \@tlsa)

Verify a DER-encoded X.509 certificate against a list of DANE TLSA records
as returned by L</md_check_dane_tlsa($domain, $port)>.

Returns true if the certificate matches at least one record, false otherwise.

Selector 0 (full certificate) requires only C<Digest::SHA>.
Selector 1 (SubjectPublicKeyInfo) additionally requires
C<Crypt::OpenSSL::X509>; records with selector 1 are skipped silently if
that module is not available.

=cut

sub md_verify_dane_cert {
    my ($cert_der, $tlsa) = @_;
    return 0 unless defined $cert_der;
    return 0 unless ref $tlsa eq 'ARRAY' && @$tlsa;

    for my $rec (@$tlsa) {
        my $selector = $rec->{selector}      // next;
        my $mtype    = $rec->{matching_type} // next;
        my $expected = $rec->{cert_data}     // next;

        my $material = _dane_material($cert_der, $selector) or next;
        my $computed = _dane_hash($material, $mtype)        or next;

        return 1 if lc($computed) eq lc($expected);
    }
    return 0;
}

sub _dane_material {
    my ($cert_der, $selector) = @_;
    return $cert_der if $selector == 0;
    return unless $selector == 1;

    local $@;
    eval { require Crypt::OpenSSL::X509 } or return;
    eval { require MIME::Base64 }         or return;

    my $x509 = eval {
        Crypt::OpenSSL::X509->new_from_string($cert_der, Crypt::OpenSSL::X509::FORMAT_ASN1())
    } or return;
    my $pem = eval { $x509->pubkey() } or return;
    $pem =~ s/-----[^\n]+-----\n?//g;
    $pem =~ s/\s+//g;
    return MIME::Base64::decode_base64($pem);
}

sub _dane_hash {
    my ($data, $mtype) = @_;
    return unpack('H*', $data) if $mtype == 0;
    local $@;
    eval { require Digest::SHA } or return;
    return Digest::SHA::sha256_hex($data) if $mtype == 1;
    return Digest::SHA::sha512_hex($data) if $mtype == 2;
    return;
}

sub _init_ua {
    my ($timeout) = @_;
    local $@;
    eval { require LWP::UserAgent; 1 } or do {
        md_syslog('err', 'md_check_mta_sts: LWP::UserAgent is not installed');
        return;
    };
    my $ua = LWP::UserAgent->new(
        agent   => 'MIMEDefang/' . ($Mail::MIMEDefang::VERSION // '3'),
        timeout => $timeout,
    );
    $ua->ssl_opts(verify_hostname => 1);
    return $ua;
}

=back

=cut

1;
