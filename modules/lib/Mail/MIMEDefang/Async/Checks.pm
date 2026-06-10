#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Async::Checks - Pre-built check descriptors for Mail::MIMEDefang::Async

=head1 DESCRIPTION

Each function returns a check-hashref suitable for passing to
C<md_async_run_checks()>. Mix and match to build the checks your filter needs.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Async::Checks;

use strict;
use warnings;
use Exporter;

use Mail::MIMEDefang::Net qw(reverse_ip_address_for_rbl);

our @ISA = qw(Exporter);
our @EXPORT = qw(
    md_async_check_dnsbl
    md_async_check_spf_record
    md_async_check_mx_exists
    md_async_check_rdns
    md_async_check_dkim_record
    md_async_check_dmarc_record
);
our @EXPORT_OK;

our $VERSION = '1.0.0';

# DNS-based checks

=item md_async_check_dnsbl(%args)

Build a DNSBL A-record lookup check. Required args: C<ip>, C<zone>.
Optional: C<name>, C<timeout>.

=cut

sub md_async_check_dnsbl {
    my (%args) = @_;
    my $ip   = $args{ip}   // die "md_async_check_dnsbl: ip required";
    my $zone = $args{zone} // die "md_async_check_dnsbl: zone required";
    my $name = $args{name} // "dnsbl_${zone}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => reverse_ip_address_for_rbl($ip) . ".${zone}",
            type    => 'A',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_spf_record(%args)

Build an SPF TXT-record lookup check. Required: C<domain>.

=cut

sub md_async_check_spf_record {
    my (%args) = @_;
    my $domain = $args{domain} // die "md_async_check_spf_record: domain required";
    my $name   = $args{name}   // "spf_${domain}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => $domain,
            type    => 'TXT',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_mx_exists(%args)

Build an MX-record existence check. Domains with no MX are often forged.
Required: C<domain>.

=cut

sub md_async_check_mx_exists {
    my (%args) = @_;
    my $domain = $args{domain} // die "md_async_check_mx_exists: domain required";
    my $name   = $args{name}   // "mx_${domain}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => $domain,
            type    => 'MX',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_rdns(%args)

Build a reverse-DNS (PTR) lookup check. Required: C<ip>.

=cut

sub md_async_check_rdns {
    my (%args) = @_;
    my $ip   = $args{ip}   // die "md_async_check_rdns: ip required";
    my $name = $args{name} // "rdns_${ip}";

    my $suffix = ($ip =~ /:/) ? '.ip6.arpa' : '.in-addr.arpa';

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => reverse_ip_address_for_rbl($ip) . $suffix,
            type    => 'PTR',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_dkim_record(%args)

Build an async lookup for a DKIM public-key TXT record at
C<$selector._domainkey.$domain>. Required: C<selector>, C<domain>.

The result is the raw TXT record string. Signature evaluation still happens
synchronously via C<Mail::DKIM> after the key is fetched.

=cut

sub md_async_check_dkim_record {
    my (%args) = @_;
    my $selector = $args{selector} // die "md_async_check_dkim_record: selector required";
    my $domain   = $args{domain}   // die "md_async_check_dkim_record: domain required";
    my $name     = $args{name}     // "dkim_${selector}._domainkey.${domain}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => "${selector}._domainkey.${domain}",
            type    => 'TXT',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_dmarc_record(%args)

Build an async lookup for the DMARC TXT record at C<_dmarc.$domain>.
Required: C<domain>.

Use C<md_async_interpret_dmarc()> from L<Mail::MIMEDefang::Async::Results> to
parse the result.

=cut

sub md_async_check_dmarc_record {
    my (%args) = @_;
    my $domain = $args{domain} // die "md_async_check_dmarc_record: domain required";
    my $name   = $args{name}   // "dmarc_${domain}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => "_dmarc.${domain}",
            type    => 'TXT',
            timeout => $args{timeout} // 5,
        },
    };
}

=back

=head1 SEE ALSO

L<Mail::MIMEDefang::Async>, L<Mail::MIMEDefang::Async::Results>

=cut

1;
