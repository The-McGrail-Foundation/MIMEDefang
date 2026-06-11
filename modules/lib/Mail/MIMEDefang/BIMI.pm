#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::BIMI - Brand Indicators for Message Identification support for MIMEDefang

=head1 DESCRIPTION

Mail::MIMEDefang::BIMI provides methods to look up and verify BIMI DNS records
from F<mimedefang-filter>. BIMI (Brand Indicators for Message Identification)
allows domain owners to publish a verified logo that mail clients can display
alongside authenticated messages.

A BIMI record is only considered valid when the sending domain passes DMARC
at enforcement level (C<p=quarantine> or C<p=reject>).

When the C<Mail::BIMI> Perl module is installed, C<md_bimi_lookup> and
C<md_bimi_verify> use it for richer validation, including SVG logo integrity
and Verified Mark Certificate (VMC) chain verification. Without C<Mail::BIMI>
the checks are limited to DNS record existence and a non-empty C<l=> tag.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::BIMI;

use strict;
use warnings;

require Exporter;

use Mail::MIMEDefang;
use Net::DNS;

our @ISA = qw(Exporter);
our @EXPORT = qw(md_bimi_lookup md_bimi_verify);
our @EXPORT_OK = qw(md_init);

=item md_init

Detect and load C<Mail::BIMI> if installed, setting C<$Features{"Mail::BIMI"}>.
Called automatically by C<detect_and_load_perl_modules> in C<Mail::MIMEDefang>.

=cut

sub md_init {
  local $@;
  eval { require Mail::BIMI };
  if ($@) {
    $Features{"Mail::BIMI"} = 0;
  } else {
    Mail::BIMI->import();
    $Features{"Mail::BIMI"} = 1;
  }
}

=item md_bimi_lookup($domain)

Look up the BIMI DNS TXT record for C<$domain>.

Returns a hashref with the following keys on success:

=over 4

=item C<version>

Always C<BIMI1>.

=item C<l>

The URL of the SVG logo (C<l=> tag).

=item C<a>

The URL of the Verified Mark Certificate (C<a=> tag), if present.

=item C<raw>

The raw TXT record string.

=back

Returns C<undef> if no BIMI record is found or if C<Net::DNS> is not available.

=cut

sub md_bimi_lookup {
  my ($domain) = @_;

  unless (defined $domain && $domain ne '') {
    md_syslog('err', 'md_bimi_lookup: domain is required');
    return;
  }

  if ($Features{"Mail::BIMI"}) {
    local $@;
    my $result = eval {
      my $bimi_obj = Mail::BIMI->new(domain => $domain, selector => 'default');
      my $record   = $bimi_obj->record;
      return unless $record && !$record->is_error;
      my %rec = (version => 'BIMI1');
      $rec{l} = $record->l_value->value if $record->l_value;
      $rec{a} = $record->a_value->value if $record->a_value;
      $rec{raw} = join('', $record->value // '');
      return \%rec;
    };
    return $result unless $@;
    md_syslog('err', "md_bimi_lookup: Mail::BIMI error: $@");
    return;
  }

  unless ($Features{"Net::DNS"}) {
    md_syslog('err', 'md_bimi_lookup: Net::DNS is not available');
    return;
  }

  my $res = Net::DNS::Resolver->new;
  $res->defnames(0);

  my $lookup = 'default._bimi.' . $domain;
  my $packet = $res->query($lookup, 'TXT');

  if (!defined($packet) ||
      $packet->header->rcode eq 'NXDOMAIN' ||
      $packet->header->rcode eq 'SERVFAIL' ||
      !defined($packet->answer)) {
    return;
  }

  for my $rr ($packet->answer) {
    next unless $rr->type eq 'TXT';
    my $txt = $rr->rdstring;
    $txt =~ s/^"|"$//g;
    $txt =~ s/"\s*"//g;

    next unless $txt =~ /^v=BIMI1\b/i;

    my %record = (raw => $txt, version => 'BIMI1');

    if ($txt =~ /\bl=([^;]+)/) {
      ($record{l} = $1) =~ s/\s+$//;
    }
    if ($txt =~ /\ba=([^;]+)/) {
      ($record{a} = $1) =~ s/\s+$//;
    }

    return \%record;
  }

  return;
}

=item md_bimi_verify($domain, $dmarc_result, $dmarc_policy)

Verify that a domain's BIMI record is valid given the DMARC result.

BIMI is only considered to pass when:

=over 4

=item *

A BIMI DNS record exists for C<$domain>.

=item *

C<$dmarc_result> is C<pass>.

=item *

C<$dmarc_policy> is C<quarantine> or C<reject> (enforcement level).

=item *

The BIMI record contains a non-empty C<l=> (logo URL) tag.

=back

Returns C<"pass"> on success, C<"fail"> otherwise.

The method accepts the following parameters:

=over 4

=item C<$domain>

The sender's domain (From: header domain).

=item C<$dmarc_result>

The DMARC result string, e.g. C<"pass"> or C<"fail">.

=item C<$dmarc_policy>

The DMARC policy in effect: C<"none">, C<"quarantine">, or C<"reject">.

=back

=cut

sub md_bimi_verify {
  my ($domain, $dmarc_result, $dmarc_policy) = @_;

  return 'fail' unless defined $domain && $domain ne '';
  return 'fail' unless defined $dmarc_result && lc($dmarc_result) eq 'pass';
  return 'fail' unless defined $dmarc_policy &&
                       (lc($dmarc_policy) eq 'quarantine' ||
                        lc($dmarc_policy) eq 'reject');

  if ($Features{"Mail::BIMI"}) {
    local $@;
    my $valid = eval {
      my $bimi_obj = Mail::BIMI->new(domain => $domain, selector => 'default');
      my $record   = $bimi_obj->record;
      return 0 unless $record;
      return $record->is_valid ? 1 : 0;
    };
    if ($@) {
      md_syslog('err', "md_bimi_verify: Mail::BIMI error: $@");
      return 'fail';
    }
    return $valid ? 'pass' : 'fail';
  }

  my $bimi = md_bimi_lookup($domain);
  return 'fail' unless defined $bimi;
  return 'fail' unless defined $bimi->{l} && $bimi->{l} ne '';

  return 'pass';
}

=back

=cut

1;
