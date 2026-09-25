#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::BIMI - Brand Indicators for Message Identification support for MIMEDefang

=encoding utf8

=head1 DESCRIPTION

Mail::MIMEDefang::BIMI provides methods to look up and verify BIMI DNS records
from F<mimedefang-filter>. BIMI (Brand Indicators for Message Identification)
allows domain owners to publish a verified logo that mail clients can display
alongside authenticated messages.

A BIMI record is only considered valid when the sending domain passes DMARC
at enforcement level (C<p=quarantine> or C<p=reject>).

When the C<Mail::BIMI> Perl module (version 3.x or later) is installed,
C<md_bimi_lookup> and C<md_bimi_verify> use it for richer validation,
including SVG logo integrity and Verified Mark Certificate (VMC) chain
verification. Without C<Mail::BIMI> the checks are limited to DNS record
existence and a non-empty C<l=> tag.

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
our @EXPORT = qw(md_bimi_lookup md_bimi_verify md_bimi_get_selector);
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

sub _validate_selector {
  my ($sel) = @_;
  $sel //= 'default';
  unless ($sel =~ /\A[A-Za-z0-9-]+\z/) {
    md_syslog('err', "md_bimi: invalid selector '$sel', using 'default'");
    return 'default';
  }
  return $sel;
}

=item md_bimi_get_selector($entity)

Extract the BIMI selector from the C<BIMI-Selector> header of a
C<MIME::Entity> object.  The header format is:

  BIMI-Selector: v=BIMI1; s=brand1;

Returns the selector string (e.g. C<"brand1">) on success, or C<"default">
when the header is absent, malformed, or C<$entity> is undefined.

Typical usage in C<filter_begin($entity)>:

  my $selector = md_bimi_get_selector($entity);
  my $result   = md_bimi_verify($domain, $dmarc_result, $policy, $selector);

=cut

sub md_bimi_get_selector {
  my ($entity) = @_;
  return 'default' unless defined $entity;
  my $hdr = $entity->head->get('BIMI-Selector') // '';
  chomp $hdr;
  if ($hdr =~ /\bv=BIMI1\b/i && $hdr =~ /\bs=([A-Za-z0-9-]+)/i) {
    return $1;
  }
  return 'default';
}

=item md_bimi_lookup($domain [, $selector])

Look up the BIMI DNS TXT record for C<$domain>.

The optional C<$selector> argument specifies which BIMI selector to query
(e.g. C<"brand1"> → C<brand1._bimi.$domain>).  When omitted or C<undef>,
C<"default"> is used.  Use C<md_bimi_get_selector> to derive the selector
from the message's C<BIMI-Selector> header.

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
  my ($domain, $selector) = @_;
  $selector = _validate_selector($selector);

  unless (defined $domain && $domain ne '') {
    md_syslog('err', 'md_bimi_lookup: domain is required');
    return;
  }

  if ($Features{"Mail::BIMI"}) {
    local $@;
    my $result = eval {
      my $bimi_obj = Mail::BIMI->new(domain => $domain, selector => $selector);
      my $record  = $bimi_obj->record;
      return unless $record;
      my $hashref = $record->record_hashref // {};
      return unless %$hashref;
      my %rec = (version => 'BIMI1');
      $rec{l} = $hashref->{l} if defined $hashref->{l};
      $rec{a} = $hashref->{a} if defined $hashref->{a};
      $rec{raw} = $record->retrieved_record // '';
      return \%rec;
    };
    return $result unless $@;
    md_syslog('err', "md_bimi_lookup: Mail::BIMI error: $@");
    return;
  }

  my ($record) = _bimi_dns_lookup($domain, $selector);
  return $record;
}

# Query the BIMI TXT record with Net::DNS.
# Returns ($record_hashref, 'ok'), (undef, 'none') when no BIMI record
# exists, or (undef, 'temperror') on DNS errors.
sub _bimi_dns_lookup {
  my ($domain, $selector) = @_;

  unless ($Features{"Net::DNS"}) {
    md_syslog('err', 'md_bimi_lookup: Net::DNS is not available');
    return (undef, 'temperror');
  }

  my $res = Net::DNS::Resolver->new;
  $res->defnames(0);

  my $lookup = $selector . '._bimi.' . $domain;
  my $packet = $res->send($lookup, 'TXT');

  return (undef, 'temperror') unless defined $packet;
  my $rcode = $packet->header->rcode;
  return (undef, 'none') if $rcode eq 'NXDOMAIN';
  return (undef, 'temperror') unless $rcode eq 'NOERROR';

  for my $rr ($packet->answer) {
    next unless $rr->type eq 'TXT';
    my $txt = $rr->rdstring;
    $txt =~ s/^"|"$//g;
    $txt =~ s/"\s*"//g;

    next unless $txt =~ /^v=BIMI1\b/i;

    my %record = (raw => $txt, version => 'BIMI1');

    if ($txt =~ /\bl=([^;]*)/) {
      ($record{l} = $1) =~ s/\s+$//;
    }
    if ($txt =~ /\ba=([^;]+)/) {
      ($record{a} = $1) =~ s/\s+$//;
    }

    return (\%record, 'ok');
  }

  return (undef, 'none');
}

=item md_bimi_verify($domain, $dmarc_result, $dmarc_policy [, $selector])

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

Returns one of the BIMI C<Authentication-Results> result values:

=over 4

=item C<pass>

A valid BIMI record was found.

=item C<none>

The domain does not publish a BIMI record.

=item C<declined>

The domain publishes a BIMI record with an empty C<l=> tag.

=item C<skipped>

The message does not pass DMARC, or the DMARC policy is not at enforcement.

=item C<temperror>

A temporary error (e.g. DNS failure) prevented the lookup.

=item C<fail>

The BIMI record, logo or certificate is invalid.

=back

The method accepts the following parameters:

=over 4

=item C<$domain>

The sender's domain (From: header domain).

=item C<$dmarc_result>

The DMARC result string, e.g. C<"pass"> or C<"fail">.

=item C<$dmarc_policy>

The DMARC policy in effect: C<"none">, C<"quarantine">, or C<"reject">.

=item C<$selector>

Optional BIMI selector string.  Defaults to C<"default">.  Pass the value
returned by C<md_bimi_get_selector($entity)> to honour the message's
C<BIMI-Selector> header.

=back

=cut

sub md_bimi_verify {
  my ($domain, $dmarc_result, $dmarc_policy, $selector) = @_;
  $selector = _validate_selector($selector);

  return 'fail' unless defined $domain && $domain ne '';
  return 'skipped' unless defined $dmarc_result && lc($dmarc_result) eq 'pass';
  return 'skipped' unless defined $dmarc_policy &&
                          (lc($dmarc_policy) eq 'quarantine' ||
                           lc($dmarc_policy) eq 'reject');

  if ($Features{"Mail::BIMI"}) {
    local $@;
    my $result = eval {
      my $bimi_obj = Mail::BIMI->new(domain => $domain, selector => $selector);
      my $record   = $bimi_obj->record;
      return 'fail' unless $record;
      return 'pass' if $record->is_valid;
      my ($err) = @{ $record->errors // [] };
      return defined $err ? $err->result : 'fail';
    };
    if ($@) {
      md_syslog('err', "md_bimi_verify: Mail::BIMI error: $@");
      return 'fail';
    }
    return $result;
  }

  my ($bimi, $status) = _bimi_dns_lookup($domain, $selector);
  return $status unless defined $bimi;
  return 'fail' unless defined $bimi->{l};
  return 'declined' if $bimi->{l} eq '';

  return 'pass';
}

=back

=cut

1;
