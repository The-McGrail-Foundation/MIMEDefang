#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Async::Results - Interpret async check output for MIMEDefang

=head1 DESCRIPTION

Mail::MIMEDefang::Async::Results translates raw output from
C<md_async_run_checks()> into actionable filter decisions (reject, tempfail,
score, pass).

=head1 SYNOPSIS

  use Mail::MIMEDefang::Async::Results;

  my $dnsbl = md_async_interpret_dnsbl(
      records => $result->{results}{zen},
      zone    => 'zen.spamhaus.org',
      error   => $result->{errors}{zen},
  );

  my $score = md_async_score_results(
      interpreted => { zen => $dnsbl },
      reject_at   => 5.0,
  );

  if ($score->{action} eq 'REJECT') {
      return action_bounce("550 5.7.1 " . $score->{reasons}[0]);
  }

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Async::Results;

use strict;
use warnings;
use Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(
    md_async_interpret_dnsbl
    md_async_interpret_spamassassin
    md_async_interpret_clamav
    md_async_interpret_rdns
    md_async_interpret_spf_txt
    md_async_interpret_dmarc
    md_async_score_results
);
our @EXPORT_OK;

our $VERSION = '1.0.0';

=item md_async_interpret_dnsbl(%args)

Interpret a DNSBL result.  Args: C<records> (arrayref or undef), C<zone>,
C<error>.  Returns a hashref with keys C<listed>, C<code>, C<reason>,
and optionally C<error>.

=cut

sub md_async_interpret_dnsbl {
    my (%args) = @_;
    my $records = $args{records};
    my $zone    = $args{zone} // '';
    my $error   = $args{error};

    return { listed => 0, reason => "DNS error: $error", error => 1 } if $error;
    return { listed => 0 } unless defined $records && @$records;

    # skip DNS error codes standard replies
    my @hits = grep { !/^127\.255\.255\./ } @$records;
    return { listed => 0 } unless @hits;

    my $code   = $hits[0];

    return {
        listed => 1,
        code   => $code,
        reason => "Listed in $zone",
    };
}

# SpamAssassin SPAMC response
# Example: "SPAMD/1.1 0 EX_OK\r\nSpam: True ; 8.3 / 5.0\r\n\r\n"

=item md_async_interpret_spamassassin(%args)

Parse a raw SPAMC protocol response. Args: C<raw>, C<error>,
C<threshold> (default 5.0). Returns C<is_spam>, C<score>, C<threshold>,
C<symbols>, C<reason>.

=cut

sub md_async_interpret_spamassassin {
    my (%args) = @_;
    my $raw       = $args{raw};
    my $error     = $args{error};
    my $threshold = $args{threshold} // 5.0;

    return { error => 1, reason => "SpamAssassin error: $error" }   if $error;
    return { error => 1, reason => "No response from spamd" }       unless defined $raw;

    my %result = (
        is_spam   => 0,
        score     => 0,
        threshold => $threshold,
        symbols   => [],
    );

    if ($raw =~ /(?:^|\r?\n)Spam:\s*(True|False|Yes|No)\s*;\s*([\d.]+)\s*\/\s*([\d.]+)/i) {
        my ($flag, $score_val, $thresh_val) = ($1, $2, $3);
        $result{is_spam}   = ($flag =~ /^(True|Yes)$/i) ? 1 : 0;
        $result{score}     = $score_val  + 0;
        $result{threshold} = $thresh_val + 0;
    }

    if ($raw =~ /X-Spam-Status:.*?tests=([\w,\s_]+)/i) {
        $result{symbols} = [ split /,\s*/, $1 ];
    }

    $result{reason} = $result{is_spam}
        ? sprintf("SpamAssassin score %.1f exceeds threshold %.1f", $result{score}, $result{threshold})
        : sprintf("SpamAssassin score %.1f (clean)", $result{score});

    return \%result;
}

# ─────────────────────────────────────────────────────────────
# ClamAV
# ─────────────────────────────────────────────────────────────

=item md_async_interpret_clamav(%args)

Interpret a clamd PING or INSTREAM response. Args: C<raw>, C<error>.
Returns C<available>, C<virus>, C<name>, C<reason>.

=cut

sub md_async_interpret_clamav {
    my (%args) = @_;
    my $raw   = $args{raw};
    my $error = $args{error};

    return { error => 1, reason => "ClamAV error: $error" }    if $error;
    return { error => 1, reason => "No response from clamd" }  unless defined $raw;

    return { available => 1, virus => 0, reason => 'ClamAV daemon online' }
        if $raw =~ /PONG/i;

    if ($raw =~ /stream:\s*(.+?)\s+FOUND/i) {
        return { virus => 1, name => $1, reason => "Virus detected: $1" };
    }
    if ($raw =~ /stream:\s*OK/i) {
        return { virus => 0, reason => 'Clean' };
    }
    if ($raw =~ /ERROR/) {
        return { error => 1, reason => "ClamAV scan error: $raw" };
    }

    return { virus => 0, reason => 'Unknown ClamAV response', raw => $raw };
}

# Reverse DNS (PTR)

=item md_async_interpret_rdns(%args)

Interpret a PTR record result.  Args: C<records>, C<error>, C<ip>.
Returns C<has_rdns>, C<ptr>, C<dynamic>, C<reason>.

=cut

sub md_async_interpret_rdns {
    my (%args) = @_;
    my $records = $args{records};
    my $error   = $args{error};
    my $ip      = $args{ip} // '';

    return { has_rdns => 0, reason => "rDNS lookup error: $error" }   if $error;
    return { has_rdns => 0, reason => "No PTR record for $ip" }
        unless defined $records && @$records;

    my $ptr = $records->[0];
    my $suspicious =
        ($ptr =~ /\b(\d{1,3}[._-]\d{1,3}[._-]\d{1,3}[._-]\d{1,3})\b/) ||
        ($ptr =~ /\b(dsl|dialup|dynamic|cable|pool|dhcp|ppp|broadband)\b/i);

    return {
        has_rdns => 1,
        ptr      => $ptr,
        dynamic  => $suspicious ? 1 : 0,
        reason   => $suspicious
            ? "Dynamic/residential PTR: $ptr"
            : "Valid PTR: $ptr",
    };
}

# SPF TXT record existence

=item md_async_interpret_spf_txt(%args)

Check whether a TXT record lookup returned an SPF record.  Args: C<records>,
C<error>, C<domain>.  Returns C<has_spf>, C<record>, C<reason>.

=cut

sub md_async_interpret_spf_txt {
    my (%args) = @_;
    my $records = $args{records};
    my $error   = $args{error};
    my $domain  = $args{domain} // '';

    return { has_spf => 0, reason => "SPF lookup error: $error" }
        if $error;
    return { has_spf => 0, reason => "No TXT records for $domain" }
        unless defined $records && @$records;

    my @spf = grep { /^v=spf1/i } @$records;
    return { has_spf => 0, reason => "No SPF record for $domain" } unless @spf;

    return {
        has_spf => 1,
        record  => $spf[0],
        reason  => "SPF record found for $domain",
    };
}

# DMARC TXT record

=item md_async_interpret_dmarc($raw)

Parse a raw DMARC TXT policy string (as returned by
C<md_async_dmarc_verify()> or from the C<records> of
C<md_async_check_dmarc_record()>).

Returns a hashref with keys: C<has_dmarc>, C<policy>, C<subdomain_policy>,
C<pct>, C<rua>, C<ruf>, C<adkim>, C<aspf>, C<reason>.

=cut

sub md_async_interpret_dmarc {
    my ($raw) = @_;

    unless (defined $raw && $raw =~ /^v=DMARC1/i) {
        return { has_dmarc => 0, reason => 'No DMARC record' };
    }

    my %tags;
    for my $pair (split /\s*;\s*/, $raw) {
        my ($k, $v) = split /\s*=\s*/, $pair, 2;
        $tags{ lc($k) } = $v if defined $k && defined $v;
    }

    return {
        has_dmarc        => 1,
        policy           => $tags{p}   // 'none',
        subdomain_policy => $tags{sp}  // $tags{p} // 'none',
        pct              => $tags{pct} // 100,
        rua              => $tags{rua} // '',
        ruf              => $tags{ruf} // '',
        adkim            => $tags{adkim} // 'r',
        aspf             => $tags{aspf}  // 'r',
        reason           => "DMARC policy: " . ($tags{p} // 'none'),
    };
}

# Composite scorer

=item md_async_score_results(%args)

Tally individual interpreted check results into a weighted spam score.
Args: C<interpreted> (hashref of name->interp result), C<weights> (optional
override), C<reject_at> (default 8.0), C<tempfail_at> (default 12.0).

Returns C<{ score, action, reasons }> where C<action> is one of
C<'PASS'>, C<'REJECT'>, C<'TEMPFAIL'>.

=cut

sub md_async_score_results {
    my (%args) = @_;
    my $interpreted = $args{interpreted} // {};
    my $weights     = { %{ $args{weights} // {} } };
    my $reject_at   = $args{reject_at}   // 8.0;
    my $tempfail_at = $args{tempfail_at} // 12.0;

    my $total   = 0;
    my @reasons;

    for my $name (keys %$interpreted) {
        my $r = $interpreted->{$name};
        next unless ref $r eq 'HASH';
        next if $r->{error};

        my $w = $weights->{$name} // 0;

        if ($r->{listed}) {
            $total += $w;
            push @reasons, "[$name] $r->{reason} (+$w)";
        }
        elsif (exists $r->{is_spam} && $r->{is_spam}) {
            my $delta = $r->{score} - $r->{threshold};
            my $add   = $w * $delta;
            $total += $add;
            push @reasons, sprintf("[spamassassin] score %.1f over threshold (+%.2f)", $r->{score}, $add);
        }
        elsif ($r->{virus}) {
            $total += $w;
            push @reasons, "[clamav] $r->{reason} (+$w)";
        }
        elsif ($name =~ /rdns/ && !$r->{has_rdns}) {
            $total += $w;
            push @reasons, "[rdns_missing] No PTR record (+$w)";
        }
        elsif ($name =~ /rdns/ && $r->{dynamic}) {
            $total += $w;
            push @reasons, "[rdns_dynamic] $r->{reason} (+$w)";
        }
        elsif ($name =~ /spf/ && !$r->{has_spf}) {
            $total += $w;
            push @reasons, "[no_spf] $r->{reason} (+$w)";
        }
    }

    my $action =
        $total >= $tempfail_at ? 'TEMPFAIL' :
        $total >= $reject_at   ? 'REJECT'   :
                                 'PASS';

    return {
        score   => $total,
        action  => $action,
        reasons => \@reasons,
    };
}

=back

=head1 SEE ALSO

L<Mail::MIMEDefang::Async>, L<Mail::MIMEDefang::Async::Checks>

=cut

1;
