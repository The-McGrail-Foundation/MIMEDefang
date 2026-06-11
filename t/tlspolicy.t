package Mail::MIMEDefang::Unit::TLSPolicy;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;

init_globals;
$Features{"Net::DNS"} = 1;

use Mail::MIMEDefang::TLSPolicy;

# ---------------------------------------------------------------------------
# md_verify_sts_mx - unit tests (no network)
# ---------------------------------------------------------------------------

sub t_verify_sts_mx_exact : Test(3)
{
    my $policy = { mx => ['mail.example.com', 'smtp.example.com'] };
    ok( md_verify_sts_mx('mail.example.com',  $policy), 'exact match');
    ok( md_verify_sts_mx('MAIL.EXAMPLE.COM',  $policy), 'case-insensitive match');
    ok(!md_verify_sts_mx('other.example.com', $policy), 'no match');
}

sub t_verify_sts_mx_wildcard : Test(3)
{
    my $policy = { mx => ['*.example.com'] };
    ok( md_verify_sts_mx('mail.example.com',    $policy), 'wildcard single label');
    ok(!md_verify_sts_mx('a.b.example.com',     $policy), 'wildcard does not span two labels');
    ok(!md_verify_sts_mx('example.com',         $policy), 'wildcard does not match bare domain');
}

sub t_verify_sts_mx_edge : Test(3)
{
    ok(!md_verify_sts_mx(undef,           { mx => ['mail.example.com'] }), 'undef host');
    ok(!md_verify_sts_mx('mail.example.com', undef),                       'undef policy');
    ok(!md_verify_sts_mx('mail.example.com', { mx => [] }),                'empty mx list');
}

# ---------------------------------------------------------------------------
# md_verify_dane_cert - unit tests (selector=0, no real cert needed)
# ---------------------------------------------------------------------------

sub t_verify_dane_cert_exact : Test(2)
{
    my $der  = "fake der bytes";
    my $hex  = unpack('H*', $der);
    my @tlsa = ({ selector => 0, matching_type => 0, cert_data => $hex });
    ok( md_verify_dane_cert($der, \@tlsa), 'exact match (matching_type=0)');
    $tlsa[0]{cert_data} = 'deadbeef';
    ok(!md_verify_dane_cert($der, \@tlsa), 'exact mismatch');
}

sub t_verify_dane_cert_sha : Test(4)
{
    SKIP: {
        eval { require Digest::SHA; 1 }
            or skip 'Digest::SHA not available', 4;

        my $der    = "fake der bytes";
        my $sha256 = Digest::SHA::sha256_hex($der);
        my $sha512 = Digest::SHA::sha512_hex($der);

        ok( md_verify_dane_cert($der,
                [{ selector => 0, matching_type => 1, cert_data => $sha256 }]),
            'SHA-256 match');
        ok(!md_verify_dane_cert($der,
                [{ selector => 0, matching_type => 1, cert_data => 'aa' x 32 }]),
            'SHA-256 mismatch');
        ok( md_verify_dane_cert($der,
                [{ selector => 0, matching_type => 2, cert_data => $sha512 }]),
            'SHA-512 match');
        ok(!md_verify_dane_cert($der,
                [{ selector => 0, matching_type => 2, cert_data => 'bb' x 64 }]),
            'SHA-512 mismatch');
    };
}

sub t_verify_dane_cert_edge : Test(3)
{
    ok(!md_verify_dane_cert(undef, [{ selector => 0, matching_type => 0, cert_data => 'aa' }]),
        'undef cert');
    ok(!md_verify_dane_cert('cert', []),
        'empty tlsa list');
    ok(!md_verify_dane_cert('cert',
            [{ selector => 0, matching_type => 99, cert_data => 'aa' }]),
        'unknown matching_type skipped');
}

# ---------------------------------------------------------------------------
# Live network tests
# ---------------------------------------------------------------------------

sub t_mta_sts_live : Test(3)
{
    SKIP: {
        if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
            skip "Net test disabled", 3;
        }
        eval { require LWP::UserAgent; 1 }
            or skip "LWP::UserAgent not available", 3;

        # gmail.com publishes MTA-STS
        my $res = md_check_mta_sts('gmail.com');
        ok(defined $res,            'gmail.com has an MTA-STS policy');
        ok(defined $res->{mode},    'mode is defined');
        ok(defined $res->{max_age}, 'max_age is defined');
    };
}

sub t_dane_live : Test(2)
{
    SKIP: {
        if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
            skip "Net test disabled", 2;
        }
        # nlnetlabs.nl is the DNS research organisation that developed DANE
        my @records = md_check_dane_tlsa('nlnetlabs.nl', 25);
        ok(scalar @records > 0, 'nlnetlabs.nl has TLSA records for port 25');
        ok(exists $records[0]{usage}, 'TLSA record has usage field');
    };
}

__PACKAGE__->runtests();
