#!/usr/bin/perl
#
# t/async.t - Unit tests for Mail::MIMEDefang::Async
#
# Tests use a mock AnyEvent backend so they work offline.
# Skips automatically when AnyEvent is not installed.
#

use strict;
use warnings;
use lib qw(modules/lib);
use Test::More;

my @required = qw(AnyEvent AnyEvent::DNS AnyEvent::Socket);
for my $mod (@required) {
    eval "require $mod";
    if ($@) {
        plan skip_all => "$mod not installed - run: cpanm $mod";
        exit 0;
    }
}

plan tests => 26;

use Mail::MIMEDefang;

use_ok 'Mail::MIMEDefang::Async';
use_ok 'Mail::MIMEDefang::Async::Checks';
use_ok 'Mail::MIMEDefang::Async::Results';

# Mail::MIMEDefang::Async::Checks

subtest 'md_async_check_dnsbl structure' => sub {
    my $c = md_async_check_dnsbl(ip => '1.2.3.4', zone => 'zen.spamhaus.org');
    is     $c->{type},       'dns',                          'type is dns';
    like   $c->{args}{host}, qr/^4\.3\.2\.1\.zen\.spamhaus/, 'host is reversed-ip.zone';
    is     $c->{args}{type}, 'A',                            'record type is A';
    is     $c->{name},       'dnsbl_zen.spamhaus.org',        'auto-generated name';
};

subtest 'md_async_check_rdns structure' => sub {
    my $c = md_async_check_rdns(ip => '1.2.3.4', name => 'test_rdns');
    is   $c->{type},           'dns',                         'type is dns';
    like $c->{args}{host},     qr/4\.3\.2\.1\.in-addr\.arpa$/, 'PTR hostname correct';
    is   $c->{args}{type},     'PTR',                          'record type is PTR';
};

subtest 'md_async_check_spf_record structure' => sub {
    my $c = md_async_check_spf_record(domain => 'example.com');
    is $c->{type},       'dns',         'type is dns';
    is $c->{args}{host}, 'example.com', 'host is domain';
    is $c->{args}{type}, 'TXT',         'record type is TXT';
};

subtest 'md_async_check_dkim_record structure' => sub {
    my $c = md_async_check_dkim_record(selector => 'sel1', domain => 'example.com');
    is $c->{type},       'dns',                             'type is dns';
    is $c->{args}{host}, 'sel1._domainkey.example.com',    'host is selector._domainkey.domain';
    is $c->{args}{type}, 'TXT',                            'record type is TXT';
};

subtest 'md_async_check_dmarc_record structure' => sub {
    my $c = md_async_check_dmarc_record(domain => 'example.com');
    is $c->{type},       'dns',                 'type is dns';
    is $c->{args}{host}, '_dmarc.example.com',  'host is _dmarc.domain';
    is $c->{args}{type}, 'TXT',                 'record type is TXT';
};

subtest 'md_async_email_is_blacklisted check' => sub {
   SKIP: {
     if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
       skip "Net test disabled", 1
     }
     init_globals;
     $Features{'Digest::SHA'} = 1;
     md_async_init();
     my $res = md_async_email_is_blacklisted('noemail@example.com', 'ebl.msbl.org', 'SHA1');
     is($res, '127.0.0.2');
   }
};

# Mail::MIMEDefang::Async::Results

subtest 'md_async_interpret_dnsbl - not listed' => sub {
    my $r = md_async_interpret_dnsbl(records => undef, zone => 'zen.spamhaus.org');
    is $r->{listed}, 0, 'undef records -> not listed';

    $r = md_async_interpret_dnsbl(records => [], zone => 'zen.spamhaus.org');
    is $r->{listed}, 0, 'empty records -> not listed';
};

subtest 'md_async_interpret_dnsbl - listed' => sub {
    my $r = md_async_interpret_dnsbl(records => ['127.0.0.2'], zone => 'zen.spamhaus.org');
    is $r->{listed}, 1,           'returns listed=1 for hit';
    is $r->{code},   '127.0.0.2', 'captures return code';
    like $r->{reason}, qr/zen/,   'reason contains zen';
};

subtest 'md_async_interpret_dnsbl - error code filtered' => sub {
    my $r = md_async_interpret_dnsbl(records => ['127.255.255.254'], zone => 'zen.spamhaus.org');
    is $r->{listed}, 0, 'DNS error return code 127.255.255.x is not a hit';
};

subtest 'md_async_interpret_dnsbl - with error' => sub {
    my $r = md_async_interpret_dnsbl(error => 'SERVFAIL', zone => 'zen.spamhaus.org');
    is $r->{error}, 1,                'propagates error flag';
    like $r->{reason}, qr/SERVFAIL/,  'reason contains error message';
};

subtest 'md_async_interpret_rdns - no record' => sub {
    my $r = md_async_interpret_rdns(records => undef, ip => '1.2.3.4');
    is $r->{has_rdns}, 0, 'no records -> has_rdns=0';
};

subtest 'md_async_interpret_rdns - dynamic PTR' => sub {
    my $r = md_async_interpret_rdns(records => ['pool-1-2-3-4.example.com'], ip => '1.2.3.4');
    is $r->{has_rdns}, 1, 'has_rdns=1';
    is $r->{dynamic},  1, 'detected dynamic/residential pattern';
};

subtest 'md_async_interpret_rdns - clean PTR' => sub {
    my $r = md_async_interpret_rdns(records => ['mail.example.com'], ip => '1.2.3.4');
    is $r->{has_rdns}, 1,                 'has_rdns=1';
    is $r->{dynamic},  0,                 'clean hostname not flagged as dynamic';
    is $r->{ptr},      'mail.example.com', 'PTR value captured';
};

subtest 'md_async_interpret_spf_txt - has SPF' => sub {
    my $r = md_async_interpret_spf_txt(
        records => ['v=spf1 include:_spf.google.com ~all'],
        domain  => 'example.com',
    );
    is $r->{has_spf}, 1,           'has_spf=1';
    like $r->{record}, qr/^v=spf1/, 'record captured';
};

subtest 'md_async_interpret_spf_txt - no SPF' => sub {
    my $r = md_async_interpret_spf_txt(records => ['some other TXT record'], domain => 'example.com');
    is $r->{has_spf}, 0, 'non-SPF TXT records -> has_spf=0';
};

subtest 'md_async_interpret_dmarc - valid policy' => sub {
    my $r = md_async_interpret_dmarc('v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com');
    is $r->{has_dmarc}, 1,        'has_dmarc=1';
    is $r->{policy},    'reject',  'policy captured';
    is $r->{pct},       '100',     'pct captured';
    like $r->{rua},     qr/dmarc/, 'rua captured';
};

subtest 'md_async_interpret_dmarc - no record' => sub {
    my $r = md_async_interpret_dmarc(undef);
    is $r->{has_dmarc}, 0, 'undef -> has_dmarc=0';
};

subtest 'md_async_interpret_spamassassin' => sub {
    my $raw = "SPAMD/1.1 0 EX_OK\r\nSpam: True ; 8.3 / 5.0\r\nContent-length: 100\r\n\r\n";
    my $r = md_async_interpret_spamassassin(raw => $raw, threshold => 5.0);
    is $r->{is_spam}, 1,   'is_spam=1';
    is $r->{score},   8.3, 'score captured';

    $raw = "SPAMD/1.1 0 EX_OK\r\nSpam: False ; 2.1 / 5.0\r\n\r\n";
    $r = md_async_interpret_spamassassin(raw => $raw, threshold => 5.0);
    is $r->{is_spam}, 0, 'is_spam=0 for clean mail';
};

subtest 'md_async_interpret_clamav' => sub {
    my $r = md_async_interpret_clamav(raw => "PONG\n");
    is $r->{available}, 1, 'PONG -> available';
    is $r->{virus},     0, 'no virus on PONG';

    $r = md_async_interpret_clamav(raw => "stream: Eicar-Test-Signature FOUND\n");
    is $r->{virus}, 1,                      'virus=1 on FOUND';
    is $r->{name},  'Eicar-Test-Signature', 'virus name captured';

    $r = md_async_interpret_clamav(raw => "stream: OK\n");
    is $r->{virus}, 0, 'virus=0 on OK';
};

subtest 'md_async_score_results - reject' => sub {
    my $r = md_async_score_results(
        interpreted => { zen => { listed => 1, reason => 'SBL hit' } },
        weights     => { zen => 8.0 },
        reject_at   => 5.0,
    );
    is $r->{action}, 'REJECT',  'score 8.0 -> REJECT at threshold 5.0';
    ok $r->{score} >= 8.0,      'score is >= 8.0';
};

subtest 'md_async_score_results - pass' => sub {
    my $r = md_async_score_results(
        interpreted => {
            zen => { listed => 0 },
            spf => { has_spf => 1 },
        },
        reject_at => 5.0,
    );
    is $r->{action}, 'PASS', 'clean checks -> PASS';
    is $r->{score},  0,      'score is 0';
};

subtest 'md_async_spam_assassin_check - missing INPUTMSG returns undef' => sub {
    my $orig;
    if (-e './INPUTMSG') {
        open(my $fh, '<', './INPUTMSG') or die;
        local $/;
        $orig = <$fh>;
        close $fh;
        unlink './INPUTMSG';
    }

    my $result = eval { md_async_spam_assassin_check() };
    is $result, undef, 'returns undef when INPUTMSG is missing';

    if (defined $orig) {
        open(my $fh, '>', './INPUTMSG') or die;
        print $fh $orig;
        close $fh;
    }
};

subtest 'Mail::MIMEDefang::Async constructor via md_async_init' => sub {
    my $engine = md_async_init(max_concurrency => 4, global_timeout => 3);
    isa_ok $engine, 'Mail::MIMEDefang::Async';
    is $engine->{max_concurrency}, 4, 'max_concurrency set';
    is $engine->{global_timeout},  3, 'global_timeout set';
};

done_testing();
