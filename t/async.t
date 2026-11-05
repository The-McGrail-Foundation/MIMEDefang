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

plan tests => 33;

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

subtest 'md_async_message_contains_virus_clamd - short replies' => sub {
    require AnyEvent::Handle;
    require File::Temp;
    require IO::Socket::UNIX;
    require POSIX;
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $n = 0;
    for my $c (["x: OK\n",                 [0, 'ok', 'ok']],
               ["x: Eicar-Test FOUND\n",   [1, 'virus', 'quarantine']],
               ["x: Access denied. ERROR\n", [999, 'swerr', 'tempfail']],
               ["UNKNOWN COMMAND\n",       [0, 'ok', 'ok']]) {
        my ($reply, $expected) = @$c;
        my $sock = "$dir/clamd" . $n++ . '.sock';
        my $srv = IO::Socket::UNIX->new(Local => $sock, Listen => 1) or die "listen: $!";
        my $pid = fork() // die "fork: $!";
        if (!$pid) {
            alarm 10;
            my $conn = $srv->accept or POSIX::_exit(0);
            my $req = <$conn>;
            print $conn $reply;
            close $conn;
            POSIX::_exit(0);
        }
        close $srv;
        init_globals();
        $CWD = $dir;
        md_async_init(global_timeout => 5);
        my @got = md_async_message_contains_virus_clamd($sock);
        waitpid($pid, 0);
        (my $shown = $reply) =~ s/\n/\\n/g;
        is_deeply \@got, $expected, "reply '$shown'";
    }
};

subtest 'md_async_check_clamd structure' => sub {
    my $c = md_async_check_clamd(sock => '/run/clamd.sock', path => '/tmp/x/Work');
    is $c->{name},              'clamd',             'default name';
    is $c->{type},              'socket',            'type is socket';
    is $c->{args}{unix_path},   '/run/clamd.sock',   'unix socket path';
    is $c->{args}{request},     "nSCAN /tmp/x/Work\n", 'nSCAN request';
    is $c->{args}{timeout},     30,                  'default timeout';

    $c = md_async_check_clamd(sock => '10.0.0.1:3310', name => 'av1', timeout => 9);
    is $c->{name},         'av1',      'custom name';
    is $c->{args}{host},   '10.0.0.1', 'tcp host';
    is $c->{args}{port},   '3310',     'tcp port';
    is $c->{args}{timeout}, 9,         'custom timeout';

    my $saved_cwd = $CWD;
    $CWD = undef;
    ok !eval { md_async_check_clamd(sock => '/run/clamd.sock'); 1 }, 'dies without path and $CWD';
    $CWD = $saved_cwd;
};

subtest 'md_async_check_clamdscan structure' => sub {
    local $Features{'Virus:CLAMDSCAN'};
    ok !eval { md_async_check_clamdscan(); 1 }, 'dies when clamdscan is not installed';

    $Features{'Virus:CLAMDSCAN'} = '/usr/bin/clamdscan';
    my $c = md_async_check_clamdscan(conf => '/etc/clamd.conf', path => '/tmp/x/Work');
    is $c->{name}, 'clamdscan', 'default name';
    is $c->{type}, 'process',   'type is process';
    is_deeply $c->{args}{cmd},
        ['/usr/bin/clamdscan', '-c', '/etc/clamd.conf', '--no-summary', '--infected',
         '--fdpass', '--stream', '/tmp/x/Work'],
        'clamdscan argv';
    is $c->{args}{timeout}, 60, 'default timeout';

    my $saved_cwd = $CWD;
    $CWD = undef;
    ok !eval { md_async_check_clamdscan(); 1 }, 'dies without path and $CWD';
    like $@, qr/no path given/,                 'clamdscan error message';
    $CWD = $saved_cwd;
};

subtest 'md_async_check_spamc / md_async_check_rspamd structure' => sub {
    require Cwd;
    require File::Temp;
    my $orig = Cwd::getcwd();
    my $dir  = File::Temp::tempdir(CLEANUP => 1);
    chdir $dir or die "chdir: $!";

    ok !eval { md_async_check_spamc(); 1 },  'spamc dies without INPUTMSG';
    like $@, qr/cannot open INPUTMSG/,       'spamc error message';
    ok !eval { md_async_check_rspamd(); 1 }, 'rspamd dies without INPUTMSG';

    open(my $fh, '>', 'INPUTMSG') or die;
    print $fh "Subject: test\n\nbody\n";
    close $fh;

    init_globals();
    $Sender = '<sender@example.com>';
    my $c = md_async_check_spamc(port => 1783, user => 'defang');
    is $c->{name},         'spamc',     'spamc default name';
    is $c->{type},         'socket',    'spamc type is socket';
    is $c->{args}{host},   '127.0.0.1', 'spamc default host';
    is $c->{args}{port},   1783,        'spamc custom port';
    like $c->{args}{request}, qr/\ACHECK SPAMC\/1\.5\r\nContent-length: \d+\r\nUser: defang\r\n\r\n/,
        'spamc request header';
    like $c->{args}{request}, qr/^Return-Path: <sender\@example\.com>$/m, 'Return-Path added';
    like $c->{args}{request}, qr/Subject: test\n\nbody\n\z/,             'message body sent';
    my ($len) = $c->{args}{request} =~ /Content-length: (\d+)/;
    my ($msg) = $c->{args}{request} =~ /\r\n\r\n(.*)\z/s;
    is $len, length($msg), 'Content-length matches the message';

    $c = md_async_check_rspamd(uri => 'http://rspamd.example:11334');
    is $c->{name},       'rspamd',         'rspamd default name';
    is $c->{args}{host}, 'rspamd.example', 'rspamd host from uri';
    is $c->{args}{port}, 11334,            'rspamd port from uri';
    like $c->{args}{request}, qr/\APOST \/checkv2 HTTP\/1\.0\r\n/, 'rspamd request line';

    chdir $orig or die "chdir: $!";
};

subtest 'md_async_interpret_clamav - nSCAN and clamdscan results' => sub {
    my $r = md_async_interpret_clamav(raw => "/var/spool/MIMEDefang/mdefang-x/Work/PART1: Eicar-Test-Signature FOUND\n");
    is $r->{virus}, 1,                      'nSCAN FOUND -> virus';
    is $r->{name},  'Eicar-Test-Signature', 'nSCAN virus name';

    $r = md_async_interpret_clamav(raw => "/w/PART1: OK\n/w/PART2: Win.Test.A FOUND\n/w/PART3: Win.Test.B FOUND\n");
    is $r->{virus}, 1,                            'multi-file reply -> virus';
    is_deeply $r->{names}, ['Win.Test.A', 'Win.Test.B'], 'all virus names collected';

    $r = md_async_interpret_clamav(raw => "/w/PART1: OK\n/w/PART2: OK\n");
    is $r->{virus}, 0, 'all OK -> clean';
    ok !$r->{error},   'all OK -> no error';

    $r = md_async_interpret_clamav(raw => "/w: Access denied. ERROR\n");
    is $r->{error}, 1, 'ERROR reply -> error';

    $r = md_async_interpret_clamav(raw => "UNKNOWN COMMAND\n");
    is $r->{error}, 1, 'unknown reply -> error, not clean';

    $r = md_async_interpret_clamav(raw => { exit_code => 0, stdout => '', stderr => '' });
    is $r->{virus}, 0, 'clamdscan exit 0 -> clean';
    $r = md_async_interpret_clamav(raw => { exit_code => 1, stdout => "/w/PART1: Eicar FOUND\n", stderr => '' });
    is $r->{virus}, 1,       'clamdscan exit 1 -> virus';
    is $r->{name},  'Eicar', 'clamdscan virus name';
    $r = md_async_interpret_clamav(raw => { exit_code => 2, stdout => '', stderr => 'oops' });
    is $r->{error}, 1, 'clamdscan exit 2 -> error';
};

# Start a fake daemon on a Unix socket that waits $delay seconds and replies.
sub _fake_daemon {
    my ($sock, $delay, $reply) = @_;
    require IO::Socket::UNIX;
    require POSIX;
    my $srv = IO::Socket::UNIX->new(Local => $sock, Listen => 1) or die "listen: $!";
    my $pid = fork() // die "fork: $!";
    if (!$pid) {
        alarm 10;
        my $conn = $srv->accept or POSIX::_exit(0);
        my $req = <$conn>;
        select(undef, undef, undef, $delay);
        print $conn $reply;
        close $conn;
        POSIX::_exit(0);
    }
    close $srv;
    return $pid;
}

subtest 'md_async_run_checks - unfinished checks reported on global timeout' => sub {
    require File::Temp;
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $slow = _fake_daemon("$dir/slow.sock", 4, "x: OK\n");
    my $fast = _fake_daemon("$dir/fast.sock", 0, "x: OK\n");

    md_async_init(global_timeout => 1);
    my $out = do {
        local $SIG{__WARN__} = sub {};
        md_async_run_checks([
            md_async_check_clamd(sock => "$dir/slow.sock", path => $dir, name => 'slow', timeout => 5),
            md_async_check_clamd(sock => "$dir/fast.sock", path => $dir, name => 'fast', timeout => 5),
        ]);
    };
    kill 'TERM', $slow;
    waitpid($_, 0) for ($slow, $fast);

    is   $out->{results}{fast}, "x: OK\n",           'fast check has a result';
    ok   !exists $out->{results}{slow},              'slow check has no result';
    like $out->{errors}{slow}, qr/Global timeout after 1s/, 'slow check reported in errors';
};

subtest 'md_async_run_checks - socket checks run in parallel' => sub {
    require File::Temp;
    require Time::HiRes;
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my @pids = (
        _fake_daemon("$dir/av1.sock", 1, "/w/PART1: OK\n"),
        _fake_daemon("$dir/av2.sock", 1, "/w/PART1: Eicar FOUND\n"),
    );

    md_async_init(global_timeout => 5);
    my $t0  = Time::HiRes::time();
    my $out = md_async_run_checks([
        md_async_check_clamd(sock => "$dir/av1.sock", path => $dir, name => 'av1'),
        md_async_check_clamd(sock => "$dir/av2.sock", path => $dir, name => 'av2'),
    ]);
    my $elapsed = Time::HiRes::time() - $t0;
    waitpid($_, 0) for @pids;

    ok $elapsed < 1.8, sprintf('two 1s scans finished in %.2fs', $elapsed);
    is md_async_interpret_clamav(raw => $out->{results}{av1})->{virus}, 0, 'av1 clean';
    is md_async_interpret_clamav(raw => $out->{results}{av2})->{virus}, 1, 'av2 found a virus';
};

done_testing();
