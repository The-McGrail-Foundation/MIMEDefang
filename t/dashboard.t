package Mail::MIMEDefang::Unit::Dashboard;
use strict;
use warnings;
use lib qw(modules/lib);
# Not Mail::MIMEDefang::Unit: it loads mimedefang.pl.in into main::,
# whose subs would clash with the dashboard script's.
use base qw(Test::Class);
use Test::Most;

use File::Spec;
use File::Temp qw(tempdir);
use IO::Socket::IP;
use IO::Socket::UNIX;
use POSIX qw(WNOHANG);
use Socket qw(SOCK_DGRAM SOCK_STREAM PF_UNIX pack_sockaddr_un);
use JSON::PP;

my $SCRIPT = 'script/mimedefang-dashboard.in';

sub load_script : Test(startup => 1)
{
  local @ARGV = ();
  my $ok = do "./$SCRIPT";
  ok($ok, "$SCRIPT loads") or diag($@ || $!);
}

# A temp dir short enough for UNIX socket paths (sun_path is ~104 bytes)
sub short_tempdir {
  my $base = File::Spec->tmpdir;
  $base = '/tmp' if length($base) > 60 && -d '/tmp';
  return tempdir('mddashXXXXXX', DIR => $base, CLEANUP => 1);
}

sub t_parse_standard : Test(8)
{
  my $ev = main::parse_mdlog('MDLOG,Q1,spam,7.5,1.2.3.4,a@ex.com,b@lo.test,Hello there', 100);
  is($ev->{id}, 'Q1', 'id');
  is($ev->{event}, 'spam', 'event');
  is_deeply($ev->{values}, ['7.5', '1.2.3.4'], 'values');
  is($ev->{sender}, 'a@ex.com', 'sender');
  is($ev->{rcpt}, 'b@lo.test', 'recipient');
  is($ev->{subject}, 'Hello there', 'subject');
  is($ev->{t}, 100, 'arrival time');
  is($ev->{rcpts}, 1, 'single recipient');
}

sub t_parse_variants : Test(12)
{
  my $ev = main::parse_mdlog('Oct 14 08:00:00 mx mimedefang.pl[123]: MDLOG,Q2,mail_in,,,<>,rcpts=3,Sub%2C%20j%C3%A9', 1);
  is($ev->{event}, 'mail_in', 'syslog prefix is skipped');
  is($ev->{rcpts}, 3, 'rcpts=N gives the recipient count');
  is($ev->{rcpt}, '', 'and no single recipient');
  is($ev->{subject}, "Sub, j\x{e9}", 'percent-encoded UTF-8 is decoded');

  $ev = main::parse_mdlog('MDLOG,Q3,virus,EICAR,,x@a.b,y@c.d,Re: a, b, c', 1);
  is($ev->{subject}, 'Re: a, b, c', 'unencoded commas in the subject (utf8 mode)');
  is($ev->{rcpt}, 'y@c.d', 'recipient found by shape');

  $ev = main::parse_mdlog('MDLOG,Q4,dnsbl,one,two,three,x@a.b,y@c.d,S', 1);
  is_deeply($ev->{values}, [qw(one two three)], 'md_graphdefang_log_array with three values');

  $ev = main::parse_mdlog('MDLOG,Q6,mail_in,,,a@b.c,d@e.f,=?UTF-8?B?RXVyb3Bl4oCZcw==?= test', 1);
  is($ev->{subject}, "Europe\x{2019}s test", 'RFC 2047 B encoding is decoded');
  $ev = main::parse_mdlog('MDLOG,Q7,mail_in,,,a@b.c,d@e.f,=?iso-8859-1?Q?caf=E9?=', 1);
  is($ev->{subject}, "caf\x{e9}", 'RFC 2047 Q encoding is decoded');
  $ev = main::parse_mdlog('MDLOG,Q8,mail_in,,,a@b.c,d@e.f,=?bogus?B?xx?=', 1);
  ok(defined $ev->{subject}, 'unknown charset does not break parsing');
  ok(!defined main::parse_mdlog('hello world', 1), 'non-MDLOG line is rejected');
  ok(!defined main::parse_mdlog('MDLOG,Q5', 1), 'truncated line is rejected');
}

sub t_pct_decode : Test(3)
{
  is(main::pct_decode('a%2Cb%C3%A8'), "a,b\x{e8}", 'percent-encoded UTF-8 is decoded');
  is(main::pct_decode(undef), '', 'undef gives an empty string');
  my $s = "x, 100%\tb\x{c3}\x{a8}";
  is(main::pct_decode(Mail::MIMEDefang::percent_encode_for_graphdefang($s)), "x, 100%\tb\x{e8}",
     'round trip with percent_encode_for_graphdefang');
}

sub t_anonymize : Test(3)
{
  my $ev = main::parse_mdlog('MDLOG,Q1,spam,1,,john.doe@ex.com,<jane@lo.test>,Secret', 1);
  main::anonymize_event($ev);
  is($ev->{sender}, 'j***@ex.com', 'sender local part masked');
  is($ev->{rcpt}, '<j***@lo.test>', 'recipient local part masked');
  is($ev->{subject}, '', 'subject dropped');
}

sub _store_with_events {
  my $st = MDDash::Store->new(history => 100, top_cap => 3, spam_event => 'spam',
                              ml_events => ['ml_spam'], pinned => ['mail_in'], now => 0);
  my $t = 1_000_000_020;
  my $i = 0;
  for my $l ('MDLOG,A,spam,5.5,1.1.1.1,a@x.org,r@l.test,S',
             'MDLOG,B,spam,12,2.2.2.2,b@x.org,r@l.test,S',
             'MDLOG,C,ml_spam,0.93,,c@y.org,r@l.test,S',
             'MDLOG,D,ml_spam,87,,d@y.org,s@l.test,S',
             'MDLOG,E,mail_in,,,e@z.org,s@l.test,S',
             'MDLOG,F,virus,EICAR,,f@x.org,s@l.test,S') {
    $st->add_event(main::parse_mdlog($l, $t + $i++));
  }
  return ($st, $t);
}

sub t_store_aggregates : Test(11)
{
  my ($st, $t) = _store_with_events();
  is($st->{slots}{mail_in}, 1, 'pinned event takes the first slot');
  is($st->{slots}{spam}, 2, 'other events follow in arrival order');
  is_deeply($st->{totals}, { spam => 2, ml_spam => 2, mail_in => 1, virus => 1 }, 'totals');

  my $s = $st->series('1h', $t + 10);
  is($s->{step}, 60, '1h series uses one-minute steps');
  is($s->{n}, 60, '60 points');
  my $last = $s->{n} - 1;
  is($s->{ev}{spam}[$last], 2, 'events land in the current step');
  ok(!defined $s->{mx}{busy}[$last], 'no multiplexor sample yet');

  my $top = $st->top(dim => 'sender_domain', window => '1h', now => $t + 10);
  is_deeply($top->{items}[0], { key => 'x.org', count => 3 }, 'top sender domain');
  $top = $st->top(dim => 'rcpt', event => 'spam', now => $t + 10);
  is_deeply($top->{items}, [ { key => 'r@l.test', count => 2 } ], 'top filtered by event');

  my $sc = $st->scores('24h', $t + 10)->{scores};
  is_deeply($sc->{spam}, [ { bin => 5, count => 1 }, { bin => 12, count => 1 } ], 'spam score bins');
  is_deeply($sc->{ml_spam}, [ { bin => 0.8, count => 1 }, { bin => 0.9, count => 1 } ],
            'ML confidence bins, percentages scaled');
}

sub t_store_ml_no_verdicts : Test(4)
{
  my $st = MDDash::Store->new(history => 100, top_cap => 3, spam_event => 'spam',
                              ml_events => ['ml_not_spam', 'ml_not_phishing', 'ml_unsure'], now => 0);
  my $t = 1_000_000_020;
  $st->add_event(main::parse_mdlog('MDLOG,A,ml_not_spam,0.95,,a@x.org,r@l.test,S', $t));
  $st->add_event(main::parse_mdlog('MDLOG,B,ml_not_phishing,0.42,,b@x.org,r@l.test,S', $t + 1));
  $st->add_event(main::parse_mdlog('MDLOG,C,ml_unsure,0.71,,c@x.org,r@l.test,S', $t + 2));
  $st->add_event(main::parse_mdlog('MDLOG,D,ml_unsure,,,d@x.org,r@l.test,S', $t + 3));
  my $sc = $st->scores('24h', $t + 10)->{scores};
  is_deeply($sc->{ml_not_spam}, [ { bin => 0.9, count => 1 } ], 'not-spam confidence binned');
  is_deeply($sc->{ml_not_phishing}, [ { bin => 0.4, count => 1 } ], 'not-phishing confidence binned');
  is_deeply($sc->{ml_unsure}, [ { bin => 0.7, count => 1 } ], 'unsure confidence binned, valueless event skipped');
  is($st->{totals}{ml_unsure}, 2, 'valueless unsure event still counted');
}

sub t_store_mx_and_state : Test(7)
{
  my ($st, $t) = _store_with_events();
  my $snap = { msgs => 10, worker_states => { busy => 2 }, queued => 1,
               load => { scan => { msgs_0 => 3, ams_0 => 40 } } };
  $st->add_mx_sample($snap, $t);
  $st->add_mx_sample({ %$snap, msgs => 15 }, $t + 1);
  my $s = $st->series('1h', $t + 10);
  my $last = $s->{n} - 1;
  is($s->{mx}{msgs}[$last], 5, 'messages counted as counter deltas');
  is($s->{mx}{busy}[$last], 2, 'busy workers averaged');
  is($s->{mx}{ams}[$last], 40, 'scan time averaged');
  is($s->{mx}{queued}[$last], 1, 'queue maximum');

  my $json = JSON::PP->new->canonical->encode($st->to_state);
  my $st2 = MDDash::Store->new(now => 0);
  ok($st2->from_state(JSON::PP->new->decode($json)), 'state reloads');
  is_deeply($st2->{totals}, $st->{totals}, 'totals survive a restart');
  ok(!$st2->from_state({ version => 999 }), 'unknown state version is ignored');
}

sub t_store_default_colors : Test(4)
{
  my $st = MDDash::Store->new(pinned => [qw(mail_out spam mail_in)], now => 0);
  $st->add_event(main::parse_mdlog('MDLOG,A,virus,EICAR,,a@x.org,r@l.test,S', 1_000_000_000));
  $st->add_event(main::parse_mdlog('MDLOG,B,mail_in,,,b@x.org,r@l.test,S', 1_000_000_001));
  is($st->{slots}{mail_out}, 1, 'mail_out gets the first (blue) slot');
  is($st->{slots}{spam}, 2, 'spam gets the second (orange-red) slot');
  is($st->{slots}{mail_in}, 3, 'mail_in gets the third (green) slot');
  is($st->{slots}{virus}, 4, 'other events follow the pinned ones');
}

sub t_store_bounded : Test(3)
{
  my $st = MDDash::Store->new(history => 100, top_cap => 3, now => 0);
  my $t = 2_000_000_000;
  for my $i (1 .. 150) {
    $st->add_event(main::parse_mdlog("MDLOG,Q$i,mail_in,,,u$i\@d$i.org,r\@l.test,S", $t));
  }
  is(scalar @{ $st->{recent} }, 100, 'recent events capped by --history');
  my $slice = (values %{ $st->{top5} })[0];
  cmp_ok(scalar keys %{ $slice->{sender}{'*'} }, '<=', 6, 'top-N counters stay bounded');
  $st->prune($t + 40 * 24 * 3600);
  is(scalar keys %{ $st->{hour} }, 0, 'old buckets are pruned');
}

sub t_privileges : Test(3)
{
  like(main::check_privileges(0, 1000), qr/must not run as root/, 'euid 0 is refused');
  like(main::check_privileges(1000, 0), qr/must not run as root/, 'uid 0 is refused');
  ok(!defined main::check_privileges(1000, 1000), 'unprivileged user is accepted');
}

# Minimal multiplexor stand-in: answers commands from a table
sub _fake_mx {
  my ($path, %answers) = @_;
  my $srv = IO::Socket::UNIX->new(Local => $path, Type => SOCK_STREAM, Listen => 5)
    or die "fake mx: $!";
  my $pid = fork();
  die "fork: $!" unless defined $pid;
  if (!$pid) {
    while (my $c = $srv->accept) {
      my $cmd = <$c> // '';
      chomp $cmd;
      print {$c} $answers{$cmd} // "error: Unknown command\n";
      close $c;
    }
    POSIX::_exit(0);
  }
  close $srv;
  return $pid;
}

sub t_mx_legacy_fallback : Test(5)
{
  my $dir = short_tempdir();
  my $pid = _fake_mx("$dir/mx.sock",
    status => "IBSS 42 7 0 0 3600\n",
    load => "1 2 3 4 1.0 1.5 1.2 1.1 10.0 20.0 30.0 40.0 0 0 0 0 0 0 0 0 1 1 2 0 42 7 0 0 3600\n",
    histo => "   1 30\n   2 12\n   3 0\n   4 0\n");
  my ($snap, $err) = main::mx_snapshot("$dir/mx.sock");
  kill 'TERM', $pid;
  waitpid($pid, 0);
  ok($snap, 'snapshot built from the text commands') or diag $err;
  ok($snap->{legacy}, 'marked as legacy');
  is_deeply($snap->{worker_states}, { idle => 1, busy => 1, stopped => 2, killed => 0, max => 4 }, 'worker states');
  is($snap->{load}{scan}{ams_1}, 20, 'scan time from load');
  is_deeply($snap->{histo}, [30, 12, 0, 0], 'histogram');
}

sub _http_get {
  my ($port, $path, $host) = @_;
  my $s = IO::Socket::IP->new(PeerHost => '127.0.0.1', PeerPort => $port, Timeout => 5) or return;
  print {$s} "GET $path HTTP/1.1\r\nHost: " . ($host // "127.0.0.1:$port") . "\r\nConnection: close\r\n\r\n";
  local $/;
  my $r = <$s>;
  close $s;
  my ($head, $body) = split /\r\n\r\n/, $r // '', 2;
  my ($code) = ($head // '') =~ m{^HTTP/1\.1 (\d+)};
  return ($code // 0, $body // '', $head // '');
}

sub t_http_end_to_end : Test(17)
{
  my $dir = short_tempdir();
  my $snapshot = '{"version":"x","time":1,"uptime":5,"msgs":3,"activations":1,"queue_size":0,"queued":0,'
               . '"worker_states":{"max":2,"min":1,"busy":1,"idle":1,"stopped":0,"killed":0},'
               . '"load":{"scan":{"msgs_0":1,"ams_0":12.5,"msgs_1":1,"ams_1":12.5,"msgs_10":1}},'
               . '"histo":[1,0],"workers":[{"id":0,"state":"busy","pid":10,"status_tag":"filter_begin"}]}' . "\n";
  my $mx = _fake_mx("$dir/mx.sock", jsonsnapshot => $snapshot);

  # Pick a free port
  my $probe = IO::Socket::IP->new(LocalHost => '127.0.0.1', LocalPort => 0, Listen => 1);
  my $port = $probe->sockport;
  close $probe;

  no warnings qw(once);
  my $app = MDDash::App->new(%main::Opt, listen => "127.0.0.1:$port", 'mx-socket' => "$dir/mx.sock",
                             feed => "$dir/feed.sock", quiet => 1, interval => 1);
  $app->open_feed;
  $app->open_listen;
  my $pid = fork();
  die "fork: $!" unless defined $pid;
  if (!$pid) {
    my $flags = { stop => 0 };
    local $SIG{TERM} = sub { $flags->{stop} = 1 };
    $app->run($flags);
    $app->cleanup;
    POSIX::_exit(0);
  }
  ok(-S "$dir/feed.sock", 'feed socket created');
  is((stat("$dir/feed.sock"))[2] & 07777, 0660, 'feed socket mode 0660');

  socket(my $tx, PF_UNIX, SOCK_DGRAM, 0) or die;
  send($tx, "MDLOG,Q1,spam,9.1,1.2.3.4,a\@x.org,b\@l.test,Buy%2C now", 0, pack_sockaddr_un("$dir/feed.sock"));
  send($tx, "not an event", 0, pack_sockaddr_un("$dir/feed.sock"));
  select(undef, undef, undef, 1.5);

  my ($code, $body) = _http_get($port, '/api/summary');
  is($code, 200, '/api/summary');
  my $sum = decode_json($body);
  is($sum->{feed}{received}, 1, 'one event received');
  is($sum->{feed}{errors}, 1, 'one bad datagram counted');
  ok($sum->{mx}{up}, 'multiplexor polled');

  ($code, $body) = _http_get($port, '/api/events');
  is(decode_json($body)->{events}[0]{subject}, 'Buy, now', '/api/events returns the decoded event');

  ($code, $body) = _http_get($port, '/api/workers');
  is(decode_json($body)->{workers}[0]{status_tag}, 'filter_begin', '/api/workers passes the snapshot through');

  ($code, $body) = _http_get($port, '/metrics');
  like($body, qr/^mimedefang_events_total\{event="spam"\} 1$/m, '/metrics counts events');

  my $head;
  ($code, $body, $head) = _http_get($port, '/');
  is($code, 200, 'UI served');
  like($head, qr/Content-Security-Policy: default-src 'none'/, 'CSP header set');

  ($code, $body, $head) = _http_get($port, '/logo.png');
  like($head, qr{Content-Type: image/png}, 'logo served as PNG');
  is(substr($body, 0, 8), "\x89PNG\r\n\x1a\n", 'logo decoded from base64');
  ($code, $body) = _http_get($port, '/favicon.ico');
  is(substr($body, 0, 8), "\x89PNG\r\n\x1a\n", 'favicon served as PNG');

  ($code) = _http_get($port, '/api/summary', 'attacker.example');
  is($code, 403, 'foreign Host header refused (DNS rebinding)');
  ($code) = _http_get($port, '/nope');
  is($code, 404, 'unknown path');

  kill 'TERM', $pid;
  waitpid($pid, 0);
  kill 'TERM', $mx;
  waitpid($mx, 0);
  ok(!-e "$dir/feed.sock", 'feed socket removed on exit');
}

sub t_real_multiplexor : Test(6)
{
  SKIP: {
    skip 'mimedefang-multiplexor not built', 6 unless -x './mimedefang-multiplexor';
    my $dir = short_tempdir();
    my $filter = "$dir/filter";
    open(my $fh, '>', $filter) or die;
    print {$fh} "#!/bin/sh\nwhile read l; do echo ok; done\n";
    close $fh;
    chmod 0755, $filter;
    my $bin = File::Spec->rel2abs('./mimedefang-multiplexor');
    my $mpid = fork();
    die "fork: $!" unless defined $mpid;
    if (!$mpid) {
      # -D keeps the multiplexor in the foreground, so $mpid is its pid
      open(STDERR, '>', '/dev/null');
      exec($bin, '-D', '-m', '1', '-x', '2', '-z', $dir, '-s', "$dir/mx.sock",
           '-a', "$dir/mxu.sock", '-f', $filter) or POSIX::_exit(1);
    }
    my $t0 = time;
    select(undef, undef, undef, 0.2) until -S "$dir/mx.sock" || time - $t0 > 5;
    if (!-S "$dir/mx.sock") {
      kill 'TERM', $mpid;
      waitpid($mpid, 0);
      skip 'multiplexor did not start', 6;
    }
    select(undef, undef, undef, 0.3);

    my $ans = main::mx_command("$dir/mx.sock", 'jsonsnapshot');
    my $snap = eval { decode_json($ans) };
    ok($snap, 'jsonsnapshot is valid JSON') or diag $ans;
    is($snap->{worker_states}{max}, 2, 'worker count');
    is(scalar @{ $snap->{workers} }, 2, 'one entry per worker');
    ok(exists $snap->{autoscale}, 'autoscale on the privileged socket');

    $snap = eval { decode_json(main::mx_command("$dir/mxu.sock", 'jsonsnapshot')) };
    ok($snap && !exists $snap->{autoscale}, 'no autoscale on the unprivileged socket');
    like(main::mx_command("$dir/mxu.sock", 'jsonautoscale'), qr/^error: .*privileged/,
         'jsonautoscale is privileged');

    kill 'TERM', $mpid;
    waitpid($mpid, 0);
  }
}

__PACKAGE__->runtests();
