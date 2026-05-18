package Mail::MIMEDefang::Unit::Antispam;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antispam;

use File::Copy;
use POSIX qw(SIGTERM);

# Start a daemon in the background via fork; returns pid or undef on failure.
sub _start_daemon {
    my (@cmd) = @_;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';
        exec @cmd;
        exit 1;
    }
    return $pid;
}

# Poll spamd via ping until ready or timeout. Returns client or undef.
sub _wait_spamd {
    my ($host, $port, $timeout) = @_;
    my $client = md_spamc_init($host, $port);
    return undef unless defined $client;
    my $deadline = time() + $timeout;
    while (time() < $deadline) {
        return $client if eval { $client->ping() };
        select undef, undef, undef, 0.2;
    }
    return undef;
}

sub md_spamc : Test(1)
{
  SKIP: {
    if ( -f "/.dockerenv" or (defined $ENV{GITHUB_ACTIONS}) ) {
      skip "Spamd test disabled on Docker", 1
    }
    skip "spamd cannot run as root", 1 if $> == 0;
    my $spamd = Mail::MIMEDefang::Unit::get_abs_path('spamd');
    if(not defined $spamd or not -f $spamd) {
      skip "Spamd binary not found", 1
    }
    init_globals();

    my $pid = _start_daemon($spamd, '-L', '-p', '7830');
    my $spamc = _wait_spamd('127.0.0.1', 7830, 15);
    unless (defined $spamc) {
      kill SIGTERM, $pid;
      waitpid($pid, 0);
      skip "spamd did not become ready on port 7830", 1;
    }

    copy('t/data/gtube.eml', './INPUTMSG');
    my ($score, $hits, $report, $flag) = md_spamc_check($spamc);
    is($flag, 'True');
    unlink('./INPUTMSG');
    kill SIGTERM, $pid;
    waitpid($pid, 0);
  }
}

sub md_rspamd : Test(1)
{
  SKIP: {
    if ( -f "/.dockerenv" or (defined $ENV{GITHUB_ACTIONS}) ) {
      skip "Spamd test disabled on Docker", 1
    }
    skip "rspamd cannot run as root", 1 if $> == 0;
    my $rspamd = Mail::MIMEDefang::Unit::get_abs_path('rspamd');
    if(not defined $rspamd or not -f $rspamd) {
      skip "Rspamd binary not found", 1
    }
    init_globals();

    my $pid = _start_daemon($rspamd, '-u', $ENV{USER}, '-c', 't/data/rspamd.conf');

    # Wait up to 15 seconds for rspamd to accept connections
    use IO::Socket::INET;
    my $ready = 0;
    my $deadline = time() + 15;
    while (time() < $deadline) {
      my $s = IO::Socket::INET->new(
        PeerAddr => 'localhost', PeerPort => 11333,
        Proto => 'tcp', Timeout => 1);
      if ($s) { $ready = 1; last; }
      select undef, undef, undef, 0.2;
    }
    unless ($ready) {
      kill SIGTERM, $pid;
      waitpid($pid, 0);
      skip "rspamd did not start on port 11333", 1;
    }

    copy('t/data/gtube.eml', './INPUTMSG');
    my ($hits, $req, $tests, $report, $action, $is_spam) = rspamd_check();
    is($is_spam, 'true');
    unlink('./INPUTMSG');
    kill SIGTERM, $pid;
    waitpid($pid, 0);
  }
}

__PACKAGE__->runtests();
