package Mail::MIMEDefang::Unit::TestMail;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use File::Spec;
use File::Temp qw(tempdir);

# Runs script/mimedefang-test-mail and the standalone spamassassin CLI against
# the same message (the GTUBE test string) and checks they agree on the spam
# score.
sub t_score_parity : Test(2)
{
  SKIP: {
    skip "Mail::SpamAssassin not installed", 2
      unless eval { require Mail::SpamAssassin; 1 };

    my $spamassassin = Mail::MIMEDefang::Unit::get_abs_path('spamassassin');
    skip "spamassassin binary not found", 2 unless defined $spamassassin;

    my $mimedefang_pl = File::Spec->catfile('.', 'mimedefang.pl');
    skip "No built mimedefang.pl (run ./configure && make, or perl Makefile.PL && make)", 2
      unless -r $mimedefang_pl;

    my @envelope = (
      '--from', 'sender@example.com',
      '--to', 'recipient@example.com',
      '--relay-ip', '127.0.0.1',
      '--relay-host', 'localhost',
      '--helo', 'localhost',
    );

    # mimedefang-test-mail runs the filter from inside its work directory,
    # so the prefs file must be passed as an absolute path.
    local $ENV{MD_TEST_SA_PREFS} = File::Spec->rel2abs('t/data/sa-test-prefs.cf');
    my $out = `perl -Iblib/lib -Imodules/lib script/mimedefang-test-mail -f t/data/mimedefang-score-filter @envelope --keep-workdir t/data/gtube.eml 2>&1`;

    my ($hits, $names) = $out =~ /^SCORE=(\S+) NAMES=(\S+)$/m;
    my ($workdir) = $out =~ /^Work directory: (.*)$/m;

    unless (defined $hits && defined $workdir) {
      fail("mimedefang-test-mail did not report a SpamAssassin score:\n$out");
      fail("no work directory to compare against");
      last SKIP;
    }

    my $samsg = File::Spec->catfile($workdir, 'SAMSG');
    unless (-r $samsg) {
      fail("mimedefang-test-mail did not dump the scored message ($samsg)");
      fail("cannot run spamassassin CLI without the scored message");
      last SKIP;
    }

    # NOTE: mimedefang.pl:64 sets $SALocalTestsOnly = 1 unconditionally, so
    # spam_assassin_check() never runs SpamAssassin's network tests (DNSBL,
    # SPF/DKIM/DMARC DNS lookups, ...). SpamAssassin picks per-rule scores
    # from one of four "scoresets" depending on whether network tests are
    # enabled and whether bayes is usable, so the same rules can add up to
    # a different score.
    my $cli_out = `$spamassassin -L -t --prefspath=t/data/sa-test-prefs.cf < $samsg 2>/dev/null`;
    system('rm', '-rf', $workdir);

    # SpamAssassin wraps long header values across "\r\n\t" continuation
    # lines with no extra separating whitespace; flatten those before
    # matching so score=/tests= aren't split.
    $cli_out =~ s/\r?\n[ \t]//g;
    my ($cli_score) = $cli_out =~ /^X-Spam-Status: .*?score=([\d.]+)/m;

    is(sprintf('%.1f', $hits), $cli_score,
       "mimedefang-test-mail and spamassassin CLI agree on the GTUBE score");

    my %mimedefang_names = map { $_ => 1 } grep { $_ ne 'TXREP' } split(/,/, $names);
    my ($cli_names) = $cli_out =~ /^X-Spam-Status: .*?tests=(\S+(?:,\S+)*)/m;
    my %cli_names = map { $_ => 1 } grep { $_ ne 'TXREP' } split(/,/, $cli_names // '');

    is_deeply(\%mimedefang_names, \%cli_names,
       "mimedefang-test-mail and spamassassin CLI agree on the triggered rules");
  }
}

__PACKAGE__->runtests();
