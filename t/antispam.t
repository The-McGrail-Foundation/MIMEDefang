package Mail::MIMEDefang::Unit::Antispam;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antispam;

use File::Copy;

sub md_spamc : Test(1)
{
  SKIP: {
    if ( -f "/.dockerenv" or (defined $ENV{GITHUB_ACTIONS}) ) {
      skip "Spamd test disabled on Docker", 1
    }
    my $spamd = Mail::MIMEDefang::Unit::get_abs_path('spamd');
    if(not defined $spamd or not -f $spamd) {
      skip "Spamd binary not found", 1
    }
    init_globals();
    system("$spamd -L -s stderr -p 7830 -d");
    copy('t/data/gtube.eml', './INPUTMSG');

    my $spamc = md_spamc_init('127.0.0.1', 7830);

    my ($score, $hits, $report, $flag) = md_spamc_check($spamc);
    is($flag, 'True');
    unlink('./INPUTMSG');
    system("pkill spamd");
  }
}

sub md_rspamd : Test(1)
{
  SKIP: {
    if ( -f "/.dockerenv" or (defined $ENV{GITHUB_ACTIONS}) ) {
      skip "Spamd test disabled on Docker", 1
    }
    my $rspamd = Mail::MIMEDefang::Unit::get_abs_path('rspamd');
    if(not defined $rspamd or not -f $rspamd) {
      skip "Rspamd binary not found", 1
    }
    init_globals();
    system("$rspamd -u $ENV{USER} -c t/data/rspamd.conf 1>/dev/null 2>&1");
    copy('t/data/gtube.eml', './INPUTMSG');

    my ($hits, $req, $tests, $report, $action, $is_spam) = rspamd_check();
    is($is_spam, 'true');
    unlink('./INPUTMSG');
    system("pkill rspamd");
  }
}

__PACKAGE__->runtests();
