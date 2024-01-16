package Mail::MIMEDefang::Unit::Antispam;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Antispam;

use File::Copy;
use version;

sub md_spamc : Test(1)
{
  SKIP: {
    if ( -f "/.dockerenv" ) {
      skip "Spamd test disabled on Docker", 1
    }
    init_globals();
    system("spamd -L -s stderr -p 7830 -d");
    copy('t/data/gtube.eml', './INPUTMSG');

    my $spamc = md_spamc_init('127.0.0.1', 7830);

    my ($score, $hits, $report, $flag) = md_spamc_check($spamc);
    is($flag, 'True');
    unlink('./INPUTMSG');
    system("pkill spamd");
  }
}
__PACKAGE__->runtests();
