package Mail::MIMEDefang::Unit::Utils;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;


use Mail::MIMEDefang;
use Mail::MIMEDefang::Actions;

sub t_get_quarantine_dir : Test(1)
{
  init_globals();
  # Set up temporary dir
  system('rm', '-rf', 't/tmp');
  mkdir('t/tmp', 0755);
  $Features{'Path:QUARANTINEDIR'} = 't/tmp';
  like(get_quarantine_dir, qr{.*\/(?:[0-9]{4})\-(?:[0-9]{2})\-(?:[0-9]{2})\-(?:[0-9]{2})\/qdir\-(?:[0-9]{4})\-(?:[0-9]{2})\-(?:[0-9]{2})\-(?:[0-9]{2})\.(?:[0-9]{2})\.(?:[0-9]{2})\-(?:[0-9]{3})});
  system('rm', '-rf', 't/tmp');
}

__PACKAGE__->runtests();
