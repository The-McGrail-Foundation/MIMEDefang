package Mail::MIMEDefang::Unit::FilterTest;

use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

sub t_check_undefined_subs_good : Test(1)
{
  my $filter = 't/tmp-good-filter';
  open(my $fh, '>', $filter) or die "Cannot create $filter: $!";
  print $fh "sub filter { md_syslog('info', 'hello'); }\n";
  close($fh);

  my @undefined = main::_check_undefined_subs($filter);

  unlink($filter);

  is_deeply(\@undefined, [], 'no undefined subs reported for a filter that only calls real subs');
}

sub t_check_undefined_subs_typo : Test(1)
{
  my $filter = 't/tmp-bad-filter';
  open(my $fh, '>', $filter) or die "Cannot create $filter: $!";
  print $fh "sub filter { md_sislog('info', 'hello'); }\n";
  close($fh);

  my @undefined = main::_check_undefined_subs($filter);

  unlink($filter);

  is_deeply(\@undefined, ['md_sislog'], 'reports the typo\'d subroutine name');
}

__PACKAGE__->runtests();
