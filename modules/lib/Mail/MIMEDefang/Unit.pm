#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

package Mail::MIMEDefang::Unit;

use strict;
use warnings;
use Test::Class;
use base qw( Test::Class );

use Net::SMTP;
use Test::Most;

# This bit of evil is how we pull in MIMEDefang's .pl code without running anything.
sub include_mimedefang : Test(startup)
{
	no warnings 'redefine';
	local *CORE::GLOBAL::exit = sub { };
	local @ARGV = ();
	do './mimedefang.pl.in';
	use warnings 'redefine';
}

sub smtp_mail
{
  my ($from, $to, $filemail) = @_;
  my $messages;

  return 0 if not -f $filemail;
  open my $fh, '<', $filemail or return 0;
  my $mailcnt = do { local $/; <$fh> };
  close($fh);

  my @email = split(/\@/, $from);
  my $smtp = Net::SMTP->new("localhost",
                           Hello => $email[1],
                           Timeout => 30,
                           Debug   => 0,
                          );
  return "Connection error" if not defined $smtp;
  $smtp->mail('<>');
  $smtp->to("$to\n");
  $messages .= $smtp->message();
  $smtp->data($mailcnt);
  $messages .= $smtp->message();
  $smtp->dataend;
  $messages .= $smtp->message();
  $smtp->quit;
  $messages .= $smtp->message();
  return $messages;
}

1;
