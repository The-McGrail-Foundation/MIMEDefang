#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Unit - Methods used by MIMEDefang regression tests

=head1 DESCRIPTION

Mail::MIMEDefang::Unit are a set of methods that are called from MIMEDefang
regression tests.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Unit;

use strict;
use warnings;
use Test::Class;
use base qw( Test::Class );

use Net::SMTP;
use Test::Most;

=item include_mimedefang

Method that includes F<mimedefang.pl.in> code without running anything.

=cut

# This bit of evil is how we pull in MIMEDefang's .pl code without running anything.
sub include_mimedefang : Test(startup)
{
	no warnings 'redefine';
	local *CORE::GLOBAL::exit = sub { };
	local @ARGV = ();
	do './mimedefang.pl.in';
	use warnings 'redefine';
}

=item smtp_mail

Method which sends a test email and returns SMTP replies.

=cut

sub smtp_mail
{
  my ($from, $to, $filemail) = @_;
  my $messages = '';

  return 0 if not -f $filemail;
  open my $fh, '<', $filemail or return 0;
  my $mailcnt = do { local $/; <$fh> };
  close($fh);

  my @email = split(/\@/, $from);
  my $smtp = Net::SMTP->new("localhost",
                           Hello => $email[1],
                           Timeout => 10,
                           Debug   => 0,
                          );
  return "Connection error" if not defined $smtp;
  $smtp->mail('<defang@localhost>');
  $smtp->to("$to\n");
  $messages .= $smtp->message();
  $smtp->data();
  $messages .= $smtp->message();
  $smtp->datasend($mailcnt);
  $messages .= $smtp->message();
  $smtp->dataend;
  $messages .= $smtp->message();
  $smtp->quit;
  $messages .= $smtp->message();
  undef $mailcnt;
  undef $smtp;
  undef $fh;
  return $messages;
}

=back

=cut

1;
