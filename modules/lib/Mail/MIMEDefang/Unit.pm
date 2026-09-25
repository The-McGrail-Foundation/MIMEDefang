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

use MIME::Parser;
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
	local $SIG{__WARN__} = sub {
		my $w = shift;
		warn $w unless $w =~ /unlikely to be reached|Maybe you meant system/;
	};
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
  $messages .= $smtp->message();
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

=item get_abs_path

Method which returns the absolute path of a file by reading $PATH.

=cut

sub get_abs_path {
  my $prog = shift;

  my $full_path;
  for my $dir (split(':', $ENV{PATH})) {
    $full_path = "$dir/$prog";
    if (-x $full_path) {
      return $full_path;
    }
  }
  return;
}

# Minimal input handle that hands out predefined chunks, to drive
# Mail::MIMEDefang::MIME::Base64::Tap across read() boundaries.
{
  package Mail::MIMEDefang::Unit::ChunkedIn;
  sub new { my ($class, @chunks) = @_; return bless { chunks => [@chunks] }, $class; }
  sub read {
    my $self = shift;
    my $chunk = shift @{$self->{chunks}};
    return 0 unless defined($chunk);
    $_[0] = $chunk;
    return length($chunk);
  }
}

=item tap_found

Method which feeds the given chunks through a
C<Mail::MIMEDefang::MIME::Base64::Tap> and returns whether data after
base64 padding was found.

=cut

sub tap_found
{
  my (@chunks) = @_;
  my $in = Mail::MIMEDefang::Unit::ChunkedIn->new(@chunks);
  my $tap = Mail::MIMEDefang::MIME::Base64::Tap->new($in);
  my $buf = '';
  while ($tap->read($buf, 32768)) { }
  return $tap->found;
}

=item parse_string

Method which parses a message held in a string and returns the
C<MIME::Parser> and the resulting C<MIME::Entity>.

=cut

sub parse_string
{
  my ($msg) = @_;
  my $parser = MIME::Parser->new();
  $parser->output_to_core(1);
  my $entity = $parser->parse_data($msg);
  return ($parser, $entity);
}

=item base64_message

Method which returns a multipart test message with an attachment
whose base64 body is the given string.

=cut

sub base64_message
{
  my ($encoded) = @_;
  return "From: a\@example.com\nTo: b\@example.com\nSubject: test\nMIME-Version: 1.0\n" .
    "Content-Type: multipart/mixed; boundary=\"XX\"\n\n" .
    "--XX\nContent-Type: text/plain\n\nhi\n" .
    "--XX\nContent-Type: application/octet-stream; name=f.bin\n" .
    "Content-Transfer-Encoding: base64\n\n$encoded\n--XX--\n";
}

=back

=cut

1;
