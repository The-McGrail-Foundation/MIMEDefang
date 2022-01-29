package Mail::MIMEDefang::Mail;

use strict;
use warnings;

use Mail::MIMEDefang::Core;
use Mail::MIMEDefang::MIME;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw( resend_message_one_recipient resend_message_specifying_mode
                  resend_message pretty_print_mail );

#***********************************************************************
# %PROCEDURE: resend_message_one_recipient
# %ARGUMENTS:
#  recip -- a single recipient
#  deliverymode -- optional sendmail delivery mode arg (default "-odd")
# %RETURNS:
#  True on success; false on failure.
# %DESCRIPTION:
#  Re-sends the message (as if it came from original sender) to
#  a single recipient.
#***********************************************************************
sub resend_message_one_recipient {
	my($recip, $deliverymode) = @_;
	return resend_message_specifying_mode($deliverymode, [ $recip ]);
}

#***********************************************************************
# %PROCEDURE: resend_message_specifying_mode
# %ARGUMENTS:
#  deliverymode -- delivery mode
#  recipients -- reference to list of recipients to resend message to.
# %RETURNS:
#  True on success; false on failure.
# %DESCRIPTION:
#  Re-sends the message (as if it came from original sender) to
#  a list of recipients.
#***********************************************************************
sub resend_message_specifying_mode {
  my($deliverymode, $recips) = @_;
  return 0 if (!in_message_context("resend_message_specifying_mode"));

  $deliverymode = "-odd" unless defined($deliverymode);
  if ($deliverymode ne "-odb" &&
	  $deliverymode ne "-odq" &&
	  $deliverymode ne "-odd" &&
	  $deliverymode ne "-odi") {
	  $deliverymode = "-odd";
  }

  # Fork and exec for safety instead of involving shell
  my $pid = open(CHILD, "|-");
  if (!defined($pid)) {
	  md_syslog('err', "Cannot fork to resend message");
	  return 0;
  }

  if ($pid) {   # In the parent -- pipe mail message to the child
	  unless (open(IN, "<INPUTMSG")) {
	    md_syslog('err', "Could not open INPUTMSG in resend_message: $!");
	    return 0;
	  }

	  # Preserve relay's IP address if possible...
	  if ($ValidateIPHeader =~ /^X-MIMEDefang-Relay/) {
	    print CHILD "$ValidateIPHeader: $RelayAddr\n"
	  }

	  # Synthesize a Received: header
	  print CHILD synthesize_received_header();

	  # Copy message over
	  while(<IN>) {
	    print CHILD;
	  }
	  close(IN);
	  if (!close(CHILD)) {
	    if ($!) {
		    md_syslog('err', "sendmail failure in resend_message: $!");
	    } else {
		    md_syslog('err', "sendmail non-zero exit status in resend_message: $?");
	    }
	    return 0;
	  }
	  return 1;
  }

  # In the child -- invoke Sendmail

  # Direct stdout to stderr, or we will screw up communication with
  # the multiplexor..
  open(STDOUT, ">&STDERR");

  my(@cmd);
  if ($Sender eq "") {
	  push(@cmd, "-f<>");
  } else {
	  push(@cmd, "-f$Sender");
  }
  push(@cmd, $deliverymode);
  push(@cmd, "-Ac");
  push(@cmd, "-oi");
  push(@cmd, "--");
  push @cmd, @$recips;

  # In curlies to silence Perl warning...
  my $sm;
  $sm = $Features{'Path:SENDMAIL'};
  { exec($sm, @cmd); }

  # exec failed!
  md_syslog('err', "Could not exec $sm: $!");
  exit(1);
  # NOTREACHED
}

#***********************************************************************
# %PROCEDURE: resend_message
# %ARGUMENTS:
#  recipients -- list of recipients to resend message to.
# %RETURNS:
#  True on success; false on failure.
# %DESCRIPTION:
#  Re-sends the message (as if it came from original sender) to
#  a list of recipients.
#***********************************************************************
sub resend_message {
  return 0 if (!in_message_context("resend_message"));
  my(@recips);
  @recips = @_;
  return resend_message_specifying_mode("-odd", \@recips);
}

#***********************************************************************
# %PROCEDURE: pretty_print_mail
# %ARGUMENTS:
#  e -- a MIME::Entity object
#  size -- maximum size of value to return in characters
#  chunk -- optional; used in recursive calls only.  Do not supply as arg.
#  depth -- used in recursive calls only.  Do not supply as arg.
# %RETURNS:
#  A "pretty-printed" version of the e-mail body
# %DESCRIPTION:
#  Makes a pretty-printed version of the e-mail body no longer than size
#  characters.  This odd-looking function is used by CanIt...
#***********************************************************************

sub pretty_print_mail {
  my($e, $size, $chunk, $depth) = @_;
  $chunk = "" unless defined($chunk);
  $depth = 0 unless defined($depth);

  my(@parts) = $e->parts;
  my($type) = $e->mime_type;
  my($fname) = takeStabAtFilename($e);
  $fname = "; filename=$fname" if ($fname ne "");
  my($spaces) = "  " x $depth;
  $chunk .= "\n$spaces" . "[Part: ${type}${fname}]\n\n";
  if ($#parts >= 0) {
	  my($part);
	  foreach $part (@parts) {
	    $chunk = pretty_print_mail($part, $size, $chunk, $depth+1);
	    last if (length($chunk) >= $size);
	  }
  } else {
	  return $chunk unless ($type =~ m+^text/+);
	  my($body) = $e->bodyhandle;
	  return $chunk unless (defined($body));
	  my($path) = $body->path;
	  return $chunk unless (defined($path));
	  return $chunk unless (open(IN, "<$path"));
	  while (<IN>) {
	    $chunk .= $_;
	    last if (length($chunk) >= $size);
	  }
	  close(IN);
  }
  return $chunk;
}

1;
