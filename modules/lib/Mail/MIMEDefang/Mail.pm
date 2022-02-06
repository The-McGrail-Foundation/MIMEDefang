#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

package Mail::MIMEDefang::Mail;

use strict;
use warnings;

use IO::Socket::SSL;

use Mail::MIMEDefang;
use Mail::MIMEDefang::MIME;
use Mail::MIMEDefang::Utils;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw( resend_message_one_recipient resend_message_specifying_mode
                  resend_message pretty_print_mail md_check_against_smtp_server );

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

#***********************************************************************
# %PROCEDURE: get_smtp_return_code
# %ARGUMENTS:
#  sock -- a socket connected to an SMTP server
#  recip -- the recipient we're inquring about
#  server -- the server we're querying
# %RETURNS:
#  A four-element list:(retval, code, dsn, text),
#  where code is a 3-digit SMTP code.
#  Retval is 'CONTINUE', 'TEMPFAIL' or 'REJECT'.
# %DESCRIPTION:
#  Reads return codes from SMTP server
#***********************************************************************
sub get_smtp_return_code {
  my($sock, $recip, $server) = @_;
  my($line, $code, $text, $retval, $dsn);
  while (defined ($line = $sock->getline())) {
  	# Chew up all trailing white space, including CR
	  $line =~ s/\s+$//;
	  if (($line =~ /^\d\d\d$/) or ($line =~ /^\d\d\d\s/)) {
	    $line =~ /^(\d\d\d)\s*(.*)$/;
	    $code = $1;
	    $text = $2;
	    # Check for DSN
	    if ($text =~ /^(\d\.\d{1,3}\.\d{1,3})\s+(.*)$/) {
		    $dsn = $1;
		    $text = $2;
	    } else {
		    $dsn = "";
	    }
	    if ($code =~ /^[123]/) {
		   $retval = 'CONTINUE';
	    } elsif ($code =~ /^4/) {
		    md_syslog('info', "get_smtp_return_code: for $recip on $server returned $code $dsn $text");
		    $retval = 'TEMPFAIL';
	    } elsif ($code =~ /^5/) {
		    md_syslog('info', "get_smtp_return_code: for $recip on $server returned $code $dsn $text");
		    $retval = 'REJECT';
	    } else {
	 	    md_syslog('warning', "get_smtp_return_code: Invalid SMTP reply code $code from server $server for $recip");
		    $retval = 'TEMPFAIL';
	    }
	    return ($retval, $code, $dsn, $text);
	  }
  }

  my $msg;
  if( defined $line ) {
    $msg = "get_smtp_return_code: Invalid response [$line] from SMTP server";
    md_syslog('info', "get_smtp_return_code: Check for $recip on $server returned invalid response [$line]");
  } else {
    $msg = "get_smtp_return_code: Empty response from SMTP server";
    md_syslog('info', "get_smtp_return_code: for $recip on $server returned an empty response");
  }

  return ('TEMPFAIL', "451", "4.3.0", $msg );
}

#***********************************************************************
# %PROCEDURE: get_smtp_extensions
# %ARGUMENTS:
#  sock -- a socket connected to an SMTP server
#  server -- the server we're querying
# %RETURNS:
#  A four-element list:(retval, code, dsn, exts)
#  retval is 'CONTINUE', 'TEMPFAIL', or 'REJECT'.
#  code is a 3-digit SMTP code.
#  dsn is an extended SMTP status code
#  exts is a hash of EXTNAME->EXTOPTS
# %DESCRIPTION:
#  Checks SMTP server's supported extensions.
#  Expects EHLO to have been sent already (artifact of cribbing get_smtp_return_code)
#***********************************************************************
sub get_smtp_extensions {
  my($sock, $server) = @_;
  my($ext, $msg, $delim, $line, $code, $text, $retval, $dsn);
  my %exts;
  my $LineNum=0;
  $delim='-';
  while ( ($delim eq '-' ) && (defined ($line = $sock->getline())))  {
    # Chew up all trailing white space, including CR
    $line =~ s/\s+$//;
    # Line can be:
    #   '[45]xy $ERROR'           Failure. Don't really care why.
    #   '250-hostname'            Initial line in multi-line response
    #   '250 hostname'            ONLY line in successful response
    #   '250-$EXTNAME $EXTOPTS'   Advertisement of extension with options
    #   '250 $EXTNAME $EXTOPTS'   Advertisement of extension with options (Final line)
    $line =~ m/([245][0-9][0-9])([- ])([^ ]+) *(.*)/  or return ('TEMPFAIL', "451", "4.3.0", "$server said: $line");
    $code=$1;
    $delim=$2;
    $ext=$3;
    $text=$4;
    # uncomment to debug parsing
    # md_syslog('debug',"get_smtp_extensions: line $LineNum: code=$code, delim=$delim, ext=$ext, text=$text");
    if ( $LineNum == 0 ) {
      $exts{'hostname'} = $3;
      $LineNum++;
      next;
    }
    $exts{$ext} = $text;
    $LineNum++;
  }

  $code =~ m/2../ and return ('CONTINUE', "$code", "2.5.0", %exts );
  $code =~ m/4../ and return ('TEMPFAIL', "$code", "4.0.0", %exts );
  $code =~ m/5../ and return ('REJECT', "$code", "5.0.0", %exts );
}

#***********************************************************************
# %PROCEDURE: md_check_against_smtp_server
# %ARGUMENTS:
#  sender -- sender e-mail address
#  recip -- recipient e-mail address
#  helo -- string to put in "HELO" command
#  server -- SMTP server to try.
#  port   -- optional: Port to connect on (defaults to 25)
# %RETURNS:
#  ('CONTINUE', "OK") if recipient is OK
#  ('TEMPFAIL', "err") if temporary failure
#  ('REJECT', "err") if recipient is not OK.
# %DESCRIPTION:
#  Verifies a recipient against another SMTP server by issuing a
#  HELO / MAIL FROM: / RCPT TO: / QUIT sequence
#***********************************************************************
sub md_check_against_smtp_server {
  my($sender, $recip, $helo, $server, $port) = @_;
  my($code, $text, $dsn, $retval);

  $port = 'smtp(25)' unless defined($port);

  # Add angle-brackets if needed
  if (!($sender =~ /^<.*>$/)) {
    $sender = "<$sender>";
  }

  if (!($recip =~ /^<.*>$/)) {
    $recip = "<$recip>";
  }

  # Set SSL_startHandshake to start in plain mode,
  # SSL_verify_mode to SSL_VERIFY_NONE to make the check work
  # with self-signed certificates and SSL_hostname for SNI
  my $sock;
  my $plaintext = 0;
  $sock = IO::Socket::SSL->new(PeerAddr => $server,
           SSL_startHandshake => 0,
           SSL_verify_mode => SSL_VERIFY_NONE,
           SSL_hostname => "$server",
           SSL_version => 'SSLv23',
           SSL_cipher_list => 'ALL',
           PeerPort => $port,
           Proto    => 'tcp',
           Timeout  => 25);

  if (!defined($sock)) {
    # fallback to plaintext if SSL connection doesn't succeed
    md_syslog('warning', 'Falling back to plaintext connection');
    $sock = IO::Socket::INET->new(PeerAddr => $server,
                                  PeerPort => $port,
                                  Proto    => 'tcp',
                                  Timeout  => 25);
    $plaintext = 1;
    if(!defined($sock)) {
      return ('TEMPFAIL', "Could not connect to other SMTP server $server, error=$!");
    }
  }

  ($retval, $code, $dsn, $text) = get_smtp_return_code($sock, $recip, $server);
  if ($retval ne 'CONTINUE') {
    $sock->print("QUIT\r\n");
    $sock->flush();
    # Swallow return value
    get_smtp_return_code($sock, $recip, $server);
    $sock->close();
    return ($retval, $text, $code, $dsn);
  }

  # If the banner contains our host name, there's a loop!
  # However, don't check if $server is explicitly 127.0.0.1
  # because presumably that indicates the caller knows
  # what he or she is doing.
  if ($server ne '127.0.0.1' && $server ne '::1') {
    my $host_expr = quotemeta(get_host_name());
    if ($text =~ /^$host_expr\b/) {
      $sock->print("QUIT\r\n");
      $sock->flush();
      # Swallow return value
      get_smtp_return_code($sock, $recip, $server);
      $sock->close();
      return('REJECT', "Verification server loop!  Trying to verify $recip against myself!",
      554, '5.4.6');
    }
  }

  $sock->print("EHLO $helo\r\n");
  $sock->flush();
  my %exts;
  my $ext;
  ($retval, $code, $dsn, %exts) = get_smtp_extensions($sock, $recip, $server);
  if (($plaintext eq 1) or ($retval ne 'CONTINUE')) {
    $sock->print("HELO $helo\r\n");
  } else {
  # Uncomment to debug (and/or uncomment similar line in get_smtp_extensions)
  #   foreach $ext ( keys %exts ) {
  #     md_syslog('debug',"md_check_against_smtp_server extension: $ext $exts{$ext}");
  #   }
    if (exists $exts{'STARTTLS'}) {
      # send STARTTLS command and read response
      $sock->print("STARTTLS\r\n");
      ($retval, $code, $dsn, $text) = get_smtp_return_code($sock, $recip, $server);
      if ($retval ne 'CONTINUE') {
        $sock->print("QUIT\r\n");
        $sock->flush();
        # Swallow return value
        get_smtp_return_code($sock, $recip, $server);
        $sock->close();
        return ($retval, $text, $code, $dsn);
      }
      # if response was successful we can upgrade the socket to SSL now:
      if ( $sock->connect_SSL ) {
        md_syslog('debug',"md_check_against_smtp_server: start_SSL succeeded!");
        # send inside EHLO
        $sock->print("EHLO $helo\r\n");
      } else {
        #back off from using STARTTLS
        $sock->stop_SSL;
        no warnings 'once';
        md_syslog('debug',"md_check_against_smtp_server: $server offers STARTTLS but fails with error $IO::Socket::SSL::SSL_ERROR. Falling back to plaintext...");
        $sock->print("EHLO $helo\r\n");
      }
    } else {
       md_syslog('debug',"md_check_against_smtp_server: STARTTLS not available");
       $sock->print("RSET\r\n");
       $sock->flush();
       # Swallow return value
       get_smtp_return_code($sock, $recip, $server);
       $sock->print("EHLO $helo\r\n");
    }
  }
  # At this point we've either sent a fallback HELO, fallback EHLO, or internal EHLO.
  # so, get the code...
  ($retval, $code, $dsn, $text) = get_smtp_return_code($sock, $recip, $server);
  if ($retval ne 'CONTINUE') {
    $sock->print("QUIT\r\n");
    $sock->flush();
    # Swallow return value
    get_smtp_return_code($sock, $recip, $server);
    $sock->close();
    return ($retval, $text, $code, $dsn);
  }
  md_syslog('debug',"md_check_against_smtp_server: Checking sender $sender");
  $sock->print("MAIL FROM:$sender\r\n");
  $sock->flush();

  ($retval, $code, $dsn, $text) = get_smtp_return_code($sock, $recip, $server);
  if ($retval ne 'CONTINUE') {
    $sock->print("QUIT\r\n");
    $sock->flush();
    # Swallow return value
    get_smtp_return_code($sock, $recip, $server);
    $sock->close();
    return ($retval, $text, $code, $dsn);
  }

  md_syslog('debug',"md_check_against_smtp_server: Checking recipient $recip");
  $sock->print("RCPT TO:$recip\r\n");
  $sock->flush();

  ($retval, $code, $dsn, $text) = get_smtp_return_code($sock, $recip, $server);
  $sock->print("QUIT\r\n");
  $sock->flush();
  # Swallow return value
  get_smtp_return_code($sock, $recip, $server);
  $sock->close();
  return ($retval, $text, $code, $dsn);
}

1;
