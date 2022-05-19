#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang - email filtering milter

=head1 DESCRIPTION

Mail::MIMEDefang is a framework for filtering e-mail.
It uses Sendmail's "Milter" API, some C glue code, and some Perl code to let you write high-performance mail filters in Perl.

People use MIMEDefang to:

    Block viruses
    Block or tag spam
    Remove HTML mail parts
    Add boilerplate disclaimers to outgoing mail
    Remove or alter attachments
    Replace attachments with URL's
    Implement sophisticated access controls.

You're limited only by your imagination. If you can think of it and code it in Perl, you can do it with MIMEDefang.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang;

require Exporter;

use Errno qw(ENOENT EACCES);
use File::Spec;

my $_syslogopen = undef;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

our $VERSION = '3.0';

@EXPORT = qw{
      $AddWarningsInline @StatusTags
      $Action $Administrator $AdminName $AdminAddress $DoStatusTags
      $Changed $CSSHost $DaemonAddress $DaemonName
      $DefangCounter $Domain $EntireMessageQuarantined
      $MessageID $Rebuild $QuarantineCount
      $QuarantineSubdir $QueueID $MsgID $MIMEDefangID
      $RelayAddr $WasResent $RelayHostname
      $RealRelayAddr $RealRelayHostname
      $ReplacementEntity $Sender $ServerMode $Subject $SubjectCount
      $ClamdSock $SophieSock $TrophieSock
      $Helo @ESMTPArgs
      @SenderESMTPArgs %RecipientESMTPArgs
      $TerminateAndDiscard $URL $VirusName
      $CurrentVirusScannerMessage @AddedParts
      $VirusScannerMessages $WarningLocation $WasMultiPart
      $CWD $FprotdHost $Fprotd6Host
      $NotifySenderSubject $NotifyAdministratorSubject
      $ValidateIPHeader
      $QuarantineSubject $SALocalTestsOnly $NotifyNoPreamble
      %Actions %Stupidity @FlatParts @Recipients @Warnings %Features
      $SyslogFacility $GraphDefangSyslogFacility
      $MaxMIMEParts $InMessageContext $InFilterContext $PrivateMyHostName
      $EnumerateRecipients $InFilterEnd $FilterEndReplacementEntity
      $AddApparentlyToForSpamAssassin $WarningCounter
      @VirusScannerMessageRoutines @VirusScannerEntityRoutines
      $VirusScannerRoutinesInitialized
      %SendmailMacros %RecipientMailers $CachedTimezone $InFilterWrapUp
      $SuspiciousCharsInHeaders
      $SuspiciousCharsInBody
      $GeneralWarning
      $HTMLFoundEndBody $HTMLBoilerplate $SASpamTester
      $results_fh
      init_globals print_and_flush detect_and_load_perl_modules
      init_status_tag push_status_tag pop_status_tag
      signal_changed signal_unchanged md_syslog md_graphdefang_log
      write_result_line in_message_context in_filter_context in_filter_wrapup
      in_filter_end percent_decode percent_encode percent_encode_for_graphdefang
      send_mail send_quarantine_notifications signal_complete send_admin_mail
      md_version set_status_tag
    };

@EXPORT_OK = qw{
      detect_antivirus_support
    };

#***********************************************************************
# %PROCEDURE: md_version
# %ARGUMENTS:
#  None
# %RETURNS:
#  MIMEDefang version
#***********************************************************************
sub md_version {
    return $VERSION;
}

=item init_globals

Initialize global variables used across MIMEDefang instance
and filter.

=cut

sub init_globals {
    my ($self, @params) = @_;

    $CWD = $Features{'Path:SPOOLDIR'};
    $InMessageContext = 0;
    $InFilterEnd = 0;
    $InFilterContext = 0;
    $InFilterWrapUp = 0;
    undef $FilterEndReplacementEntity;
    $Action = "";
    $Changed = 0;
    $DefangCounter = 0;
    $Domain = "";
    $MIMEDefangID = "";
    $MsgID = "NOQUEUE";
    $MessageID = "NOQUEUE";
    $Helo = "";
    $QueueID = "NOQUEUE";
    $QuarantineCount = 0;
    $Rebuild = 0;
    $EntireMessageQuarantined = 0;
    $QuarantineSubdir = "";
    $RelayAddr = "";
    $RealRelayAddr = "";
    $WasResent = 0;
    $RelayHostname = "";
    $RealRelayHostname = "";
    $Sender = "";
    $Subject = "";
    $SubjectCount = 0;
    $SuspiciousCharsInHeaders = 0;
    $SuspiciousCharsInBody = 0;
    $TerminateAndDiscard = 0;
    $VirusScannerMessages = "";
    $VirusName = "";
    $WasMultiPart = 0;
    $WarningCounter = 0;
    undef %Actions;
    undef %SendmailMacros;
    undef %RecipientMailers;
    undef %RecipientESMTPArgs;
    undef @FlatParts;
    undef @Recipients;
    undef @Warnings;
    undef @AddedParts;
    undef @StatusTags;
    undef @ESMTPArgs;
    undef @SenderESMTPArgs;
    undef $results_fh;
}

=item print_and_flush(text)

Prints to stdout and flush buffer.

=cut

sub print_and_flush
{
	local $| = 1;
	print($_[0], "\n");
}

=item md_openlog(tag, facility)

Initialize e syslog object using Sys::Syslog or Unix::Syslog as
appropriate.

=item md_syslog(facility, msg)

Prints a message to syslog(3) using the specified facility

=cut

{
	# Reworked detection/usage of Sys::Syslog or Unix::Syslog as
	# appropriate is mostly borrowed from Log::Syslog::Abstract, to which
	# I'd love to convert at some point.
	my $_syslogsub = undef;
	my $_openlogsub = undef;
	my $_fac_map   = undef;

	#***********************************************************************
	# %PROCEDURE: md_openlog
	# %ARGUMENTS:
	#  tag -- syslog tag ("mimedefang.pl")
	#  facility -- Syslog facility as a string
	# %RETURNS:
	#  Nothing
	# %DESCRIPTION:
	#  Opens a log using either Unix::Syslog or Sys::Syslog
	#***********************************************************************
	sub md_openlog
	{
		my ($tag, $facility) = @_;

		if( ! defined $_openlogsub ) {
			# Try Unix::Syslog first, then Sys::Syslog
			eval qq{use Unix::Syslog qw( :macros ); };
			if(!$@) {
				($_openlogsub, $_syslogsub) = _wrap_for_unix_syslog();
			} else {
				eval qq{use Sys::Syslog ();};
				if(!$@) {
					($_openlogsub, $_syslogsub) = _wrap_for_sys_syslog();
				} else {
					die q{Unable to detect either Unix::Syslog or Sys::Syslog};
				}
			}
		}

		return $_openlogsub->($tag, 'pid,ndelay', $facility);
	}

	#***********************************************************************
	# %PROCEDURE: md_syslog
	# %ARGUMENTS:
	#  facility -- Syslog facility as a string
	#  msg -- message to log
	# %RETURNS:
	#  Nothing
	# %DESCRIPTION:
	#  Calls syslog, either in Sys::Syslog or Unix::Syslog package
	#***********************************************************************
	sub md_syslog
	{
		my ($facility, $msg) = @_;

		if(!$_syslogsub) {
			md_openlog('mimedefang.pl', $SyslogFacility);
		}

		if (defined $MsgID && $MsgID ne 'NOQUEUE') {
			return $_syslogsub->($facility, '%s', $MsgID . ': ' . $msg);
		} else {
			return $_syslogsub->($facility, '%s', $msg);
		}
	}

	sub _wrap_for_unix_syslog
	{

		my $openlog = sub {
			my ($id, $flags, $facility) = @_;

			die q{first argument must be an identifier string} unless defined $id;
			die q{second argument must be flag string} unless defined $flags;
			die q{third argument must be a facility string} unless defined $facility;

			return Unix::Syslog::openlog( $id, _convert_flags( $flags ), _convert_facility( $facility ) );
		};

		my $syslog = sub {
			my $facility = shift;
			return Unix::Syslog::syslog( _convert_facility( $facility ), @_);
		};

		return ($openlog, $syslog);
	}

	sub _wrap_for_sys_syslog
	{

		my $openlog  = sub {
			# Debian Stretch version is 0.33_01...dammit!
			my $ver = $Sys::Syslog::VERSION;
			$ver =~ s/_.*//;
			if( $ver < 0.16 ) {
				# Older Sys::Syslog versions still need
				# setlogsock().  RHEL5 still ships with 0.13 :(
				Sys::Syslog::setlogsock([ 'unix', 'tcp', 'udp' ]);
			}
			return Sys::Syslog::openlog(@_);
		};
		my $syslog   = sub {
			return Sys::Syslog::syslog(@_);
		};

		return ($openlog, $syslog);
	}

	sub _convert_flags
	{
		my($flags) = @_;

		my $flag_map = {
			pid     => Unix::Syslog::LOG_PID(),
			ndelay  => Unix::Syslog::LOG_NDELAY(),
		};

		my $num = 0;
		foreach my $thing (split(/,/, $flags)) {
			next unless exists $flag_map->{$thing};
			$num |= $flag_map->{$thing};
		}
		return $num;
	}


	sub _convert_facility
	{
		my($facility) = @_;

		my $num = 0;
		foreach my $thing (split(/\|/, $facility)) {
			if (!defined($_fac_map) ||
			    !exists($_fac_map->{$thing})) {
				$_fac_map->{$thing} = _fac_to_num($thing);
			}
			next unless defined $_fac_map->{$thing};
			$num |= $_fac_map->{$thing};
		}
		return $num;
	}

	my %special = (
		error => 'err',
		panic => 'emerg',
	);

	# Some of the Unix::Syslog 'macros' tag exports aren't
	# constants, so we need to ignore them if found.
	my %blacklisted = map { $_ => 1 } qw(mask upto pri makepri fac);

        sub _fac_to_num
	{
		my ($thing) = @_;
		return undef if exists $blacklisted{$thing};
		$thing = $special{$thing} if exists $special{$thing};
		$thing = 'LOG_' . uc($thing);
		return undef unless grep { $_ eq $thing } @ {$Unix::Syslog::EXPORT_TAGS{macros} };
		return eval "Unix::Syslog::$thing()";
	}
}

=item md_graphdefang_log

This is called to log events that occur during mimedefang processing.
It should be called from mimedefang-filter with appropriate
event names and values.  Possible examples:
C<md_graphdefang_log('virus',$VirusName,$filename);>
C<md_graphdefang_log('spam',$hits);>
C<md_graphdefang_log('bad_filename',$filename,$extension);>

=cut

#***********************************************************************
# %PROCEDURE: md_graphdefang_log
# %ARGUMENTS:
#  event -- The name of the event that is being logged.  Examples
#           include virus, spam, mail, etc.
#  value1 -- (optional) A value associated with the event being logged.
#  value2 -- (optional) A value associated with the event being logged.
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  This is called to log events that occur during mimedefang processing.
#  It should be called from mimedefang-filter with appropriate
#  event names and values.  Possible examples:
#      md_graphdefang_log('virus',$VirusName,$filename);
#      md_graphdefang_log('spam',$hits);
#      md_graphdefang_log('bad_filename',$filename,$extension);
#***********************************************************************
sub md_graphdefang_log
{
    return unless defined($GraphDefangSyslogFacility);
    return if (!in_message_context("md_graphdefang_log"));

    my $event = shift;
    my $value1 = shift;
    my $value2 = shift;

    $value1 = "" unless defined($value1);
    $value2 = "" unless defined($value2);

    my $lcsender = percent_encode_for_graphdefang(lc($Sender));

    # Make values safe for graphdefang
    my $id = percent_encode_for_graphdefang($MsgID);
    my $subj = percent_encode_for_graphdefang($Subject);
    $event = percent_encode_for_graphdefang($event);
    $value1 = percent_encode_for_graphdefang($value1);
    $value2 = percent_encode_for_graphdefang($value2);
    if ($EnumerateRecipients || scalar(@Recipients) == 1) {
	foreach my $recipient (@Recipients) {
	    my $lcrecipient = percent_encode_for_graphdefang(lc($recipient));
	    md_syslog("$GraphDefangSyslogFacility|info","MDLOG,$id," .
		      "$event,$value1,$value2,$lcsender," .
		      "$lcrecipient,$subj");
	}
    } else {
	my $lcrecipient = "rcpts=" . scalar(@Recipients);
	$lcrecipient = percent_encode_for_graphdefang($lcrecipient);
	md_syslog("$GraphDefangSyslogFacility|info","MDLOG,$id," .
		  "$event,$value1,$value2,$lcsender," .
		  "$lcrecipient,$subj");
    }
}

=item detect_and_load_perl_modules

Automatically detect and load Perl modules needed for some features
like SpamAssassin, rbl checks, zip file listing and HTML parsing.

=cut

# Detect these Perl modules at run-time.  Can explicitly prevent
# loading of these modules by setting $Features{"xxx"} = 0;
#
# You can turn off ALL auto-detection by setting
# $Features{"AutoDetectPerlModules"} = 0;

sub detect_and_load_perl_modules() {
    if (!defined($Features{"AutoDetectPerlModules"}) or
      $Features{"AutoDetectPerlModules"}) {
      if (!defined($Features{"SpamAssassin"}) or ($Features{"SpamAssassin"} eq 1)) {
        (eval 'use Mail::SpamAssassin (); $Features{"SpamAssassin"} = 1;')
        or $Features{"SpamAssassin"} = 0;
      }
      if (!defined($Features{"HTML::Parser"}) or ($Features{"HTML::Parser"} eq 1)) {
        (eval 'use HTML::Parser; $Features{"HTML::Parser"} = 1;')
        or $Features{"HTML::Parser"} = 0;
      }
      if (!defined($Features{"Archive::Zip"}) or ($Features{"Archive::Zip"} eq 1)) {
        (eval 'use Archive::Zip; $Features{"Archive::Zip"} = 1;')
        or $Features{"Archive::Zip"} = 0;
      }
      if (!defined($Features{"Net::DNS"}) or ($Features{"Net::DNS"} eq 1)) {
        (eval 'use Net::DNS; $Features{"Net::DNS"} = 1;')
        or $Features{"Net::DNS"} = 0;
      }
      if(exists &Mail::MIMEDefang::Actions::md_init) {
        Mail::MIMEDefang::Action::md_init();
      }
      if(exists &Mail::MIMEDefang::Antispam::md_init) {
        Mail::MIMEDefang::Antispam::md_init();
      }
      if(exists &Mail::MIMEDefang::Antivirus::md_init) {
        Mail::MIMEDefang::Antivirus::md_init();
      }
      if(exists &Mail::MIMEDefang::Mail::md_init) {
        Mail::MIMEDefang::Mail::md_init();
      }
      if(exists &Mail::MIMEDefang::MIME::md_init) {
        Mail::MIMEDefang::MIME::md_init();
      }
      if(exists &Mail::MIMEDefang::Net::md_init) {
        Mail::MIMEDefang::Net::md_init();
      }
      if(exists &Mail::MIMEDefang::RFC2822::md_init) {
        Mail::MIMEDefang::RFC2822::md_init();
      }
      if(exists &Mail::MIMEDefang::Utils::md_init) {
        Mail::MIMEDefang::Utils::md_init();
      }
    }
}

=item detect_antivirus_support

Check if antivirus support should be loaded by looking at %Features

=cut

# Detect if antivirus support should be enabled
sub detect_antivirus_support() {
  return 1 if (!defined $Features{"AutoDetectPerlModules"});
  foreach my $k ( keys %Features ) {
    if($k =~ /^Virus\:/) {
      if($Features{$k} ne 0) {
        return 1;
      }
    }
  }
  return 0;
}

=item init_status_tag

Open the status file descriptor

=cut

# Try to open the status descriptor
sub init_status_tag
{
	return unless $DoStatusTags;

	if(open(STATUS_HANDLE, ">&=3")) {
		STATUS_HANDLE->autoflush(1);
	} else {
		$DoStatusTags = 0;
	}
}

=item set_status_tag(depth, tag)

Sets the status tag for this worker inside the multiplexor.

=cut

#***********************************************************************
# %PROCEDURE: set_status_tag
# %ARGUMENTS:
#  nest_depth -- nesting depth
#  tag -- status tag
# %DESCRIPTION:
#  Sets the status tag for this worker inside the multiplexor.
# %RETURNS:
#  Nothing
#***********************************************************************
sub set_status_tag
{
	return unless $DoStatusTags;

	my ($depth, $tag) = @_;
	$tag ||= '';

	if($tag eq '') {
		print STATUS_HANDLE "\n";
		return;
	}
	$tag =~ s/[^[:graph:]]/ /g;

	if(defined($MsgID) and ($MsgID ne "NOQUEUE")) {
		print STATUS_HANDLE percent_encode("$depth: $tag $MsgID") . "\n";
	} else {
		print STATUS_HANDLE percent_encode("$depth: $tag") . "\n";
	}
}

=item push_status_tag(tag)

Updates status tag inside multiplexor and pushes onto stack.

=cut

#***********************************************************************
# %PROCEDURE: push_status_tag
# %ARGUMENTS:
#  tag -- tag describing current status
# %DESCRIPTION:
#  Updates status tag inside multiplexor and pushes onto stack.
# %RETURNS:
#  Nothing
#***********************************************************************
sub push_status_tag
{
	return unless $DoStatusTags;

	my ($tag) = @_;
	push(@StatusTags, $tag);
	if($tag ne '') {
		$tag = "> $tag";
	}
	set_status_tag(scalar(@StatusTags), $tag);
}

=item pop_status_tag

Pops previous status of stack and sets tag in multiplexor.

=cut

#***********************************************************************
# %PROCEDURE: pop_status_tag
# %ARGUMENTS:
#  None
# %DESCRIPTION:
#  Pops previous status of stack and sets tag in multiplexor.
# %RETURNS:
#  Nothing
#***********************************************************************
sub pop_status_tag
{
	return unless $DoStatusTags;

	pop @StatusTags;

	my $tag = $StatusTags[0] || 'no_tag';

	set_status_tag(scalar(@StatusTags), "< $tag");
}

=item percent_encode(str)

Encode a string with unsafe chars as "%XY" where X and Y are hex digits.

=cut

#***********************************************************************
# %PROCEDURE: percent_encode
# %ARGUMENTS:
#  str -- a string, possibly with newlines and control characters
# %RETURNS:
#  A string with unsafe chars encoded as "%XY" where X and Y are hex
#  digits.  For example:
#  "foo\r\nbar\tbl%t" ==> "foo%0D%0Abar%09bl%25t"
#***********************************************************************
sub percent_encode {
  my($str) = @_;

  $str =~ s/([^\x21-\x7e]|[%\\'"])/sprintf("%%%02X", unpack("C", $1))/ge;
  #" Fix emacs highlighting...
  return $str;
}

=item percent_encode_for_graphdefang(str)

Encode a string with unsafe chars as "%XY" where X and Y are hex digits.

Quotes or spaces are not encoded but commas are encoded.

=cut

#***********************************************************************
# %PROCEDURE: percent_encode_for_graphdefang
# %ARGUMENTS:
#  str -- a string, possibly with newlines and control characters
# %RETURNS:
#  A string with unsafe chars encoded as "%XY" where X and Y are hex
#  digits.  For example:
#  "foo\r\nbar\tbl%t" ==> "foo%0D%0Abar%09bl%25t"
# This differs slightly from percent_encode because we don't encode
# quotes or spaces, but we do encode commas.
#***********************************************************************
sub percent_encode_for_graphdefang {
  my($str) = @_;
  $str =~ s/([^\x20-\x7e]|[%\\,])/sprintf("%%%02X", unpack("C", $1))/ge;
  #" Fix emacs highlighting...
  return $str;
}

=item percent_decode(str)

Decode a string previously encoded by percent_encode().

=cut

#***********************************************************************
# %PROCEDURE: percent_decode
# %ARGUMENTS:
#  str -- a string encoded by percent_encode
# %RETURNS:
#  The decoded string.  For example:
#  "foo%0D%0Abar%09bl%25t" ==> "foo\r\nbar\tbl%t"
#***********************************************************************
sub percent_decode {
  my($str) = @_;
  $str =~ s/%([0-9A-Fa-f]{2})/pack("C", hex($1))/ge;
  return $str;
}

=item write_result_line ( $cmd, @args )

Writes a result line to the RESULTS file.

$cmd should be a one-letter command for the RESULTS file

@args are the arguments for $cmd, if any.  They will be percent_encode()'ed
before being written to the file.

Returns 0 or 1 and an optional warning message.

=cut

sub write_result_line
{
        my $cmd = shift;

        # Do nothing if we don't yet have a dedicated working directory
        if ($CWD eq $Features{'Path:SPOOLDIR'}) {
                md_syslog('warning', "write_result_line called before working directory established");
                return;
        }

        my $line = $cmd . join ' ', map { percent_encode($_) } @_;

        if (!$results_fh) {
                $results_fh = IO::File->new('>>RESULTS');
                if (!$results_fh) {
                        die("Could not open RESULTS file: $!");
                }
        }

        # We have a 16kb limit on the length of lines in RESULTS, including
        # trailing newline and null used in the milter.  So, we limit $cmd +
        # $args to 16382 bytes.
        if( length $line > 16382 ) {
                md_syslog( 'warning',  "Cannot write line over 16382 bytes long to RESULTS file; truncating.  Original line began with: " . substr $line, 0, 40);
                $line = substr $line, 0, 16382;
        }

        print $results_fh "$line\n" or die "Could not write RESULTS line: $!";

        return;
}

=item signal_unchanged

Tells mimedefang C program message has not been altered.

=cut

#***********************************************************************
# %PROCEDURE: signal_unchanged
# %ARGUMENTS:
#  None
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Tells mimedefang C program message has not been altered (does nothing...)
#***********************************************************************
sub signal_unchanged {
}

=item signal_changed

Tells mimedefang C program message has been altered.

=cut

#***********************************************************************
# %PROCEDURE: signal_changed
# %ARGUMENTS:
#  None
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Tells mimedefang C program message has been altered.
#***********************************************************************
sub signal_changed {
    write_result_line("C", "");
}

=item in_message_context(name)

Returns 1 if we are processing a message; 0 otherwise.

=cut

#***********************************************************************
# %PROCEDURE: in_message_context
# %ARGUMENTS:
#  name -- a string to syslog if we are not in a message context
# %RETURNS:
#  1 if we are processing a message; 0 otherwise.  Returns 0 if
#  we're in filter_relay, filter_sender or filter_recipient
#***********************************************************************
sub in_message_context {
    my($name) = @_;
    return 1 if ($InMessageContext);
    md_syslog('warning', "$name called outside of message context");
    return 0;
}

=item in_filter_wrapup(name)

Returns 1 if we are not in filter wrapup; 0 otherwise.

=cut

#***********************************************************************
# %PROCEDURE: in_filter_wrapup
# %ARGUMENTS:
#  name -- a string to syslog if we are in filter wrapup
# %RETURNS:
#  1 if we are not in filter wrapup; 0 otherwise.
#***********************************************************************
sub in_filter_wrapup {
    my($name) = @_;
    if ($InFilterWrapUp) {
	    md_syslog('warning', "$name called inside filter_wrapup context");
	    return 1;
    }
    return 0;
}

=item in_filter_context

Returns 1 if we are inside filter or filter_multipart, 0 otherwise.

=cut

#***********************************************************************
# %PROCEDURE: in_filter_context
# %ARGUMENTS:
#  name -- a string to syslog if we are not in a filter context
# %RETURNS:
#  1 if we are inside filter or filter_multipart, 0 otherwise.
#***********************************************************************
sub in_filter_context {
    my($name) = @_;
    return 1 if ($InFilterContext);
    md_syslog('warning', "$name called outside of filter context");
    return 0;
}

=item in_filter_end(name)

Returns 1 if we are inside filter_end 0 otherwise.

=cut

#***********************************************************************
# %PROCEDURE: in_filter_end
# %ARGUMENTS:
#  name -- a string to syslog if we are not in filter_end
# %RETURNS:
#  1 if we are inside filter_end 0 otherwise.
#***********************************************************************
sub in_filter_end {
    my($name) = @_;
    return 1 if ($InFilterEnd);
    md_syslog('warning', "$name called outside of filter_end");
    return 0;
}

=item send_quarantine_notifications

Sends quarantine notification message, if anything was quarantined.

=cut

#***********************************************************************
# %PROCEDURE: send_quarantine_notifications
# %ARGUMENTS:
#  None
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Sends quarantine notification message, if anything was quarantined
#***********************************************************************
sub send_quarantine_notifications {
  # If there are quarantined parts, e-mail a report
  if ($QuarantineCount > 0 || $EntireMessageQuarantined) {
	  my($body);
	  $body = "From: $DaemonName <$DaemonAddress>\n";
	  $body .= "To: \"$AdminName\" <$AdminAddress>\n";
	  $body .= gen_date_msgid_headers();
	  $body .= "Auto-Submitted: auto-generated\n";
	  $body .= "MIME-Version: 1.0\nContent-Type: text/plain\n";
	  $body .= "Precedence: bulk\n";
	  $body .= "Subject: $QuarantineSubject\n\n";
	  if ($QuarantineCount >= 1) {
	    $body .= "An e-mail had $QuarantineCount part";
	    $body .= "s" if ($QuarantineCount != 1);
	  } else {
	    $body .= "An e-mail message was";
	  }

	  $body .= " quarantined in the directory\n";
	  $body .= "$QuarantineSubdir on " . get_host_name() . ".\n\n";
	  $body .= "The sender was '$Sender'.\n\n" if defined($Sender);
	  $body .= "The Sendmail queue identifier was $QueueID.\n\n" if ($QueueID ne "NOQUEUE");
	  $body .= "The relay machine was $RelayHostname ($RelayAddr).\n\n";
	  if ($EntireMessageQuarantined) {
	    $body .= "The entire message was quarantined in $QuarantineSubdir/ENTIRE_MESSAGE\n\n";
	  }

	  my($recip);
	  foreach $recip (@Recipients) {
	    $body .= "Recipient: $recip\n";
	  }
 	  my $donemsg = 0;
	  my $i;
	  for ($i=0; $i<=$QuarantineCount; $i++) {
	    if (open(IN, "<$QuarantineSubdir/MSG.$i")) {
		    if (!$donemsg) {
		      $body .= "Quarantine Messages:\n";
		      $donemsg = 1;
	 	    }
		    while(<IN>) {
		      $body .= $_;
		    }
		    close(IN);
	    }
	  }
	  if ($donemsg) {
	    $body .= "\n";
	  }

	  if (open(IN, "<$QuarantineSubdir/HEADERS")) {
	    $body .= "\n----------\nHere are the message headers:\n";
	    while(<IN>) {
		    $body .= $_;
	    }
	    close(IN);
	  }
	  for ($i=1; $i<=$QuarantineCount; $i++) {
	    if (open(IN, "<$QuarantineSubdir/PART.$i.HEADERS")) {
		    $body .= "\n----------\nHere are the headers for quarantined part $i:\n";
		    while(<IN>) {
		      $body .= $_;
		    }
		    close(IN);
	    }
	  }
	  if ($#Warnings >= 0) {
	    $body .= "\n----------\nHere are the warning details:\n\n";
	    $body .= "@Warnings";
	  }
	  send_mail($DaemonAddress, $DaemonName, $AdminAddress, $body);
  }
}

=item signal_complete

Tells mimedefang C program Perl filter has finished successfully.

Also mails any quarantine notifications and sender notifications.

=cut

#***********************************************************************
# %PROCEDURE: signal_complete
# %ARGUMENTS:
#  None
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Tells mimedefang C program Perl filter has finished successfully.
#  Also mails any quarantine notifications and sender notifications.
#***********************************************************************
sub signal_complete {
  # Send notification to sender, if required
  if ($Sender ne '<>' && -r "NOTIFICATION") {
	  my($body);
	  $body = "From: $DaemonName <$DaemonAddress>\n";
	  $body .= "To: $Sender\n";
	  $body .= gen_date_msgid_headers();
	  $body .= "Auto-Submitted: auto-generated\n";
	  $body .= "MIME-Version: 1.0\nContent-Type: text/plain\n";
	  $body .= "Precedence: bulk\n";
	  $body .= "Subject: $NotifySenderSubject\n\n";
	  unless($NotifyNoPreamble) {
	    $body .= "An e-mail you sent with message-id $MessageID\n";
	    $body .= "was modified by our mail scanning software.\n\n";
	    $body .= "The recipients were:";
	    my($recip);
	    foreach $recip (@Recipients) {
		    $body .= " $recip";
	    }
	    $body .= "\n\n";
	  }
	  if (open(FILE, "<NOTIFICATION")) {
	    unless($NotifyNoPreamble) {
		    $body .= "Here are the details of the modification:\n\n";
	    }
	    while(<FILE>) {
		    $body .= $_;
	    }
	    close(FILE);
	  }
	  send_mail($DaemonAddress, $DaemonName, $Sender, $body);
  }

  # Send notification to administrator, if required
  if (-r "ADMIN_NOTIFICATION") {
	my $body = "";
	  if (open(FILE, "<ADMIN_NOTIFICATION")) {
	    $body .= join('', <FILE>);
	    close(FILE);
	    send_admin_mail($NotifyAdministratorSubject, $body);
	  }
  }

  # Syslog some info if any actions were taken
  my($msg) = "";
  my($key, $num);
  foreach $key (sort keys(%Actions)) {
	  $num = $Actions{$key};
	  $msg .= " $key=$num";
  }
  if ($msg ne "") {
	  md_syslog('debug', "filter: $msg");
  }
  write_result_line("F", "");
  if ($results_fh) {
	  $results_fh->close() or die("Could not close RESULTS file: $!");
	  undef $results_fh;
  }

  if ($ServerMode) {
	  print_and_flush('ok');
  }
}

=item send_mail(fromAddr, fromFull, recipient, body, deliverymode)

Sends a mail message using Sendmail.

Invokes Sendmail without involving the shell, so that shell metacharacters won't cause security problems.

Deliverimode parameter is the optional sendmail delivery mode arg (default "-odd").

=cut

#***********************************************************************
# %PROCEDURE: send_mail
# %ARGUMENTS:
#  fromAddr -- address of sender
#  fromFull -- full name of sender
#  recipient -- address of recipient
#  body -- mail message (including headers) newline-terminated
#  deliverymode -- optional sendmail delivery mode arg (default "-odd")
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Sends a mail message using Sendmail.  Invokes Sendmail without involving
#  the shell, so that shell metacharacters won't cause security problems.
#***********************************************************************
sub send_mail {
  my($fromAddr, $fromFull, $recipient, $body, $deliverymode) = @_;

  $deliverymode = "-odd" unless defined($deliverymode);
  if ($deliverymode ne "-odb" &&
	  $deliverymode ne "-odq" &&
	  $deliverymode ne "-odd" &&
	  $deliverymode ne "-odi") {
	  $deliverymode = "-odd";
  }

  my($pid);

  # Fork and exec for safety instead of involving shell
  $pid = open(CHILD, "|-");
  if (!defined($pid)) {
	  md_syslog('err', "Cannot fork to run sendmail");
	  return;
  }

  if ($pid) {   # In the parent -- pipe mail message to the child
	  print CHILD $body;
	  close(CHILD);
	  return;
  }

  # In the child -- invoke Sendmail

  # Direct stdout to stderr, or we will screw up communication with
  # the multiplexor..
  open(STDOUT, ">&STDERR");

  my(@cmd);
  if ($fromAddr ne "") {
	  push(@cmd, "-f$fromAddr");
  } else {
	  push(@cmd, "-f<>");
  }
  if ($fromFull ne "") {
	  push(@cmd, "-F$fromFull");
  }
  push(@cmd, $deliverymode);
  push(@cmd, "-Ac");
  push(@cmd, "-oi");
  push(@cmd, "--");
  push(@cmd, $recipient);

  # In curlies to silence Perl warning...
  my $sm;
  $sm = $Features{'Path:SENDMAIL'};
  { exec($sm, @cmd); }

  # exec failed!
  md_syslog('err', "Could not exec $sm: $!");
  exit(1);
  # NOTREACHED
}

=item send_admin_mail(subject, body)

Sends a mail message to the administrator

=cut

#***********************************************************************
# %PROCEDURE: send_admin_mail
# %ARGUMENTS:
#  subject -- mail subject
#  body -- mail message (without headers) newline-terminated
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Sends a mail message to the administrator
#***********************************************************************
sub send_admin_mail {
  my ($subject, $body) = @_;

  my $mail;
  $mail = "From: $DaemonName <$DaemonAddress>\n";
  $mail .= "To: \"$AdminName\" <$AdminAddress>\n";
  $mail .= gen_date_msgid_headers();
  $mail .= "Auto-Submitted: auto-generated\n";
  $mail .= "MIME-Version: 1.0\nContent-Type: text/plain\n";
  $mail .= "Precedence: bulk\n";
  $mail .= "Subject: $subject\n\n";
  $mail .= $body;

  send_mail($DaemonAddress, $DaemonName, $AdminAddress, $mail);
}

=back

=over 4

=back

=head2 SEE ALSO

L<Mail::MIMEDefang::Actions(3)>

L<Mail::MIMEDefang::Antispam(3)>

L<Mail::MIMEDefang::Antivirus(3)>

L<Mail::MIMEDefang::DKIM(3)>

L<Mail::MIMEDefang::DKIM::ARC(3)>

L<Mail::MIMEDefang::DKIM::Authres(3)>

L<Mail::MIMEDefang::Mail(3)>

L<Mail::MIMEDefang::MIME(3)>

L<Mail::MIMEDefang::Net(3)>

L<Mail::MIMEDefang::RFC2822(3)>

L<Mail::MIMEDefang::Unit(3)>

L<Mail::MIMEDefang::Utils(3)>

=cut

1;
