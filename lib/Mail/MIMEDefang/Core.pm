package Mail::MIMEDefang::Core;

require Exporter;

use Errno qw(ENOENT EACCES);
use File::Spec;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

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
      init_globals detect_and_load_perl_modules
      init_status_tag push_status_tag pop_status_tag
    };

@EXPORT_OK = qw(read_config set_status_tag write_result_line);

sub new {
    my ($class, @params) = @_;
    my $self = {};
    return bless $self, $class;
}

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
        (eval 'use Archive::Zip qw(:ERROR_CODES); $Features{"Archive::Zip"} = 1;')
        or $Features{"Archive::Zip"} = 0;
      }
      if (!defined($Features{"Net::DNS"}) or ($Features{"Net::DNS"} eq 1)) {
        (eval 'use Net::DNS; $Features{"Net::DNS"} = 1;')
        or $Features{"Net::DNS"} = 0;
      }
    }
}

#***********************************************************************
# %PROCEDURE: read_config
# %ARGUMENTS:
#  configuration file path
# %RETURNS:
#  return 1 if configuration file cannot be loaded; 0 otherwise
# %DESCRIPTION:
#  loads a configuration file to overwrite global variables values
#***********************************************************************
# Derivative work from amavisd-new read_config_file($$)
# Copyright (C) 2002-2018 Mark Martinec
sub read_config($) {
  my($config_file) = @_;

  $config_file = File::Spec->rel2abs($config_file);

  my(@stat_list) = stat($config_file);  # symlinks-friendly
  my $errn = @stat_list ? 0 : 0+$!;
  my $owner_uid = $stat_list[4];
  my $msg;

  if ($errn == ENOENT) { $msg = "does not exist" }
  elsif ($errn)        { $msg = "is inaccessible: $!" }
  elsif (-d _)         { $msg = "is a directory" }
  elsif (-S _ || -b _ || -c _) { $msg = "is not a regular file or pipe" }
  elsif ($owner_uid) { $msg = "should be owned by root (uid 0)" }
  if (defined $msg)    {
    return (1, $msg);
  }
  if (defined(do $config_file)) {}
  return (0, undef);
}

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

=pod

=head2 write_result_line ( $cmd, @args )

Writes a result line to the RESULTS file.

$cmd should be a one-letter command for the RESULTS file

@args are the arguments for $cmd, if any.  They will be percent_encode()'ed
before being written to the file.

Returns 0 or 1 and an optional warning message.

=cut

sub write_result_line
{
	my $cmd = shift;
  my $wmsg;

	# Do nothing if we don't yet have a dedicated working directory
	if ($CWD eq $Features{'Path:SPOOLDIR'}) {
		return (0, "write_result_line called before working directory established");
	}

	my $line = $cmd . join ' ', map { percent_encode($_) } @_;

	if (!$results_fh) {
		$results_fh = IO::File->new('>>RESULTS');
		if (!$results_fh) {
			return (0, "Could not open RESULTS file: $!");
		}
	}

	# We have a 16kb limit on the length of lines in RESULTS, including
	# trailing newline and null used in the milter.  So, we limit $cmd +
	# $args to 16382 bytes.
	if( length $line > 16382 ) {
		$wmsg = "Cannot write line over 16382 bytes long to RESULTS file; truncating.  Original line began with: " . substr $line, 0, 40;
		$line = substr $line, 0, 16382;
	}

	print $results_fh "$line\n" or return (0, "Could not write RESULTS line: $!");

	return (1, $wmsg);
}

1;
