package MIMEDefang::Core;

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
    };

@EXPORT_OK = qw{
      init_globals
      };

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

1;
