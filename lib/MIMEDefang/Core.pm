package MIMEDefang::Core;

require Exporter;

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
}

1;
