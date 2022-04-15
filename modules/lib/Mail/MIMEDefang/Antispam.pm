#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Antispam - antispam related methods for email filters

=head1 DESCRIPTION

Mail::MIMEDefang::Antispam are a set of methods that can be called
from F<mimedefang-filter> to check email messages with antispam softwares.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Antispam;

use strict;
use warnings;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Utils;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(spam_assassin_init spam_assassin_mail spam_assassin_check
            spam_assassin_status spam_assassin_is_spam
            rspamd_check);

=item spam_assassin_is_spam

Method that scans a mmessage using SpamAssassin and returns True if the email
message has been detected as spam.

=cut

#***********************************************************************
# %PROCEDURE: spam_assassin_is_spam
# %ARGUMENTS:
#  config -- optional configuration file
# %RETURNS:
#  1 if SpamAssassin thinks current message is SPAM; 0 otherwise
#  or if message could not be opened.
# %DESCRIPTION:
#  Scans message using SpamAssassin (http://www.spamassassin.org)
#***********************************************************************
sub spam_assassin_is_spam {

    my($hits, $req, $tests, $report) = spam_assassin_check(@_);
    return undef if (!defined($hits));

    return ($hits >= $req);
}

=item spam_assassin_check

Method that scans a message using SpamAssassin and returns an array of four
elements,

=over 4

=item * Weight of message ('hits')

=item * Number of hits required before SA considers a message spam

=item * Comma separated list of symbolic test names that were triggered

=item * A 'report' string, detailing tests that failed and their weights

=back

=cut

#***********************************************************************
# %PROCEDURE: spam_assassin_check
# %ARGUMENTS:
#  config -- optional spamassassin config file
# %RETURNS:
#  An array of four elements,
#       Weight of message ('hits')
#       Number of hits required before SA considers a message spam
#       Comma separated list of symbolic test names that were triggered
#       A 'report' string, detailing tests that failed and their weights
# %DESCRIPTION:
#  Scans message using SpamAssassin (http://www.spamassassin.org)
#***********************************************************************
sub spam_assassin_check {

    my($status) = spam_assassin_status(@_);
    return undef if (!defined($status));

    my $hits = $status->get_hits;
    my $req = $status->get_required_hits();
    my $tests = $status->get_names_of_tests_hit();
    my $report = $status->get_report();

    $status->finish();

    return ($hits, $req, $tests, $report);
}

=item spam_assassin_status

Method that scans a mmessage using SpamAssassin and returns a
C<Mail::SpamAssassin:PerMsgStatus> object.
The caller is responsible for calling the C<finish> method.

=cut

#***********************************************************************
# %PROCEDURE: spam_assassin_status
# %ARGUMENTS:
#  config -- optional spamassassin config file
# %RETURNS:
#  A Mail::SpamAssassin:PerMsgStatus object.
#  CALLER IS RESPONSIBLE FOR CALLING finish()
# %DESCRIPTION:
#  Scans message using SpamAssassin (http://www.spamassassin.org)
#***********************************************************************
sub spam_assassin_status {

    my $object = spam_assassin_init(@_);
    return undef unless $object;

    my $mail = spam_assassin_mail();
    return undef unless $mail;

    my $status;
    push_status_tag("Running SpamAssassin");
    $status = $object->check($mail);
    $mail->finish();
    pop_status_tag();
    return $status;
}

=item spam_assassin_init

Initialize Apache SpamAssassin and returns a C<Mail::SpamAssassin> object.

=cut

#***********************************************************************
# %PROCEDURE: spam_assassin_init
# %ARGUMENTS:
#  config -- optional spamassassin config file
# %RETURNS:
#  A Mail::SpamAssassin object.
# %DESCRIPTION:
#  Scans message using SpamAssassin (http://www.spamassassin.org)
#***********************************************************************
sub spam_assassin_init {
    my ($config) = @_;

    unless ($Features{"SpamAssassin"}) {
	md_syslog('err', "Attempt to call SpamAssassin function, but SpamAssassin is not installed.");
	return undef;
    }

    if (!defined($SASpamTester)) {

	push_status_tag("Creating SpamAssasin Object");

	my $sa_args = {
		local_tests_only   => $SALocalTestsOnly,
		dont_copy_prefs    => 1,
		user_dir           => $Features{'Path:QUARANTINEDIR'},
	};

	$SASpamTester = Mail::SpamAssassin->new( $sa_args );
	pop_status_tag();
    }

    return $SASpamTester;
}

=item spam_assassin_mail

Method that calls SpamAssassin and returns
a C<Mail::SpamAssassin::Message> object.

=cut

#***********************************************************************
# %PROCEDURE: spam_assassin_mail
# %ARGUMENTS:
#  none
# %RETURNS:
#  A Mail::SpamAssassin::Message object
#***********************************************************************
sub spam_assassin_mail {

    unless ($Features{"SpamAssassin"}) {
	md_syslog('err', "Attempt to call SpamAssassin function, but SpamAssassin is not installed.");
	return undef;
    }

    open(IN, "<./INPUTMSG") or return undef;
    my @msg = <IN>;
    close(IN);

    # Synthesize a "Return-Path" and "Received:" header
    my @sahdrs;
    push (@sahdrs, "Return-Path: $Sender\n");
    push (@sahdrs, split(/^/m, synthesize_received_header()));

    if ($AddApparentlyToForSpamAssassin and
	($#Recipients >= 0)) {
	push(@sahdrs, "Apparently-To: " .
	     join(", ", @Recipients) . "\n");
    }
    unshift (@msg, @sahdrs);
    if (!defined($SASpamTester)) {
	spam_assassin_init(@_);
	return undef unless $SASpamTester;
    }
    return $SASpamTester->parse(\@msg);
}

=item rspamd_check

Method that scans the message using Rspamd and returns an array of six elemets:

=over 4

=item * Weight of message ('hits')

=item * Number of hits required before Rspamd considers a message spam

=item * Comma separated list of symbolic test names that were triggered

=item * A 'report' string, detailing tests that failed and their weights
  or a Json report if JSON and LWP modules are present

=item * An action that should be applied to the email

=item * A flag explaining if the email is a spam message or not (true/false).

=back

An optional rspamd url can be passed to the method, its default value
is http://127.0.0.1:11333.

=cut

#***********************************************************************
# %PROCEDURE: rspamd_check
# %ARGUMENTS:
#  an Rspamd url -- defaults to http://127.0.0.1:11333
# %RETURNS:
#  An array of six elements,
#       Weight of message ('hits')
#       Number of hits required before Rspamd considers a message spam
#       Comma separated list of symbolic test names that were triggered
#       A 'report' string, detailing tests that failed and their weights
#       or a Json report if JSON and LWP modules are present
#       An action that should be applied to the email
#       A flag is_spam true/false
# %DESCRIPTION:
#  Scans message using Rspamd (http://rspamd.org)
#***********************************************************************
sub rspamd_check {
    my ($uri) = @_;
    my $rp;
    my ($hits, $req, $action, $is_spam);
    my $tests = '';
    my $report = '';

    $uri = 'http://127.0.0.1:11333' if not defined $uri;

    # Check if required modules are available
    my $rspamc;
    (eval 'use JSON (); use LWP::UserAgent (); $rspamc = 1;') or $rspamc = 0;

    unless ($Features{"Path:RSPAMC"} or $rspamc = 1) {
        md_syslog('err', "Attempt to call Rspamd function, but Rspamd is not installed or JSON and LWP modules not available.");
        return undef;
    }
    # forking method is deprecated
    if($Features{"Path:RSPAMC"}) {
      md_syslog("Warning", "Using fork method to check Rspamd server (deprecated)");
      $rspamc = 0;
    }

    if($rspamc eq 1) {
      my $ua = LWP::UserAgent->new;
      $ua->agent("MIMEDefang");

      # slurp the mail message
      open my $fh, '<', "./INPUTMSG" or return undef;
      $/ = undef;
      my $mail = <$fh>;
      close $fh;
      my $req = HTTP::Request->new(POST => "$uri/checkv2");
      $req->content("$mail");

      my $res = $ua->request($req);
      if ($res->is_success) {
	my $json = JSON->new->allow_nonref;
        my $rspamd_res = $json->decode( $res->content );
        $hits = $rspamd_res->{score};
        $req = $rspamd_res->{required_score};
        $action = $rspamd_res->{action};
	my %sym = %{$rspamd_res->{symbols}};
        foreach my $test ( keys %sym ) {
          $tests .= $sym{$test}->{name} . " (" . $sym{$test}->{score} . "), ";
        }
	$tests =~ s/, $//;
        if($hits >= $req) {
	  $is_spam = "true";
	} else {
	  $is_spam = "false";
	}
	$report = $res->content;
        return ($hits, $req, $tests, $report, $action, $is_spam);
      } else {
        md_syslog("Warning", "Cannot connect to Rspamd server, the message will be temporarily delayed");
        return (0, 0, '', '', "soft reject", "false");
      }
    } else {
      my @rs = ($Features{"Path:RSPAMC"}, "./INPUTMSG");

      if ( -f $Features{"Path:RSPAMC"} ) {
        open(RSPAMD_PIPE, "-|", @rs)
                        || die "can't open rspamc: $!";
        while(<RSPAMD_PIPE>) {
          $rp = $_;
          {
            if($rp =~ /Action: (.*)/) {
              $action = $1;
            }
          }
          {
            if($rp =~ /Spam: (.*)/) {
              $is_spam = $1;
            }
          }
          {
            if($rp =~ /Score: (.*) \/ (.*)/) {
              $hits = $1;
              $req = $2;
            }
          }
          {
            if($rp =~ /Symbol: (.*)/) {
              $tests .= $1 . ", ";
            }
          }
          $report .= $rp . "\n";
        }
        $tests =~ s/\, $//;
        close(RSPAMD_PIPE);
      }
    }

    return ($hits, $req, $tests, $report, $action, $is_spam);
}

=back

=cut

1;
