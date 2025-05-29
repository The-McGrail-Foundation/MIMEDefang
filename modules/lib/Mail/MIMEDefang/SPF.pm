#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::SPF - Sender Policy Framework interface for MIMEDefang

=head1 DESCRIPTION

Mail::MIMEDefang::SPF is a module used to check for Sender Policy Framework
headers from F<mimedefang-filter>.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::SPF;

use strict;
use warnings;

require Exporter;

use Mail::SPF;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(md_spf_verify);

=item md_spf_verify

Returns code and explanation of Sender Policy Framework
check.
Additional optional return values are code and explanation
of helo SPF query, 5th and 6th return values are the SPF dns
records if they are available;

Possible return code values are:
"pass", "fail", "softfail", "neutral", "none", "error", "permerror", "temperror", "invalid"

The method accepts the following parameters:

=over 4

=item C<$email>

The email address of the sender

=item C<$relayip>

The relay ip address

=item C<$helo> (optional)

The MTA helo server name

=back

=cut

sub md_spf_verify {

  my ($spfmail, $relayip, $helo) = @_;

  if(not defined $spfmail and not defined $relayip) {
    md_syslog('err', "Cannot check SPF without email address and relay ip");
    return;
  }

  # RFC 4408 defines the maximum number of terms (mechanisms and modifiers) per SPF check that perform DNS look-ups
  # to 10.
  # In practice 10 lookups are not enough for some domains.
  my $spf_server  = Mail::SPF::Server->new(max_dns_interactive_terms => 20);
  my ($spfres, $helo_spfres);
  $spfmail =~ s/^<//;
  $spfmail =~ s/>$//;
  if(defined $spfmail and $spfmail ne '') {
    if($spfmail =~ /(.*)\+(?:.*)\@(.*)/) {
      $spfmail = $1 . '@' . $2;
    }
    my $request;
    eval {
      local $SIG{__WARN__} = sub {
        my $warn = $_[0];
        $warn =~ s/\n//g;
        $warn =~ s/\bat .{10,100} line \d+\.//g;
        md_syslog("Warning", "md_spf_verify: $warn");
      };
      $request          = Mail::SPF::Request->new(
        scope           => 'mfrom',
        identity        => $spfmail,
        ip_address      => $relayip,
      );
      $spfres = $spf_server->process($request);
    };
  } else {
    return ('invalid', 'Invalid mail from parameter');
  }
  if(defined $helo) {
    my $helo_request;
    eval {
      local $SIG{__WARN__} = sub {
        my $warn = $_[0];
        $warn =~ s/\n//g;
        $warn =~ s/\bat .{10,100} line \d+\.//g;
        md_syslog("Warning", "md_spf_verify: $warn");
      };
      $helo_request     = Mail::SPF::Request->new(
        scope           => 'helo',
        identity        => $helo,
        ip_address      => $relayip,
      );
      $helo_spfres = $spf_server->process($helo_request);
    };
  }
  my $spf_record;
  my $helospf_record;
  eval {
    $spf_record = $spfres->request->record->text;
    $helospf_record = $helo_spfres->request->record->text();
  };
  if(defined $helo) {
    return ($spfres->code, $spfres->local_explanation, $helo_spfres->code, $helo_spfres->local_explanation, $spf_record, $helospf_record);
  } else {
    return ($spfres->code, $spfres->local_explanation, undef, undef, $spf_record);
  }
}

=back

=cut

1;
