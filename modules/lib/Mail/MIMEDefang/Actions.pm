#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Actions - actions methods for email filters

=head1 DESCRIPTION

Mail::MIMEDefang::Actions are a set of methods that can be called
from F<mimedefang-filter> to accept or reject the email message.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Actions;

use strict;
use warnings;

use Digest::SHA;

use Mail::MIMEDefang;
use Mail::MIMEDefang::Utils;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw{
  action_rebuild action_notify_sender action_insert_header action_drop
  action_bounce action_accept action_defang action_discard action_add_part
  action_tempfail action_add_header action_add_entity action_quarantine
  action_quarantine_entire_message action_change_header action_delete_header
  action_external_filter get_quarantine_dir
  action_replace_with_url action_drop_with_warning action_delete_all_headers
  message_rejected process_added_parts add_recipient delete_recipient change_sender
};

=item action_rebuild

Sets a flag telling MIMEDefang to rebuild message even if it is
unchanged.

=cut

#***********************************************************************
# %PROCEDURE: action_rebuild
# %ARGUMENTS:
#  None
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Sets a flag telling MIMEDefang to rebuild message even if it is
#  unchanged.
#***********************************************************************
sub action_rebuild {
    return undef unless (in_message_context("action_rebuild") && !in_filter_wrapup("action_rebuild"));
    $Rebuild = 1;
}

=item action_add_entity

Makes a note to add a part to the message.  Parts are *actually* added
at the end, which lets us correctly handle non-multipart messages or
multipart/foo where "foo" != "mixed".  Sets the rebuild flag.

=cut

#***********************************************************************
# %PROCEDURE: action_add_entity
# %ARGUMENTS:
#  entity -- the mime entity to add (must be pre-built)
#  location -- (optional) location at which to add part (default -1 = end)
# %RETURNS:
#  The entity object for the new part
# %DESCRIPTION:
#  Makes a note to add a part to the message.  Parts are *actually* added
#  at the end, which lets us correctly handle non-multipart messages or
#  multipart/foo where "foo" != "mixed".  Sets the rebuild flag.
#***********************************************************************
sub action_add_entity
{
	my($entity, $offset) = @_;

	return undef unless (in_message_context("action_add_part") && !in_filter_wrapup("action_add_part"));
	$offset = -1 unless defined($offset);
	push(@AddedParts, [$entity, $offset]);
	action_rebuild();
	return $entity;
}

=item action_add_part

Makes a note to add a part to the message.  Parts are *actually* added
at the end, which lets us correctly handle non-multipart messages or
multipart/foo where "foo" != "mixed".  Sets the rebuild flag.

=cut

#***********************************************************************
# %PROCEDURE: action_add_part
# %ARGUMENTS:
#  entity -- the mime entity
#  type -- the mime type
#  encoding -- see MIME::Entity(8)
#  data -- the data for the part
#  fname -- file name
#  disposition -- content-disposition header
#  location -- (optional) location at which to add part (default -1 = end)
# %RETURNS:
#  The entity object for the new part
# %DESCRIPTION:
#  Makes a note to add a part to the message.  Parts are *actually* added
#  at the end, which lets us correctly handle non-multipart messages or
#  multipart/foo where "foo" != "mixed".  Sets the rebuild flag.
#***********************************************************************
sub action_add_part {
    my ($entity)      = shift;
    my ($type)        = shift;
    my ($encoding)    = shift;
    my ($data)        = shift;
    my ($fname)       = shift;
    my ($disposition) = shift;
    my ($offset)      = shift;

    return undef unless (in_message_context("action_add_part") && !in_filter_wrapup("action_add_part"));

    $offset = -1 unless defined($offset);

    my ($part);

    $part = MIME::Entity->build(Type => $type,
				Top => 0,
				'X-Mailer' => undef,
				Encoding => $encoding,
				Data => ["$data"]);
    defined ($fname) && $part->head->mime_attr("Content-Type.name" => $fname);
    defined ($disposition) && $part->head->mime_attr("Content-Disposition" => $disposition);
    defined ($fname) && $part->head->mime_attr("Content-Disposition.filename" => $fname);

    return action_add_entity($part, $offset);
}

=item process_added_parts

Actually adds requested parts to entity.  Ensures that entity is
of type multipart/mixed.

=cut

#***********************************************************************
# %PROCEDURE: process_added_parts
# %ARGUMENTS:
#  rebuilt -- rebuilt entity
# %RETURNS:
#  A new entity with parts added
# %DESCRIPTION:
#  Actually adds requested parts to entity.  Ensures that entity is
#  of type multipart/mixed
#***********************************************************************
sub process_added_parts {
    my($rebuilt) = @_;
    my($entity);

    # If no parts to add, do nothing
    return $rebuilt if ($#AddedParts < 0);

    # Make sure we have a multipart/mixed container
    if (lc($rebuilt->head->mime_type) ne "multipart/mixed") {
	$entity = MIME::Entity->build(Type => "multipart/mixed",
				      'X-Mailer' => undef);
	$entity->add_part($rebuilt);
    } else {
	$entity = $rebuilt;
    }
    my $thing;
    foreach $thing (@AddedParts) {
	$entity->add_part($thing->[0], $thing->[1]);
    }
    return $entity;
}

=item action_insert_header

Makes a note for milter to insert a header in the message in the
specified position.  May not be supported on all versions of Sendmail;
on unsupported versions, the C milter falls back to action_add_header.

=cut

#***********************************************************************
# %PROCEDURE: action_insert_header
# %ARGUMENTS:
#  header -- header name (eg: X-My-Header)
#  value -- header value (eg: any text goes here)
#  position -- where to place it (eg: 0 [default] to make it first)
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note for milter to insert a header in the message in the
#  specified position.  May not be supported on all versions of Sendmail;
#  on unsupported versions, the C milter falls back to action_add_header.
#***********************************************************************
sub action_insert_header {
    my($header, $value, $pos) = @_;
    $pos = 0 unless defined($pos);
    write_result_line('N', $header, $pos, $value);
}

=item action_add_header

Makes a note for milter to add a header to the message.

=cut

#***********************************************************************
# %PROCEDURE: action_add_header
# %ARGUMENTS:
#  header -- header name (eg: X-My-Header)
#  value -- header value (eg: any text goes here)
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note for milter to add a header to the message.
#***********************************************************************
sub action_add_header {
    my($header, $value) = @_;
    write_result_line('H', $header, $value);
}

=item action_change_header

Makes a note for milter to change a header in the message.

=cut

#***********************************************************************
# %PROCEDURE: action_change_header
# %ARGUMENTS:
#  header -- header name (eg: X-My-Header)
#  value -- header value (eg: any text goes here)
#  index -- index of header to change (default 1)
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note for milter to change a header in the message.
#***********************************************************************
sub action_change_header {
    my($header, $value, $idx) = @_;
    return if (!in_message_context("action_change_header"));
    $idx = 1 unless defined($idx);

    write_result_line('I', $header, $idx, $value);
}

=item action_delete_header

Makes a note for milter to delete a header in the message.

=cut

#***********************************************************************
# %PROCEDURE: action_delete_header
# %ARGUMENTS:
#  header -- header name (eg: X-My-Header)
#  index -- index of header to delete (default 1)
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note for milter to delete a header in the message.
#***********************************************************************
sub action_delete_header {
    my($header, $idx) = @_;
    return if (!in_message_context("action_delete_header"));
    $idx = 1 unless defined($idx);

    write_result_line('J', $header, $idx);
}

=item action_delete_all_headers

Makes a note for milter to delete all instances of header.

=cut

#***********************************************************************
# %PROCEDURE: action_delete_all_headers
# %ARGUMENTS:
#  header -- header name (eg: X-My-Header)
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note for milter to delete all instances of header.
#***********************************************************************
sub action_delete_all_headers {
    my($header) = @_;
    return 0 if (!in_message_context("action_delete_all_headers"));
    my($count, $len, $orig_header);

    $orig_header = $header;
    $len = length($header) + 1;
    $header .= ":";
    $header = lc($header);

    return undef unless(open(HDRS, "<", "HEADERS"));

    $count = 0;
    while(<HDRS>) {
	if (lc(substr($_, 0, $len)) eq $header) {
	    $count++;
	}
    }
    close(HDRS);

    # Delete in REVERSE order, in case Sendmail updates
    # its count as headers are deleted... paranoid but safe.
    while ($count > 0) {
	action_delete_header($orig_header, $count);
	$count--;
    }
    return 1;
}

=item action_accept

Makes a note for milter to accept the current part.

=cut

#***********************************************************************
# %PROCEDURE: action_accept
# %ARGUMENTS:
#  Ignored
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note to accept the current part.
#***********************************************************************
sub action_accept {
    return 0 if (!in_filter_context("action_accept"));
    $Action = "accept";
    return 1;
}

=item action_accept_with_warning

Makes a note for milter to accept the current part,
but add a warning to the message.

=cut

#***********************************************************************
# %PROCEDURE: action_accept_with_warning
# %ARGUMENTS:
#  msg -- warning message
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note to accept the current part, but add a warning to the
#  message.
#***********************************************************************
sub action_accept_with_warning {
    my($msg) = @_;
    return 0 if (!in_filter_context("action_accept_with_warning"));
    $Actions{'accept_with_warning'}++;
    $Action = "accept";
    push(@Warnings, "$msg\n");
    return 1;
}

=item message_rejected

Method that returns True if message has been rejected
(with action_bounce or action_tempfail), false otherwise.

=cut

#***********************************************************************
# %PROCEDURE: message_rejected
# %ARGUMENTS:
#  None
# %RETURNS:
#  True if message has been rejected (with action_bounce or action_tempfail);
#  false otherwise.
#***********************************************************************
sub message_rejected {
    return 0 if (!in_message_context("message_rejected"));
    return (defined($Actions{'tempfail'}) ||
	    defined($Actions{'bounce'})   ||
	    defined($Actions{'discard'}));
}

=item action_drop

Makes a note for milter to drop the current part without
any warning.

=cut

#***********************************************************************
# %PROCEDURE: action_drop
# %ARGUMENTS:
#  Ignored
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note to drop the current part without any warning.
#***********************************************************************
sub action_drop {
    return 0 if (!in_filter_context("action_drop"));
    $Actions{'drop'}++;
    $Action = "drop";
    return 1;
}

=item action_drop_with_warning

Makes a note for milter to drop the current part
and add a warning to the message.

=cut

#***********************************************************************
# %PROCEDURE: action_drop_with_warning
# %ARGUMENTS:
#  msg -- warning message
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note to drop the current part and add a warning to the message
#***********************************************************************
sub action_drop_with_warning {
    my($msg) = @_;
    return 0 if (!in_filter_context("action_drop_with_warning"));
    $Actions{'drop_with_warning'}++;
    $Action = "drop";
    push(@Warnings, "$msg\n");
    return 1;
}

=item action_replace_with_warning

Makes a note for milter to drop the current part
and replace it with a warning.

=cut

#***********************************************************************
# %PROCEDURE: action_replace_with_warning
# %ARGUMENTS:
#  msg -- warning message
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note to drop the current part and replace it with a warning
#***********************************************************************
sub action_replace_with_warning {
    my($msg) = @_;
    return 0 if (!in_filter_context("action_replace_with_warning"));
    $Actions{'replace_with_warning'}++;
    $Action = "replace";
    $WarningCounter++;
    $ReplacementEntity = MIME::Entity->build(Top => 0,
					     Type => "text/plain",
 					     Encoding => "-suggest",
					     Disposition => "inline",
					     Filename => "warning$WarningCounter.txt",
					     'X-Mailer' => undef,
 					     Data => [ "$msg\n" ]);
    return 1;
}

=item action_defang

Makes a note for milter to defang the current part by changing its name,
filename and possibly MIME type.

=cut

#***********************************************************************
# %PROCEDURE: action_defang
# %ARGUMENTS:
#  entity -- current part
#  name -- suggested name for defanged part
#  fname -- suggested filename for defanged part
#  type -- suggested MIME type for defanged part
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Makes a note to defang the current part by changing its name, filename
#  and possibly MIME type.
#***********************************************************************
sub action_defang {
    $Changed = 1;
    my($entity, $name, $fname, $type) = @_;
    return 0 if (!in_filter_context("action_defang"));

    $name = "" unless defined($name);
    $fname = "" unless defined($fname);
    $type = "application/octet-stream" unless defined($type);

    $Actions{'defang'}++;
    my($head) = $entity->head;
    my($oldfname) = takeStabAtFilename($entity);

    my($defang);
    if ($name eq "" || $fname eq "") {
	$defang = make_defanged_name();
    }
    $name = $defang if ($name eq "");
    $fname = $defang if ($fname eq "");

    my($warning);
    if (defined(&defang_warning)) {
	$warning = defang_warning($oldfname, $fname);
    } else {
	$warning = "An attachment named '$oldfname'";
	$warning .= " was converted to '$fname'.\n";
	$warning .= "To recover the file, click on the attachment and Save As\n'$oldfname' in order to access it.\n";
    }

    $entity->effective_type($type);
    $head->replace("Content-Type", $type);
    $head->mime_attr("Content-Type.name" => $name);
    $head->mime_attr("Content-Disposition.filename" => $fname);
    $head->mime_attr("Content-Description" => $fname);

    action_accept_with_warning("$warning");
    return 1;
}

=item action_external_filter

Pipes the part through the UNIX command $cmd, and replaces the
part with the result of running the filter.

=cut

#***********************************************************************
# %PROCEDURE: action_external_filter
# %ARGUMENTS:
#  entity -- current part
#  cmd -- UNIX command to run
# %RETURNS:
#  1 on success, 0 otherwise.
# %DESCRIPTION:
#  Pipes the part through the UNIX command $cmd, and replaces the
#  part with the result of running the filter.
#***********************************************************************
sub action_external_filter {
    my($entity, $cmd) = @_;

    return 0 if (!in_filter_context("action_external_filter"));
    # Copy the file
    my($body) = $entity->bodyhandle;
    if (!defined($body)) {
	return 0;
    }

    if (!defined($body->path)) {
	return 0;
    }

    unless(copy_or_link($body->path, "FILTERINPUT")) {
	md_syslog('err', "Could not open FILTERINPUT: $!");
	return(0);
    }

    # Run the filter
    my($status) = system($cmd);

    # Filter failed if non-zero exit
    if ($status % 255) {
	md_syslog('err', "External filter exited with non-zero status $status");
	return 0;
    }

    # If filter didn't produce FILTEROUTPUT, do nothing
    return 1 if (! -r "FILTEROUTPUT");

    # Rename FILTEROUTPUT over original path
    unless (rename("FILTEROUTPUT", $body->path)) {
	md_syslog('err', "Could not rename FILTEROUTPUT to path: $!");
	return(0);
    }
    $Changed = 1;
    $Actions{'external_filter'}++;
    return 1;
}

=item action_quarantine

Makes a note for milter to drop the current part,
emails the MIMEDefang administrator a notification,
and quarantines the part in the quarantine directory.

=cut

#***********************************************************************
# %PROCEDURE: action_quarantine
# %ARGUMENTS:
#  entity -- current part
#  msg -- warning message
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Similar to action_drop_with_warning, but e-mails the MIMEDefang
#  administrator a notification, and quarantines the part in the
#  quarantine directory.
#***********************************************************************
sub action_quarantine {
    my($entity, $msg) = @_;

    return 0 if (!in_filter_context("action_quarantine"));
    $Action = "drop";
    push(@Warnings, "$msg\n");

    # Can't handle path-less bodies
    my($body) = $entity->bodyhandle;
    if (!defined($body)) {
	return 0;
    }

    if (!defined($body->path)) {
	return 0;
    }

    get_quarantine_dir();
    if ($QuarantineSubdir eq "") {
	# Could not create quarantine directory
	return 0;
    }

    $Actions{'quarantine'}++;
    $QuarantineCount++;

    # Save the part
    copy_or_link($body->path, "$QuarantineSubdir/PART.$QuarantineCount.BODY");

    # Save the part's headers
    if (open(OUT, ">", "$QuarantineSubdir/PART.$QuarantineCount.HEADERS")) {
	$entity->head->print(\*OUT);
	close(OUT);
    }

    # Save the messages
    if (open(OUT, ">", "$QuarantineSubdir/MSG.$QuarantineCount")) {
	print OUT "$msg\n";
	close(OUT);
    }
    return 1;
}

=item action_sm_quarantine

Asks Sendmail to quarantine message in mqueue using Sendmail's
smfi_quarantine facility.

=cut

#***********************************************************************
# %PROCEDURE: action_sm_quarantine
# %ARGUMENTS:
#  reason -- reason for quarantine
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Asks Sendmail to quarantine message in mqueue using Sendmail's
#  smfi_quarantine facility.
#***********************************************************************
sub action_sm_quarantine {
    my($reason) = @_;
    return if (!in_message_context("action_sm_quarantine"));

    $Actions{'sm_quarantine'} = 1;
    write_result_line("Q", $reason);
}

=item get_quarantine_dir

Method that returns the configured quarantine directory.

=cut

sub get_quarantine_dir {

    # If quarantine dir has already been made, return it.
    if ($QuarantineSubdir ne "") {
	return $QuarantineSubdir;
    }

    my($counter) = 0;
    my($tries);
    my($success) = 0;
    my($tm);
    $tm = time_str();
    my $hour = hour_str();
    my $hour_dir = sprintf("%s/%s", $Features{'Path:QUARANTINEDIR'}, $hour);
    mkdir($hour_dir, 0750);
    if (! -d $hour_dir) {
	    return "";
    }
    do {
	$counter++;
	$QuarantineSubdir = sprintf("%s/%s/qdir-%s-%03d",
				    $Features{'Path:QUARANTINEDIR'}, $hour, $tm, $counter);
	if (mkdir($QuarantineSubdir, 0750)) {
	    $success = 1;
	}
    } while(!$success && ($tries++ < 1000));
    if (!$success) {
	$QuarantineSubdir = "";
	return "";
    }

    # Write the sender and recipient info
    if (open(OUT, ">", "$QuarantineSubdir/SENDER")) {
	print OUT "$Sender\n";
	close(OUT);
    }
    if (open(OUT, ">", "$QuarantineSubdir/SENDMAIL-QID")) {
	print OUT "$QueueID\n";
	close(OUT);
    }

    if (open(OUT, ">", "$QuarantineSubdir/RECIPIENTS")) {
	my($s);
	foreach $s (@Recipients) {
	    print OUT "$s\n";
	}
	close(OUT);
    }

    # Copy message headers
    if (open(OUT, ">", "$QuarantineSubdir/HEADERS")) {
	if (open(IN, "<", "HEADERS")) {
	    while(<IN>) {
		print OUT;
	    }
	    close(IN);
	}
	close(OUT);
    }

    return $QuarantineSubdir;
}

=item action_quarantine_entire_message

Method that puts a copy of the entire message in the quarantine directory.

=cut

#***********************************************************************
# %PROCEDURE: action_quarantine_entire_message
# %ARGUMENTS:
#  msg -- quarantine message (optional)
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Puts a copy of the entire message in the quarantine directory.
#***********************************************************************
sub action_quarantine_entire_message {
    my($msg) = @_;
    return 0 if (!in_message_context("action_quarantine_entire_message"));
    # If no parts have yet been quarantined, create the quarantine subdirectory
    # and write useful info there
    get_quarantine_dir();
    if ($QuarantineSubdir eq "") {
	# Could not create quarantine directory
	return 0;
    }

    # Don't copy message twice
    if ($EntireMessageQuarantined) {
	return 1;
    }

    $Actions{'quarantine_entire_message'}++;
    if (defined($msg) && ($msg ne "")) {
	if (open(OUT, ">", "$QuarantineSubdir/MSG.0")) {
	    print OUT "$msg\n";
	    close(OUT);
	}
    }

    $EntireMessageQuarantined = 1;

    copy_or_link("INPUTMSG", "$QuarantineSubdir/ENTIRE_MESSAGE");

    return 1;
}

=item action_bounce

Method that Causes the SMTP transaction to fail with an SMTP 554 failure code
and the specified reply text.
If code or DSN are omitted or invalid, use 554 and 5.7.1.

=cut

#***********************************************************************
# %PROCEDURE: action_bounce
# %ARGUMENTS:
#  reply -- SMTP reply text (eg: "Not allowed, sorry")
#  code -- SMTP reply code (eg: 554)
#  DSN -- DSN code (eg: 5.7.1)
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Causes the SMTP transaction to fail with an SMTP 554 failure code and the
#  specified reply text.  If code or DSN are omitted or invalid,
#  use 554 and 5.7.1.
#***********************************************************************
sub action_bounce {
    my($reply, $code, $dsn) = @_;
    return 0 if (!in_message_context("action_bounce"));

    $reply = "Forbidden for policy reasons" unless (defined($reply) and ($reply ne ""));
    $code = 554 unless (defined($code) and $code =~ /^5\d\d$/);
    $dsn = "5.7.1" unless (defined($dsn) and $dsn =~ /^5\.\d{1,3}\.\d{1,3}$/);

    write_result_line('B', $code, $dsn, $reply);
    $Actions{'bounce'}++;
    return 1;
}

=item action_discard

Method that causes the entire message to be silently discarded without without
notifying anyone.

=cut

#***********************************************************************
# %PROCEDURE: action_discard
# %ARGUMENTS:
#  None
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Causes the entire message to be silently discarded without without
#  notifying anyone.
#***********************************************************************
sub action_discard {
    return 0 if (!in_message_context("action_discard"));
    write_result_line("D", "");
    $Actions{'discard'}++;
    return 1;
}

=item action_notify_sender

Method that sends an email to the sender containing the $msg.

=cut

#***********************************************************************
# %PROCEDURE: action_notify_sender
# %ARGUMENTS:
#  msg -- a message to send
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Causes an e-mail to be sent to the sender containing $msg
#***********************************************************************
sub action_notify_sender {
    my($msg) = @_;
    return 0 if (!in_message_context("action_notify_sender"));
    if ($Sender eq '<>') {
	md_syslog('err', "Skipped action_notify_sender: Sender = <>");
	return 0;
    }

    if ($VirusName ne "") {
	md_syslog('err', "action_notify_sender disabled when virus is detected");
	return 0;
    }

    if (open(FILE, ">>", "NOTIFICATION")) {
	print FILE $msg;
	close(FILE);
	$Actions{'notify_sender'}++;
	return 1;
    }
    md_syslog('err', "Could not create NOTIFICATION file: $!");
    return 0;
}

=item action_notify_administrator

Method that sends an email to MIMEDefang administrator containing the $msg.

=cut

#***********************************************************************
# %PROCEDURE: action_notify_administrator
# %ARGUMENTS:
#  msg -- a message to send
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Causes an e-mail to be sent to the MIMEDefang administrator
#  containing $msg
#***********************************************************************
sub action_notify_administrator {
    my($msg) = @_;
    if (!$InMessageContext) {
	send_admin_mail($NotifyAdministratorSubject, $msg);
	return 1;
    }
    if (open(FILE, ">>", "ADMIN_NOTIFICATION")) {
	print FILE $msg;
	close(FILE);
	$Actions{'notify_administrator'}++;
	return 1;
    }
    md_syslog('err', "Could not create ADMIN_NOTIFICATION file: $!");
    return 0;
}

=item action_tempfail

Method that sends a temporary failure with a 4.x.x SMTP code.
If code or DSN are omitted or invalid, use 451 and 4.3.0.

=cut

#***********************************************************************
# %PROCEDURE: action_tempfail
# %ARGUMENTS:
#  reply -- the text reply
#  code -- SMTP reply code (eg: 451)
#  DSN -- DSN code (eg: 4.3.0)
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Tempfails the message with a 4.x.x SMTP code.  If code or DSN are
#  omitted or invalid, use 451 and 4.3.0.
#***********************************************************************
sub action_tempfail {
    my($reply, $code, $dsn) = @_;
    return 0 if (!in_message_context("action_tempfail"));
    $reply = "Try again later" unless (defined($reply) and ($reply ne ""));
    $code = 451 unless (defined($code) and $code =~ /^4\d\d$/);
    $dsn = "4.3.0" unless (defined($dsn) and $dsn =~ /^4\.\d{1,3}\.\d{1,3}$/);

    write_result_line('T', $code, $dsn, $reply);
    $Actions{'tempfail'}++;
    return 1;
}

=item add_recipient

Signals to MIMEDefang to add a recipient to the envelope.

=cut

#***********************************************************************
# %PROCEDURE: add_recipient
# %ARGUMENTS:
#  recip -- recipient to add
# %RETURNS:
#  0 on failure, 1 on success.
# %DESCRIPTION:
#  Signals to MIMEDefang to add a recipient to the envelope.
#***********************************************************************
sub add_recipient {
    my($recip) = @_;
    write_result_line("R", $recip);
    return 1;
}

=item delete_recipient

Signals to MIMEDefang to delete a recipient from the envelope.

=cut

#***********************************************************************
# %PROCEDURE: delete_recipient
# %ARGUMENTS:
#  recip -- recipient to delete
# %RETURNS:
#  0 on failure, 1 on success.
# %DESCRIPTION:
#  Signals to MIMEDefang to delete a recipient from the envelope.
#***********************************************************************
sub delete_recipient {
    my($recip) = @_;
    write_result_line("S", $recip);
    return 1;
}

=item change_sender

Signals to MIMEDefang to change the envelope sender.

=cut

#***********************************************************************
# %PROCEDURE: change_sender
# %ARGUMENTS:
#  sender -- new envelope sender
# %RETURNS:
#  0 on failure, 1 on success.
# %DESCRIPTION:
#  Signals to MIMEDefang to change the envelope sender.  Only works on
#  Sendmail 8.14.0 and higher, but no feedback is given to Perl caller!
#***********************************************************************
sub change_sender {
    my($sender) = @_;
    write_result_line("f", $sender);
    return 1;
}

=item action_replace_with_url

Method that places the part in doc_root/{sha1_of_part}.ext and replaces it with
a text/plain part giving the URL for pickup.

=cut

#***********************************************************************
# %PROCEDURE: action_replace_with_url
# %ARGUMENTS:
#  entity -- part to replace
#  doc_root -- document root in which to place file
#  base_url -- base URL for retrieving document
#  msg -- message to replace document with.  The string "_URL_" is
#         replaced with the actual URL of the part.
#  cd_data -- optional Content-Disposition filename data to save
#  salt    -- optional salt to add to SHA1 hash.
# %RETURNS:
#  1 on success, 0 on failure
# %DESCRIPTION:
#  Places the part in doc_root/{sha1_of_part}.ext and replaces it with
#  a text/plain part giving the URL for pickup.
#***********************************************************************
sub action_replace_with_url {
    my($entity, $doc_root, $base_url, $msg, $cd_data, $salt) = @_;
    my($ctx);
    my($path);
    my($fname, $ext, $name, $url);
    my $extension = "";

    return 0 unless in_filter_context("action_replace_with_url");
    return 0 unless defined($entity->bodyhandle);
    $path = $entity->bodyhandle->path;
    return 0 unless defined($path);
    open(IN, "<", "$path") or return 0;

    $ctx = Digest::SHA->new;
    $ctx->addfile(*IN);
    $ctx->add($salt) if defined($salt);
    close(IN);

    $fname = takeStabAtFilename($entity);
    $fname = "" unless defined($fname);
    $extension = $1 if ($fname =~ /(\.[^.]*)$/);

    # Use extension if it is .[alpha,digit,underscore]
    $extension = "" unless ($extension =~ /^\.[A-Za-z0-9_]*$/);

    # Filename to save
    $name = $ctx->hexdigest . $extension;
    $fname = $doc_root . "/" . $name;
    $url = $base_url . "/" . $name;

    if (-r $fname) {
	# If file exists, then this is either a duplicate or someone
	# has defeated SHA1.  Just update the mtime on the file.
	my($now);
	$now = time;
	utime($now, $now, $fname);
    } else {
	copy_or_link($path, $fname) or return 0;
	# In case umask is whacked...
	chmod 0644, $fname;
    }

    # save optional Content-Disposition data
    if (defined($cd_data) and ($cd_data ne "")) {
	if (open CDF, ">", "$doc_root/.$name") {
	    print CDF $cd_data;
	    close CDF;
	    chmod 0644, "$doc_root/.$name";
	}
    }

    $msg =~ s/_URL_/$url/g;
    action_replace_with_warning($msg);
    return 1;
}

=back

=cut

1;
