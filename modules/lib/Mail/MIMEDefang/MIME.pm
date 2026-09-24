#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::MIME - MIME objects interface methods for email filters

=head1 DESCRIPTION

Mail::MIMEDefang::MIME are a set of methods that can be called
from F<mimedefang-filter> to operate on MIME objects.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::MIME;

use strict;
use warnings;

require Exporter;

use MIME::Parser;
use MIME::Words qw(:all);

use Mail::MIMEDefang;
use Mail::MIMEDefang::MIME::Base64;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(builtin_create_parser find_part append_to_part takeStabAtFilename
             remove_redundant_html_parts append_to_html_part append_html_boilerplate
             append_text_boilerplate collect_parts anonymize_uri
             md_concatenated_base64 md_mime_suspicious);

sub builtin_create_parser {
    my $parser = MIME::Parser->new();
    $parser->extract_nested_messages(1);
    $parser->extract_uuencode(1);
    $parser->output_to_core(0);
    $parser->tmp_to_core(0);
    return $parser;
}

=item collect_parts

Method that adds parts to the array C<@FlatParts> for flattening.

=cut

#***********************************************************************
# %PROCEDURE: collect_parts
# %ARGUMENTS:
#  entity -- root entity to rebuild
#  skip_pgp_mime -- If true, skip multipart/signed and multipart/encrypted
#                   parts
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Adds parts to the array @FlatParts for flattening.
#***********************************************************************
sub collect_parts {
  my($entity, $skip_pgp_mime) = @_;
  my(@parts) = $entity->parts;
  if ($#parts >= 0) {
	  if (! $skip_pgp_mime ||
	    (lc($entity->head->mime_type) ne "multipart/signed" and
	     lc($entity->head->mime_type) ne "multipart/encrypted")) {
	    foreach my $part (@parts) {
		    collect_parts($part, $skip_pgp_mime);
	    }
	  }
  } else {
	  push(@FlatParts, $entity);
  }
}

=item  takeStabAtFilename ( $entity )

Makes a guess at a filename for the attachment.  Calls MIME::Head's
recommended_filename() method, which tries 'Content-Disposition.filename'and if
not found, 'Content-Type.name'.

Returns a MIME-decoded filename, or a blank string if none found.

=cut

sub takeStabAtFilename
{
	my ($entity) = @_;

	my $guess = $entity->head->recommended_filename();

	if( defined $guess ) {
		return scalar( decode_mimewords( $guess ) );
	}

	return '';
}

=item find_part

Method that returns the first MIME entity of type C<$content_type>,
C<undef> if none exists.

=cut

#***********************************************************************
# %PROCEDURE: find_part
# %ARGUMENTS:
#  entity -- root MIME part
#  content_type -- desired MIME content type
#  skip_pgp_mime -- If true, do not descend into multipart/signed or
#                   multipart/encrypted parts
# %RETURNS:
#  First MIME entity of type "$content_type"; undef if none exists.
#***********************************************************************
sub find_part {
  my($entity, $content_type, $skip_pgp_mime) = @_;
  my(@parts);
  my($ans);
  if (!($entity->is_multipart)) {
  	if (lc($entity->head->mime_type) eq lc($content_type)) {
	    return $entity;
	  } else {
	    return;
	  }
  }

  if ($skip_pgp_mime &&
	  (lc($entity->head->mime_type) eq "multipart/signed" or
	   lc($entity->head->mime_type) eq "multipart/encrypted")) {
	  return;
  }

  @parts = $entity->parts;
  foreach my $part (@parts) {
	  $ans = find_part($part, $content_type, $skip_pgp_mime);
	    return $ans if defined($ans);
  }
  return;
}

=item append_to_part

Method that appends text to C<$part>

=cut

#***********************************************************************
# %PROCEDURE: append_to_part
# %ARGUMENTS:
#  part -- a mime entity
#  msg -- text to append to the entity
# %RETURNS:
#  1 on success; 0 on failure.
# %DESCRIPTION:
#  Appends text to $part
#***********************************************************************
sub append_to_part {
  my($part, $boilerplate) = @_;
  return 0 unless defined($part->bodyhandle);
  my($path) = $part->bodyhandle->path;
  return 0 unless (defined($path));
  return 0 unless (open(my $OUT, ">>", "$path"));
  print $OUT "\n$boilerplate\n";
  close($OUT);
  $Changed = 1;
  return 1;
}

=item remove_redundant_html_parts

Method that rebuilds the email message without redundant HTML parts.
That is, if a multipart/alternative entity contains text/plain and text/html
parts, the text/html part will be removed.

=cut

#***********************************************************************
# %PROCEDURE: remove_redundant_html_parts
# %ARGUMENTS:
#  e -- entity
# %RETURNS:
#  Nothing
# %DESCRIPTION:
#  Rebuilds $e without redundant HTML parts.  That is, if
#  a multipart/alternative entity contains text/plain and text/html
#  parts, we nuke the text/html part.
#***********************************************************************
sub remove_redundant_html_parts {
  my($e) = @_;
  return 0 unless in_filter_end("remove_redundant_html_parts");

  my(@parts) = $e->parts;
  my($type) = lc($e->mime_type);

  # Don't recurse into multipart/signed or multipart/encrypted
  return 0 if ($type eq "multipart/signed" or
    $type eq "multipart/encrypted");
  my(@keep);
  my($didsomething);
  $didsomething = 0;
  my($have_text_plain);
  if ($type eq "multipart/alternative" && $#parts >= 0) {
	  # First look for a text/plain part
	  $have_text_plain = 0;
	  foreach my $part (@parts) {
	    $type = lc($part->mime_type);
	    if ($type eq "text/plain") {
	 	    $have_text_plain = 1;
		    last;
	    }
	  }

	  # If we have a text/plain part, delete any text/html part
	  if ($have_text_plain) {
	    foreach my $part (@parts) {
		    $type = lc($part->mime_type);
		    if ($type ne "text/html") {
		      push(@keep, $part);
		    } else {
		      $didsomething = 1;
		    }
	    }
	    if ($didsomething) {
		    $e->parts(\@keep);
		    @parts = @keep;
		    $Changed = 1;
	    }
	  }
  }
  if ($#parts >= 0) {
	  foreach my $part (@parts) {
	    $didsomething = 1 if (remove_redundant_html_parts($part));
	  }
  }
  return $didsomething;
}

# HTML parser callbacks
sub html_echo {
  my($p, $text) = @_;
  $p->{ofh}->print($text);
}

sub html_end {
  my($p, $text) = @_;
  if (!$HTMLFoundEndBody) {
  	if ($text =~ m+<\s*/body+i) {
	    $p->{ofh}->print("$HTMLBoilerplate\n");
	    $HTMLFoundEndBody = 1;
	  }
  }
  if (!$HTMLFoundEndBody) {
	  if ($text =~ m+<\s*/html+i) {
	    $p->{ofh}->print("$HTMLBoilerplate\n");
	    $HTMLFoundEndBody = 1;
	  }
  }

  $p->{ofh}->print($text);
}

=item append_to_html_part

Method that appends text to the specified mime part, but does so by
parsing HTML and adding the text before </body> or </html> tags.

=cut

#***********************************************************************
# %PROCEDURE: append_to_html_part
# %ARGUMENTS:
#  part -- a mime entity (of type text/html)
#  msg -- text to append to the entity
# %RETURNS:
#  1 on success; 0 on failure.
# %DESCRIPTION:
#  Appends text to $part, but does so by parsing HTML and adding the
#  text before </body> or </html>
#***********************************************************************
sub append_to_html_part {
  my($part, $boilerplate) = @_;

  my ($ifh, $ofh);
  if (!$Features{"HTML::Parser"}) {
	  md_syslog('warning', "Attempt to call append_to_html_part, but HTML::Parser Perl module not installed");
	  return 0;
  }
  return 0 unless defined($part->bodyhandle);
  my($path) = $part->bodyhandle->path;
  return 0 unless (defined($path));
  return 0 unless (open($ifh, "<", "$path"));
  if (!open($ofh, ">", "$path.tmp")) {
	  close($ifh);
	  return(0);
  }

  $HTMLFoundEndBody = 0;
  $HTMLBoilerplate = $boilerplate;
  my($p);
  $p = HTML::Parser->new(api_version => 3,
		   default_h   => [\&html_echo, "self,text"],
		   end_h       => [\&html_end,  "self,text"]);

  $p->{ifh} = $ifh;
  $p->{ofh} = $ofh;

  $p->unbroken_text(1);
  $p->parse_file($ifh);
  if (!$HTMLFoundEndBody) {
	  print $ofh "\n$boilerplate\n";
  }

  close($ifh);
  close($ofh);

  # Rename the path
  return 0 unless rename($path, "$path.old");
  unless (rename("$path.tmp", $path)) {
	  rename ("$path.old", $path);
	  return 0;
  }
  unlink "$path.old";
  $Changed = 1;
  return 1;
}

=item append_text_boilerplate

Method that appends text to text/plain part or parts.

=cut

#***********************************************************************
# %PROCEDURE: append_text_boilerplate
# %ARGUMENTS:
#  msg -- root MIME entity.
#  boilerplate -- boilerplate text to append
#  all -- if 1, append to ALL text/plain parts.  If 0, append only to
#         FIRST text/plain part.
# %RETURNS:
#  1 if text was appended to at least one part; 0 otherwise.
# %DESCRIPTION:
#  Appends text to text/plain part or parts.
#***********************************************************************
sub append_text_boilerplate {
  my($msg, $boilerplate, $all) = @_;
  my($part);
  if (!$all) {
	  $part = find_part($msg, "text/plain", 1);
	  if (defined($part)) {
	    if (append_to_part($part, $boilerplate)) {
		    $Actions{'append_text_boilerplate'}++;
		    return 1;
	    }
	  }
	  return 0;
  }
  @FlatParts = ();
  my($ok) = 0;
  collect_parts($msg, 1);
  foreach my $part (@FlatParts) {
	  if (lc($part->head->mime_type) eq "text/plain") {
	    if (append_to_part($part, $boilerplate)) {
		    $ok = 1;
		    $Actions{'append_text_boilerplate'}++;
	    }
	  }
  }
  return $ok;
}

=item append_html_boilerplate

Method that appends text to text/html part or parts.
It tries to be clever and inserts the text before the </body> tag
to be able of being seen.

=cut

#***********************************************************************
# %PROCEDURE: append_html_boilerplate
# %ARGUMENTS:
#  msg -- root MIME entity.
#  boilerplate -- boilerplate text to append
#  all -- if 1, append to ALL text/html parts.  If 0, append only to
#         FIRST text/html part.
# %RETURNS:
#  1 if text was appended to at least one part; 0 otherwise.
# %DESCRIPTION:
#  Appends text to text/html part or parts.  Tries to be clever and
#  insert the text before the </body> tag so it has a hope in hell of
#  being seen.
#***********************************************************************
sub append_html_boilerplate {
  my($msg, $boilerplate, $all) = @_;
  my($part);
  if (!$all) {
	  $part = find_part($msg, "text/html", 1);
	  if (defined($part)) {
	    if (append_to_html_part($part, $boilerplate)) {
		    $Actions{'append_html_boilerplate'}++;
		    return 1;
	    }
	  }
	  return 0;
  }
  @FlatParts = ();
  my($ok) = 0;
  collect_parts($msg, 1);
  foreach my $part (@FlatParts) {
	  if (lc($part->head->mime_type) eq "text/html") {
	    if (append_to_html_part($part, $boilerplate)) {
		    $ok = 1;
		    $Actions{'append_html_boilerplate'}++;
	    }
	  }
  }
  return $ok;
}

sub _anonymize_text_uri {
  my ($part) = @_;

  return 0 unless defined($part->bodyhandle);
  my($path) = $part->bodyhandle->path;
  my $npath = $path . '.tmp';
  return 0 unless (defined($path));

  my $body = $part->bodyhandle;

  # If there's no body, then we can't add
  return 0 unless $body;

  my $ifh = $body->open('r');
  return 0 unless $ifh;

  my $ofh;
  if (!open($ofh, '>', $npath)) {
    $ifh->close();
    return 0;
  }

  my $line;
  my $nline;
  while (defined($line = $ifh->getline())) {
    if($line =~ /https?\:\/\/.{3,512}\/(.{1,30})?(\&|\?)utm([_a-z0-9=]+)/) {
      my @params = split(/(\?|\&|\s+)/, $line);
      foreach my $p ( @params ) {
        if($p =~ /(\?|\&)?utm_.{1,20}\=.{1,64}/) {
          next;
        } else {
          $nline .= $p;
        }
      }
      $nline =~ s/(\&{2,}|\?{2,}|\n)//g;
      $ofh->print($nline);
    } else {
      $ofh->print($line);
    }
  }
  $ifh->close();
  $ofh->close();

  # Rename over the old path
  return 1 if rename($npath, $path);

  # Rename failed
  unlink($npath);
  $Changed = 1;
  return 0;
}

sub html_utm_filter {
  my($p, $text) = @_;

  my $nline;
  if($text =~ /https?\:\/\/.{3,512}\/(.{1,30})?(\&|\?)utm([_a-z0-9=]+)/) {
    my @params = split(/(\?|\&|\s+|\>|\"|\')/, $text);
    foreach my $par ( @params ) {
      if($par =~ /(\?|\&)?utm_.{1,20}\=.{1,64}/) {
        next;
      } else {
        $nline .= $par;
      }
    }
    $nline =~ s/(\&{2,}|\?{2,}|\n)//g;
    $p->{ofh}->print($nline);
  } else {
    $p->{ofh}->print($text);
  }
}

sub _anonymize_html_uri {
  my ($part) = @_;

  if (!$Features{"HTML::Parser"}) {
          md_syslog('warning', "Attempt to call append_to_html_part, but HTML::Parser Perl module not installed");
          return 0;
  }

  my ($ifh, $ofh);
  return 0 unless defined($part->bodyhandle);
  my($path) = $part->bodyhandle->path;
  return 0 unless (defined($path));
  return 0 unless (open($ifh, "<", "$path"));
  if (!open($ofh, ">", "$path.tmp")) {
          close($ifh);
          return(0);
  }

  my $p;
  $p = HTML::Parser->new(api_version => 3,
                         default_h   => [\&html_utm_filter, "self,text"],
                         end_h       => [\&html_echo,  "self,text"]);

  $p->{ifh} = $ifh;
  $p->{ofh} = $ofh;

  $p->unbroken_text(1);
  $p->parse_file($ifh);

  close($ifh);
  close($ofh);

  # Rename the path
  return 0 unless rename($path, "$path.old");
  unless (rename("$path.tmp", $path)) {
          rename ("$path.old", $path);
          return 0;
  }
  unlink "$path.old";
  $Changed = 1;
  return 1;
}

=item anonymize_uri

Anonymize urls by removing all utm_* parameters,
takes the message part as parameter and returns
a boolean value if the sub succeeded or not.

=cut

sub anonymize_uri {
  my ($msg) = @_;

  @FlatParts = ();
  my($ok) = 0;
  collect_parts($msg, 1);
  foreach my $part (@FlatParts) {
    if (lc($part->head->mime_type) =~ /text\/html/) {
      if (_anonymize_html_uri($part)) {
        $ok = 1;
      }
    } elsif (lc($part->head->mime_type) =~ /text\/plain/) {
      if (_anonymize_text_uri($part)) {
        $ok = 1;
      }
    }
  }
  return $ok;
}

# State for the message most recently parsed; see md_mime_prepare().
my $AmbiguousMime = 0;

=item md_concatenated_base64

Returns 1 if the message being filtered has at least one base64-encoded
part made of several base64 streams glued together (data follows a padding
character), and 0 otherwise.  RFC 2045 does not allow this; some mail clients decode
each stream separately and join the results, others decode the part as a
single stream.  MIMEDefang logs a warning when it sees such a part.

Legitimate mail from buggy software can trigger this, so consider tagging or
quarantining rather than rejecting.  For example:

    sub filter_begin {
        my ($entity) = @_;
        if (md_concatenated_base64()) {
            action_quarantine_entire_message('Base64 part with concatenated streams');
        }
    }

=cut

sub md_concatenated_base64 {
    return Mail::MIMEDefang::MIME::Base64::count() ? 1 : 0;
}

=item md_mime_suspicious

Returns 1 if MIME-tools reported the message being filtered as ambiguous
(for example, repeated Content-Type or Content-Transfer-Encoding headers,
or repeated or empty parameters), so that mail clients may interpret it
differently, and 0 otherwise.  Always returns 0 if the installed MIME-tools
cannot report this.  MIMEDefang logs a warning for such messages.

=cut

sub md_mime_suspicious {
    return $AmbiguousMime ? 1 : 0;
}

=back

=cut

# The functions below are called by mimedefang.pl, not by filters.

# Called before each message is parsed.
sub md_mime_prepare {
    Mail::MIMEDefang::MIME::Base64::reset_count();
    $AmbiguousMime = 0;
    Mail::MIMEDefang::MIME::Base64::activate();
    return;
}

# Called right after each message is parsed.
sub md_mime_note_parse {
    my ($parser) = @_;

    if ($parser && $parser->can('ambiguous_content') && $parser->ambiguous_content) {
        $AmbiguousMime = 1;
        md_syslog('warning', 'Message has an ambiguous MIME structure (repeated headers or parameters)');
    }
    my $n = Mail::MIMEDefang::MIME::Base64::count();
    if ($n) {
        md_syslog('warning', "Message has $n base64 part(s) made of concatenated streams");
    }
    return;
}

1;
