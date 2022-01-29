package Mail::MIMEDefang::MIME;

require Exporter;

use MIME::Parser;
use MIME::Words qw(:all);
use Mail::MIMEDefang::Core;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw(builtin_create_parser rebuild_entity find_part append_to_part
             remove_redundant_html_parts append_to_html_part append_html_boilerplate
             append_text_boilerplate);
@EXPORT_OK = qw(collect_parts);

sub builtin_create_parser {
    my $parser = MIME::Parser->new();
    $parser->extract_nested_messages(1);
    $parser->extract_uuencode(1);
    $parser->output_to_core(0);
    $parser->tmp_to_core(0);
    return $parser;
}

#***********************************************************************
# %PROCEDURE: rebuild_entity
# %ARGUMENTS:
#  out -- output entity to hold rebuilt message
#  in -- input message
# %RETURNS:
#  Nothing useful
# %DESCRIPTION:
#  Descends through input entity and rebuilds an output entity.  The
#  various parts of the input entity may be modified (or even deleted)
#***********************************************************************
sub rebuild_entity {
  my($out, $in) = @_;
  my @parts = $in->parts;
  my($type) = $in->mime_type;
  $type =~ tr/A-Z/a-z/;
  my($body) = $in->bodyhandle;
  my($fname) = takeStabAtFilename($in);
  $fname = "" unless defined($fname);
  my $extension = "";
  $extension = $1 if $fname =~ /(\.[^.]*)$/;

  # If no Content-Type: header, add one
  if (!$in->head->mime_attr('content-type')) {
	  $in->head->mime_attr('Content-Type', $type);
  }

  if (!defined($body)) {
	  $Action = "accept";
	  if (defined(&filter_multipart)) {
	    push_status_tag("In filter_multipart routine");
	    filter_multipart($in, $fname, $extension, $type);
	    pop_status_tag();
	  }
	  if ($Action eq "drop") {
	    $Changed = 1;
	    return 0;
	  }

	  if ($Action eq "replace") {
	    $Changed = 1;
	    $out->add_part($ReplacementEntity);
	    return 0;
	  }

	  my($subentity);
	  $subentity = $in->dup;
	  $subentity->parts([]);
	  $out->add_part($subentity);
	  map { rebuild_entity($subentity, $_) } @parts;
  } else {
	  # This is where we call out to the user filter.  Get some useful
	  # info to pass to the filter

	  # Default action is to accept the part
	  $Action = "accept";

	  if (defined(&filter)) {
	    push_status_tag("In filter routine");
	    filter($in, $fname, $extension, $type);
	    pop_status_tag();
	  }

 	  # If action is "drop", just drop it silently;
	  if ($Action eq "drop") {
	    $Changed = 1;
	    return 0;
	  }

	  # If action is "replace", replace it with $ReplacementEntity;
	  if ($Action eq "replace") {
	    $Changed = 1;
	    $out->add_part($ReplacementEntity);
	    return 0;
	  }

	  # Otherwise, accept it
	  $out->add_part($in);
  }
}

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
  my($part);
  if ($#parts >= 0) {
	  if (! $skip_pgp_mime ||
	    (lc($entity->head->mime_type) ne "multipart/signed" and
	     lc($entity->head->mime_type) ne "multipart/encrypted")) {
	    foreach $part (@parts) {
		    collect_parts($part, $skip_pgp_mime);
	    }
	  }
  } else {
	  push(@FlatParts, $entity);
  }
}

=pod

=head2  takeStabAtFilename ( $entity )

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
		$guess =~ tr/\x00-\x7F/#/c;
		return scalar( decode_mimewords( $guess ) );
	}

	return '';
}

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
  my($part);
  my($ans);
  if (!($entity->is_multipart)) {
  	if (lc($entity->head->mime_type) eq lc($content_type)) {
	    return $entity;
	  } else {
	    return undef;
	  }
  }

  if ($skip_pgp_mime &&
	  (lc($entity->head->mime_type) eq "multipart/signed" or
	   lc($entity->head->mime_type) eq "multipart/encrypted")) {
	  return undef;
  }

  @parts = $entity->parts;
  foreach $part (@parts) {
	  $ans = find_part($part, $content_type, $skip_pgp_mime);
	    return $ans if defined($ans);
  }
  return undef;
}

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
  return 0 unless (open(OUT, ">>$path"));
  print OUT "\n$boilerplate\n";
  close(OUT);
  $Changed = 1;
  return 1;
}

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
  my(@keep, $part);
  my($didsomething);
  $didsomething = 0;
  my($have_text_plain);
  if ($type eq "multipart/alternative" && $#parts >= 0) {
	  # First look for a text/plain part
	  $have_text_plain = 0;
	  foreach $part (@parts) {
	    $type = lc($part->mime_type);
	    if ($type eq "text/plain") {
	 	    $have_text_plain = 1;
		    last;
	    }
	  }

	  # If we have a text/plain part, delete any text/html part
	  if ($have_text_plain) {
	    foreach $part (@parts) {
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
	  foreach $part (@parts) {
	    $didsomething = 1 if (remove_redundant_html_parts($part));
	  }
  }
  return $didsomething;
}

# HTML parser callbacks
sub html_echo {
  my($text) = @_;
  print OUT $text;
}

sub html_end {
  my($text) = @_;
  if (!$HTMLFoundEndBody) {
  	if ($text =~ m+<\s*/body+i) {
	    print OUT "$HTMLBoilerplate\n";
	    $HTMLFoundEndBody = 1;
	  }
  }
  if (!$HTMLFoundEndBody) {
	  if ($text =~ m+<\s*/html+i) {
	    print OUT "$HTMLBoilerplate\n";
	    $HTMLFoundEndBody = 1;
	  }
  }

  print OUT $text;
}

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

  if (!$Features{"HTML::Parser"}) {
	  md_syslog('warning', "Attempt to call append_to_html_part, but HTML::Parser Perl module not installed");
	  return 0;
  }
  return 0 unless defined($part->bodyhandle);
  my($path) = $part->bodyhandle->path;
  return 0 unless (defined($path));
  return 0 unless (open(IN, "<$path"));
  if (!open(OUT, ">$path.tmp")) {
	  close(IN);
	  return(0);
  }

  $HTMLFoundEndBody = 0;
  $HTMLBoilerplate = $boilerplate;
  my($p);
  $p = HTML::Parser->new(api_version => 3,
		   default_h   => [\&html_echo, "text"],
		   end_h       => [\&html_end,  "text"]);
  $p->unbroken_text(1);
  $p->parse_file(*IN);
  if (!$HTMLFoundEndBody) {
	  print OUT "\n$boilerplate\n";
  }
  close(IN);
  close(OUT);

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
  foreach $part (@FlatParts) {
	  if (lc($part->head->mime_type) eq "text/plain") {
	    if (append_to_part($part, $boilerplate)) {
		    $ok = 1;
		    $Actions{'append_text_boilerplate'}++;
	    }
	  }
  }
  return $ok;
}

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
  foreach $part (@FlatParts) {
	  if (lc($part->head->mime_type) eq "text/html") {
	    if (append_to_html_part($part, $boilerplate)) {
		    $ok = 1;
		    $Actions{'append_html_boilerplate'}++;
	    }
	  }
  }
  return $ok;
}

1;
