package Mail::MIMEDefang::MIME;

require Exporter;

use MIME::Parser;
use MIME::Words qw(:all);
use Mail::MIMEDefang::Core;

our @ISA = qw(Exporter);
our @EXPORT;
our @EXPORT_OK;

@EXPORT = qw{builtin_create_parser rebuild_entity};
@EXPORT_OK = qw{collect_parts};

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

1;
