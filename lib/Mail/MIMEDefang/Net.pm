package Mail::MIMEDefang::Net;

use strict;
use warnings;

use Net::DNS;

#***********************************************************************
# %PROCEDURE: expand_ipv6_address
# %ARGUMENTS:
#  addr -- an IPv6 address
# %RETURNS:
#  An IPv6 address with all zero fields explicitly expanded, and
#  any field shorter than 4 hex digits padded out with zeros.
#***********************************************************************
sub expand_ipv6_address {
  my ($addr) = @_;

  return '0000:0000:0000:0000:0000:0000:0000:0000' if ($addr eq '::');
  if ($addr =~ /::/) {
    # Do nothing if more than one pair of colons
    return $addr if ($addr =~ /::.*::/);

    # Make sure we don't begin or end with ::
    $addr = "0000$addr" if $addr =~ /^::/;
    $addr .= '0000' if $addr =~ /::$/;

    # Count number of colons
    my $colons = ($addr =~ tr/:/:/);
    if ($colons < 8) {
      my $missing = ':' . ('0000:' x (8 - $colons));
      $addr =~ s/::/$missing/;
    }
  }

  # Pad short fields
  return join(':', map { (length($_) < 4 ? ('0' x (4-length($_)) . $_) : $_) } (split(/:/, $addr)));
}


#***********************************************************************
# %PROCEDURE: reverse_ip_address_for_rbl
# %ARGUMENTS:
#  addr -- an IPv4 or IPv6 address
# %RETURNS:
#  The appropriately-reversed address for RBL lookups.
#***********************************************************************
sub reverse_ip_address_for_rbl {
  my ($addr) = @_;
  if ($addr =~ /:/) {
    $addr = expand_ipv6_address($addr);
    $addr =~ s/://g;
    return join('.', reverse(split(//, $addr)));
  }
  return join('.', reverse(split(/\./, $addr)));
}

#***********************************************************************
# %PROCEDURE: relay_is_blacklisted
# %ARGUMENTS:
#  addr -- IP address of relay host.
#  domain -- domain of blacklist server (eg: inputs.orbz.org)
# %RETURNS:
#  The result of the lookup (eg 127.0.0.2)
#***********************************************************************
sub relay_is_blacklisted {
  my($addr, $domain) = @_;
  $addr = reverse_ip_address_for_rbl($addr) . ".$domain";

  my $hn = gethostbyname($addr);
  return 0 unless defined($hn);
  return $hn if ($hn);

  # Hostname is defined, but false -- return 1 instead.
  return 1;
}

1;
