package Mail::MIMEDefang::Net;

use strict;
use warnings;

use Net::DNS;
use Sys::Hostname;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(expand_ipv6_address reverse_ip_address_for_rbl relay_is_black_listed
                 is_public_ip4_address md_get_bogus_mx_hosts);
our @EXPORT_OK = qw(get_host_name get_mx_ip_addresses);

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

#***********************************************************************
# %PROCEDURE: get_host_name
# %ARGUMENTS:
#  None
# %RETURNS:
#  Local host name, if it could be determined.
#***********************************************************************
sub get_host_name {
  my ($PrivateMyHostName) = @_;
  # Use cached value if we have it
  return $PrivateMyHostName if defined($PrivateMyHostName);

  # Otherwise execute "hostname"
  $PrivateMyHostName = hostname;

  $PrivateMyHostName = "localhost" unless defined($PrivateMyHostName);

  # Now make it FQDN
  my($fqdn) = gethostbyname($PrivateMyHostName);
  $PrivateMyHostName = $fqdn if (defined $fqdn) and length($fqdn) > length($PrivateMyHostName);

  return $PrivateMyHostName;
}

=item is_public_ip4_address $ip_addr

Returns true if $ip_addr is a publicly-routable IPv4 address, false otherwise

=cut
sub is_public_ip4_address {
	my ($addr) = @_;
	my @octets = split(/\./, $addr);

	# Sanity check: Return false if it's not an IPv4 address
	return 0 unless (scalar(@octets) == 4);
	foreach my $octet (@octets) {
		return 0 if ($octet !~ /^\d+$/);
		return 0 if ($octet > 255);
	}

	# 10.0.0.0 to 10.255.255.255
	return 0 if ($octets[0] == 10);

	# 172.16.0.0 to 172.31.255.255
	return 0 if ($octets[0] == 172 && $octets[1] >= 16 && $octets[1] <= 31);

	# 192.168.0.0 to 192.168.255.255
	return 0 if ($octets[0] == 192 && $octets[1] == 168);

	# Loopback
	return 0 if ($octets[0] == 127);

	# Local-link for auto-DHCP
	return 0 if ($octets[0] == 169 && $octets[1] == 254);

	# IPv4 multicast
	return 0 if ($octets[0] >= 224 && $octets[0] <= 239);

	# Class E ("Don't Use")
	return 0 if ($octets[0] >= 240 && $octets[0] <= 247);

	# 0.0.0.0 and 255.255.255.255 are bogus
	return 0 if ($octets[0] == 0 &&
		     $octets[1] == 0 &&
		     $octets[2] == 0 &&
		     $octets[3] == 0);

	return 0 if ($octets[0] == 255 &&
		     $octets[1] == 255 &&
		     $octets[2] == 255 &&
		     $octets[3] == 255);
	return 1;
}


=item get_mx_ip_addresses $domain [$resolver_object]

Get IP addresses of all MX hosts for given domain.  If there are
no MX hosts, then return A records.

=cut
sub get_mx_ip_addresses {
	my($domain, $res, %Features) = @_;
	my @results;
	unless ($Features{"Net::DNS"}) {
		return(@results, 'err', "Attempted to call get_mx_ip_addresses, but Perl module Net::DNS is not installed");
	}
	if (!defined($res)) {
		$res = Net::DNS::Resolver->new;
		$res->defnames(0);
	}

	my $packet = $res->query($domain, 'MX');
	if (!defined($packet) ||
	    $packet->header->rcode eq 'SERVFAIL' ||
	    $packet->header->rcode eq 'NXDOMAIN' ||
	    !defined($packet->answer)) {
		# No MX records; try A records
		$packet = $res->query($domain, 'A');
		if (!defined($packet) ||
		    $packet->header->rcode eq 'SERVFAIL' ||
		    $packet->header->rcode eq 'NXDOMAIN' ||
		    !defined($packet->answer)) {
			return (@results,undef,undef);
		}
	}
	foreach my $item ($packet->answer) {
		if ($item->type eq 'MX') {

			# Weird MX record of "." or ""
			# host -t mx yahoo.com.pk for example
			if ($item->exchange eq '' ||
			    $item->exchange eq '.' ||
			    $item->exchange eq '0' ||
			    $item->exchange eq '0 ' ||
			    $item->exchange eq '0 .' ||
			    $item->exchange eq '0.') {
				push(@results, '0.0.0.0');
				next;
			}

			# If it LOOKS like an IPv4 address, don't do
			# an A lookup
			if ($item->exchange =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.?$/) {
				my ($a, $b, $c, $d) = ($1, $2, $3, $4);
				if ($a <= 255 && $b <= 255 && $c <= 255 && $d <= 255) {
					push(@results, "$a.$b.$c.$d");
					next;
				}
			}

			my $packet2 = $res->query($item->exchange, 'A');
			next unless defined($packet2);
			next if $packet2->header->rcode eq 'SERVFAIL';
			next if $packet2->header->rcode eq 'NXDOMAIN';
			next unless defined($packet2->answer);
			foreach my $item2 ($packet2->answer) {
				if ($item2->type eq 'A') {
					push(@results, $item2->address);
				}
			}
		} elsif ($item->type eq 'A') {
			push(@results, $item->address);
		}
	}
	return (@results,undef,undef);
}

=item md_get_bogus_mx_hosts $domain

Returns a list of "bogus" IP addresses that are in $domain's list of MX
records.  A "bogus" IP address is loopback/private/multicast/etc.

=cut

sub md_get_bogus_mx_hosts {
	my ($domain) = @_;
	my @bogus_hosts = ();
	my @mx = get_mx_ip_addresses($domain);
	foreach my $mx (@mx) {
		if (!is_public_ip4_address($mx)) {
			push(@bogus_hosts, $mx);
		}
	}
	return @bogus_hosts;
}

1;
