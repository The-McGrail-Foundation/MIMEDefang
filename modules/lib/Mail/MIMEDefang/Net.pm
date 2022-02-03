package Mail::MIMEDefang::Net;

use strict;
use warnings;

use Net::DNS;
use Sys::Hostname;

use Mail::MIMEDefang;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(expand_ipv6_address reverse_ip_address_for_rbl relay_is_black_listed
                 relay_is_blacklisted_multi relay_is_blacklisted_multi_count relay_is_blacklisted_multi_list
                 is_public_ip4_address md_get_bogus_mx_hosts get_mx_ip_addresses);
our @EXPORT_OK = qw(get_host_name);

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
	my($domain, $res) = @_;
	my @results;
	unless ($Features{"Net::DNS"}) {
    md_syslog('err', "Attempted to call get_mx_ip_addresses, but Perl module Net::DNS is not installed");
		return(@results);
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
			return (@results);
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
	return (@results);
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

#***********************************************************************
# %PROCEDURE: relay_is_blacklisted_multi
# %ARGUMENTS:
#  addr -- IP address of relay host.
#  timeout -- number of seconds after which to time out
#  answers_wanted -- if positive, return as soon as this many positive answers
#                    have been received.
#  domains -- an array of domains to check
#  res (optional) -- A Net::DNS::Resolver object.  If you don't pass
#                    one in, we'll generate one and use it.
# %RETURNS:
#  A hash table with one entry per original domain.  Entries in hash
#  will be:
#  { $domain => $return }, where $return is one of SERVFAIL, NXDOMAIN or
#  a list of IP addresses as a dotted-quad.
#***********************************************************************
sub relay_is_blacklisted_multi {
  my($addr, $timeout, $answers_wanted, $domains, $res) = @_;
  my($domain, $sock);

  my $ans = {};
  my $positive_answers = 0;

  foreach $domain (@{$domains}) {
    $ans->{$domain} = 'SERVFAIL';
  }
  unless ($Features{"Net::DNS"}) {
    md_syslog('err', "Attempted to call relay_is_blacklisted_multi, but Perl module Net::DNS is not installed");
    return $ans;
  }

  push_status_tag("Doing RBL Lookup");
  my %sock_to_domain;

  # Reverse the address
  $addr = reverse_ip_address_for_rbl($addr);

  # If user did not pass in a Net::DNS::Resolver object, generate one.
  unless (defined($res and (UNIVERSAL::isa($res, "Net::DNS::Resolver")))) {
    $res = Net::DNS::Resolver->new;
    $res->defnames(0);
  }

  my $sel = IO::Select->new();

  # Send out the queries
  foreach $domain (@{$domains}) {
    $sock = $res->bgsend("$addr.$domain", 'A');
    $sock_to_domain{$sock} = $domain;
    $sel->add($sock);
  }

  # Now wait for them to come back.
  my $terminate = time() + $timeout;
  while (time() <= $terminate) {
    my $expire = $terminate - time();
    # Avoid fractional wait for select which gets truncated.
    # So we may end up timing out after 1 extra second... no big deal
    $expire = 1 if ($expire < 1);
    my @ready;
    @ready = $sel->can_read($expire);
    foreach $sock (@ready) {
      my $pack = $res->bgread($sock);
      $sel->remove($sock);
      $domain = $sock_to_domain{$sock};
      undef($sock);
      my($rr, $rcode);
      $rcode = $pack->header->rcode;
      if ($rcode eq "SERVFAIL" or $rcode eq "NXDOMAIN") {
        $ans->{$domain} = $rcode;
        next;
      }
      my $got_one = 0;
      foreach $rr ($pack->answer) {
        if ($rr->type eq 'A') {
          $got_one = 1;
          if ($ans->{$domain} eq "SERVFAIL") {
            $ans->{$domain} = ();
          }
          push(@{$ans->{$domain}}, $rr->address);
        }
      }
      $positive_answers++ if ($got_one);
    }
    last if ($sel->count() == 0 or
      ($answers_wanted > 0 and $positive_answers >= $answers_wanted));
  }
  pop_status_tag();
  return $ans;
}

#***********************************************************************
# %PROCEDURE: relay_is_blacklisted_multi_count
# %ARGUMENTS:
#  addr -- IP address of relay host.
#  timeout -- number of seconds after which to time out
#  answers_wanted -- if positive, return as soon as this many positive answers
#                    have been received.
#  domains -- an array of domains to check
#  res (optional) -- A Net::DNS::Resolver object.  If you don't pass
#                    one in, we'll generate one and use it.
# %RETURNS:
#  A number indicating how many RBLs the host was blacklisted in.
#***********************************************************************
sub relay_is_blacklisted_multi_count {
  my($addr, $timeout, $answers_wanted, $domains, $res) = @_;
  my $ans = relay_is_blacklisted_multi($addr,
					 $timeout,
					 $answers_wanted,
					 $domains,
					 $res);
  my $count = 0;
  my $domain;
  foreach $domain (keys(%$ans)) {
	  my $r = $ans->{$domain};
	  if (ref($r) eq "ARRAY" and $#{$r} >= 0) {
	    $count++;
	  }
  }
  return $count;
}

#***********************************************************************
# %PROCEDURE: relay_is_blacklisted_multi_list
# %ARGUMENTS:
#  addr -- IP address of relay host.
#  timeout -- number of seconds after which to time out
#  answers_wanted -- if positive, return as soon as this many positive answers
#                    have been received.
#  domains -- an array of domains to check
#  res (optional) -- A Net::DNS::Resolver object.  If you don't pass
#                    one in, we'll generate one and use it.
# %RETURNS:
#  An array indicating the domains in which the relay is blacklisted.
#***********************************************************************
sub relay_is_blacklisted_multi_list {
  my($addr, $timeout, $answers_wanted, $domains, $res) = @_;
  my $ans = relay_is_blacklisted_multi($addr,
					 $timeout,
					 $answers_wanted,
					 $domains,
					 $res);
  my $result = [];
  my $domain;
  foreach $domain (keys(%$ans)) {
	  my $r = $ans->{$domain};
	  if (ref($r) eq "ARRAY" and $#{$r} >= 0) {
	    push @$result, $domain;
	  }
  }

  # If in list context, return the array.  Otherwise, return
  # array reference.
  return (wantarray ? @$result : $result);
}

1;
