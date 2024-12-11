#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Net - Network related methods for email filters

=head1 DESCRIPTION

Mail::MIMEDefang::Net are a set of methods that can be called
from F<mimedefang-filter> to call network related services.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Net;

use strict;
use warnings;

use Socket;

use IO::Select;
use Net::DNS;
use Sys::Hostname;

use Mail::MIMEDefang;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(expand_ipv6_address reverse_ip_address_for_rbl relay_is_blacklisted email_is_blacklisted
                 relay_is_blacklisted_multi relay_is_blacklisted_multi_count relay_is_blacklisted_multi_list
                 is_public_ip4_address is_public_ip6_address md_get_bogus_mx_hosts get_mx_ip_addresses);
our @EXPORT_OK = qw(get_host_name get_ptr_record md_init);

sub md_init {
  my $digest_md5 = 0;
  my $digest_sha = 0;
  local $@;
  if (!defined($Features{"Digest::MD5"}) or ($Features{"Digest::MD5"} eq 1)) {
    eval {
      require Digest::MD5;
      $digest_md5 = 1;
    };
    if($@) {
      $digest_md5 = 0;
    } else {
      Digest::MD5->import(qw(md5_hex));
    }
  }
  if (!defined($Features{"Digest::SHA"}) or ($Features{"Digest::SHA"} eq 1)) {
    eval {
      require Digest::SHA;
      $digest_sha = 1;
    };
    if($@) {
      $digest_sha = 0;
    } else {
      Digest::SHA->import(qw(sha1_hex));
    }
  }
  $Features{"Digest::MD5"} = $digest_md5;
  $Features{"Digest::SHA"} = $digest_sha;
}

=item expand_ipv6_address

Method that returns an IPv6 address with all zero fields explicitly expanded,
any field shorter than 4 hex digits will be padded with zeros.

=cut

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

=item reverse_ip_address_for_rbl

Method that returns the ip address in the appropriately-reversed format used
for RBL lookups.

=cut

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

=item relay_is_blacklisted

Method that returns the result of the lookup (eg 127.0.0.2).
Parameters are the ip address of the relay host and the domain of the
rbl server.

=cut

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
  if (defined $hn) {
    return inet_ntoa($hn);
  }

  # Hostname is defined, but false -- return 1 instead.
  return 1;
}

=item email_is_blacklisted

Method that returns the result of the lookup (eg 127.0.0.2).
Parameters are an email address, the domain of the
hashbl server, and the type of hashing (MD5 or SHA1).

=cut

#***********************************************************************
# %PROCEDURE: email_is_blacklisted
# %ARGUMENTS:
#  email -- email address to check in hashbl.
#  domain -- domain of blacklist server (eg: ebl.msbl.org)
#  hash_type -- type of hash: MD5/SHA1
# %RETURNS:
#  The result of the lookup (eg 127.0.0.2)
#***********************************************************************
sub email_is_blacklisted {
  my($email, $domain, $hash_type) = @_;

  my $hashed;
  if($Features{'Digest::MD5'} eq 1 and uc($hash_type) eq 'MD5') {
    $hashed = md5_hex($email);
  } elsif($Features{'Digest::SHA'} eq 1 and uc($hash_type) eq 'SHA1') {
    $hashed = sha1_hex($email);
  } else {
    md_syslog("Warning", "Invalid or unsupported hash type in email_is_blacklisted call");
    return 0;
  }
  my $addr = $hashed . ".$domain";
  my $hn = gethostbyname($addr);
  return 0 unless defined($hn);
  if (defined $hn) {
    return inet_ntoa($hn);
  }

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

=item is_public_ip6_address $ip_addr

Returns true if $ip_addr is a publicly-routable IPv6 address, false otherwise

=cut

sub is_public_ip6_address {
	my ($addr) = @_;
	my @octets = split(/\:/, $addr);

	# Unique-local address
	return 0 if $octets[0] =~ /^fd/i;
	# Link-local address
	return 0 if $octets[0] =~ /^fe80/i;

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

=item get_ptr_record $domain [$resolver_object]

Get PTR record for given IP address.

=cut

sub get_ptr_record {
        my($ip, $res) = @_;
        unless ($Features{"Net::DNS"}) {
                md_syslog('err', "Attempted to call get_ptr_record, but Perl module Net::DNS is not installed");
                return;
        }
        if (!defined($res)) {
                $res = Net::DNS::Resolver->new;
                $res->defnames(0);
        }

        my $packet = $res->query(reverse_ip_address_for_rbl($ip) . ".in-addr.arpa", 'PTR');
        if (!defined($packet) ||
            $packet->header->rcode eq 'SERVFAIL' ||
            $packet->header->rcode eq 'NXDOMAIN' ||
            !defined($packet->answer)) {
	           return;
        }
        my $answer = ($packet->answer)[0];
        if(defined $answer) {
          my $res = $answer->rdstring;
          $res =~ s/\.$//;
          return $res;
        }
        return;
}

=item relay_is_blacklisted_multi

Method that rerurns a hash table with one entry per original domain.
Entries in hash will be:
C<{ $domain =<gt> $return }>, where $return is one of SERVFAIL, NXDOMAIN or
a list of IP addresses as a dotted-quad.

=cut

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
  my $sock;

  my $ans = {};
  my $positive_answers = 0;

  foreach my $domain (@{$domains}) {
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
  foreach my $domain (@{$domains}) {
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
    foreach my $rsock (@ready) {
      my $pack = $res->bgread($rsock);
      $sel->remove($sock);
      my $sdomain = $sock_to_domain{$rsock};
      undef($rsock);
      my($rr, $rcode);
      $rcode = $pack->header->rcode;
      if ($rcode eq "SERVFAIL" or $rcode eq "NXDOMAIN") {
        $ans->{$sdomain} = $rcode;
        next;
      }
      my $got_one = 0;
      foreach my $rr ($pack->answer) {
        if ($rr->type eq 'A') {
          $got_one = 1;
          if ($ans->{$sdomain} eq "SERVFAIL") {
            $ans->{$sdomain} = ();
          }
          push(@{$ans->{$sdomain}}, $rr->address);
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

=item relay_is_blacklisted_multi_count

Method that returns a number indicating how many RBLs the host
was blacklisted in.

=cut

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
  foreach my $domain (keys(%$ans)) {
	  my $r = $ans->{$domain};
	  if (ref($r) eq "ARRAY" and $#{$r} >= 0) {
	    $count++;
	  }
  }
  return $count;
}

=item relay_is_blacklisted_multi_list

Method that returns an array indicating the domains in which
the relay is blacklisted.

=cut

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
  foreach my $domain (keys(%$ans)) {
	  my $r = $ans->{$domain};
	  if (ref($r) eq "ARRAY" and $#{$r} >= 0) {
	    push @$result, $domain;
	  }
  }

  # If in list context, return the array.  Otherwise, return
  # array reference.
  return (wantarray ? @$result : $result);
}

=back

=cut

1;
