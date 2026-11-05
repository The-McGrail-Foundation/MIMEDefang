#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Async::Checks - Pre-built check descriptors for Mail::MIMEDefang::Async

=head1 DESCRIPTION

Each function returns a check-hashref suitable for passing to
C<md_async_run_checks()>. Mix and match to build the checks your filter needs.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Async::Checks;

use strict;
use warnings;
use Exporter;

use Mail::MIMEDefang qw(%Features $CWD $ClamdSock $Sender @Recipients
                        $AddApparentlyToForSpamAssassin);
use Mail::MIMEDefang::Net qw(reverse_ip_address_for_rbl);
use Mail::MIMEDefang::Utils qw(synthesize_received_header);

our @ISA = qw(Exporter);
our @EXPORT = qw(
    md_async_check_dnsbl
    md_async_check_spf_record
    md_async_check_mx_exists
    md_async_check_rdns
    md_async_check_dkim_record
    md_async_check_dmarc_record
    md_async_check_clamd
    md_async_check_clamdscan
    md_async_check_spamc
    md_async_check_rspamd
);
our @EXPORT_OK;

our $VERSION = '1.0.0';

# DNS-based checks

=item md_async_check_dnsbl(%args)

Build a DNSBL A-record lookup check. Required args: C<ip>, C<zone>.
Optional: C<name>, C<timeout>.

=cut

sub md_async_check_dnsbl {
    my (%args) = @_;
    my $ip   = $args{ip}   // die "md_async_check_dnsbl: ip required";
    my $zone = $args{zone} // die "md_async_check_dnsbl: zone required";
    my $name = $args{name} // "dnsbl_${zone}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => reverse_ip_address_for_rbl($ip) . ".${zone}",
            type    => 'A',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_spf_record(%args)

Build an SPF TXT-record lookup check. Required: C<domain>.

=cut

sub md_async_check_spf_record {
    my (%args) = @_;
    my $domain = $args{domain} // die "md_async_check_spf_record: domain required";
    my $name   = $args{name}   // "spf_${domain}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => $domain,
            type    => 'TXT',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_mx_exists(%args)

Build an MX-record existence check. Domains with no MX are often forged.
Required: C<domain>.

=cut

sub md_async_check_mx_exists {
    my (%args) = @_;
    my $domain = $args{domain} // die "md_async_check_mx_exists: domain required";
    my $name   = $args{name}   // "mx_${domain}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => $domain,
            type    => 'MX',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_rdns(%args)

Build a reverse-DNS (PTR) lookup check. Required: C<ip>.

=cut

sub md_async_check_rdns {
    my (%args) = @_;
    my $ip   = $args{ip}   // die "md_async_check_rdns: ip required";
    my $name = $args{name} // "rdns_${ip}";

    my $suffix = ($ip =~ /:/) ? '.ip6.arpa' : '.in-addr.arpa';

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => reverse_ip_address_for_rbl($ip) . $suffix,
            type    => 'PTR',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_dkim_record(%args)

Build an async lookup for a DKIM public-key TXT record at
C<$selector._domainkey.$domain>. Required: C<selector>, C<domain>.

The result is the raw TXT record string. Signature evaluation still happens
synchronously via C<Mail::DKIM> after the key is fetched.

=cut

sub md_async_check_dkim_record {
    my (%args) = @_;
    my $selector = $args{selector} // die "md_async_check_dkim_record: selector required";
    my $domain   = $args{domain}   // die "md_async_check_dkim_record: domain required";
    my $name     = $args{name}     // "dkim_${selector}._domainkey.${domain}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => "${selector}._domainkey.${domain}",
            type    => 'TXT',
            timeout => $args{timeout} // 5,
        },
    };
}

=item md_async_check_dmarc_record(%args)

Build an async lookup for the DMARC TXT record at C<_dmarc.$domain>.
Required: C<domain>.

Use C<md_async_interpret_dmarc()> from L<Mail::MIMEDefang::Async::Results> to
parse the result.

=cut

sub md_async_check_dmarc_record {
    my (%args) = @_;
    my $domain = $args{domain} // die "md_async_check_dmarc_record: domain required";
    my $name   = $args{name}   // "dmarc_${domain}";

    return {
        name => $name,
        type => 'dns',
        args => {
            host    => "_dmarc.${domain}",
            type    => 'TXT',
            timeout => $args{timeout} // 5,
        },
    };
}

# Socket and process based checks (antivirus, antispam)

=item md_async_check_clamd(%args)

Build a clamd socket check that sends C<nSCAN $path> and reads the whole
reply. Optional: C<sock> (Unix socket path or C<host:port>, default
C<$ClamdSock>), C<path> (default C<$CWD/Work>), C<timeout> (default 30),
C<name> (default C<clamd>).

clamd opens C<$path> on its own filesystem, so this only works when clamd runs
on the same host as MIMEDefang; use C<md_async_check_clamdscan> for a remote
clamd. Interpret the result with C<md_async_interpret_clamav()> from
L<Mail::MIMEDefang::Async::Results>, or with
C<Mail::MIMEDefang::Antivirus::ClamAV::clamd_interpret_reply()> to get the
standard virus-scanner triplet.

=cut

sub md_async_check_clamd {
    my (%args) = @_;
    my $path = _scan_path('md_async_check_clamd', $args{path});
    my $sock = $args{sock} // $ClamdSock
        // die "md_async_check_clamd: no clamd socket configured";

    my %sock_args = (
        request    => "nSCAN $path\n",
        read_until => qr/(?!)/,    # never matches - read the whole reply, until EOF
        max_bytes  => 65536,
        timeout    => $args{timeout} // 30,
    );
    if ($sock =~ /:/) {
        @sock_args{qw(host port)} = split /:/, $sock, 2;
    } else {
        $sock_args{unix_path} = $sock;
    }

    return {
        name => $args{name} // 'clamd',
        type => 'socket',
        args => \%sock_args,
    };
}

=item md_async_check_clamdscan(%args)

Build a process check that runs C<clamdscan --stream>, which streams the
files to clamd (INSTREAM) and so works with a local or a remote clamd.
Optional: C<conf> (path to C<clamd.conf>, default
C<$Features{'Path:CLAMDCONF'}>), C<path> (default C<$CWD/Work>),
C<timeout> (default 60), C<name> (default C<clamdscan>).

Dies if clamdscan is not installed. The result is a hashref with
C<stdout>, C<stderr> and C<exit_code>; C<md_async_interpret_clamav()>
understands it.

=cut

sub md_async_check_clamdscan {
    my (%args) = @_;
    my $path = _scan_path('md_async_check_clamdscan', $args{path});
    my $clamdscan = $Features{'Virus:CLAMDSCAN'}
        or die "md_async_check_clamdscan: clamdscan not installed";
    my $conf = $args{conf} // $Features{'Path:CLAMDCONF'};

    my @cmd = ($clamdscan);
    push @cmd, '-c', $conf if defined $conf;
    push @cmd, '--no-summary', '--infected', '--fdpass', '--stream', $path;

    return {
        name => $args{name} // 'clamdscan',
        type => 'process',
        args => { cmd => \@cmd, timeout => $args{timeout} // 60 },
    };
}

# Path to scan: the explicit one, else $CWD/Work; dies when neither is set.
sub _scan_path {
    my ($caller, $path) = @_;
    return $path if defined $path;
    die "$caller: no path given and \$CWD is not set" unless defined $CWD;
    return "$CWD/Work";
}

# Read ./INPUTMSG, dies on failure.
sub _read_inputmsg {
    my ($caller) = @_;
    open(my $in, '<', './INPUTMSG') or die "$caller: cannot open INPUTMSG: $!";
    local $/;
    my $msg = <$in>;
    close($in);
    return $msg // '';
}

=item md_async_check_spamc(%args)

Build a spamd socket check that sends the message (C<./INPUTMSG>, with the
synthesized C<Return-Path>, C<Received> and optional C<Apparently-To>
headers) using the SPAMC C<CHECK> command. Optional: C<host> (default
C<127.0.0.1>), C<port> (default 783), C<user> (default current user),
C<timeout> (default 30), C<name> (default C<spamc>).

Dies if C<./INPUTMSG> cannot be read. Interpret the result with
C<md_async_interpret_spamassassin()>.

=cut

sub md_async_check_spamc {
    my (%args) = @_;
    my $user = $args{user} // getpwuid($<);

    my $sahdrs = "Return-Path: " . ($Sender // '') . "\n";
    $sahdrs   .= synthesize_received_header();
    if ($AddApparentlyToForSpamAssassin && @Recipients) {
        $sahdrs .= "Apparently-To: " . join(', ', @Recipients) . "\n";
    }
    my $msg = $sahdrs . _read_inputmsg('md_async_check_spamc');

    my $request = join("\r\n",
        "CHECK SPAMC/1.5",
        "Content-length: " . length($msg),
        "User: $user",
        '',
        $msg,
    );

    return {
        name => $args{name} // 'spamc',
        type => 'socket',
        args => {
            host       => $args{host} // '127.0.0.1',
            port       => $args{port} // 783,
            request    => $request,
            read_until => qr/\r\n\r\n/,
            max_bytes  => 65536,
            timeout    => $args{timeout} // 30,
        },
    };
}

=item md_async_check_rspamd(%args)

Build an Rspamd socket check that POSTs C<./INPUTMSG> to C<$uri/checkv2>
over HTTP/1.0. Optional: C<uri> (default C<http://127.0.0.1:11333>),
C<timeout> (default 30), C<name> (default C<rspamd>).

Dies if C<./INPUTMSG> cannot be read. The result is the raw HTTP response;
the JSON body follows the first blank line.

=cut

sub md_async_check_rspamd {
    my (%args) = @_;
    my $uri = $args{uri} // 'http://127.0.0.1:11333';

    my ($host, $port) = ('127.0.0.1', 11333);
    if ($uri =~ m{https?://([^/:]+)(?::(\d+))?}) {
        $host = $1;
        $port = $2 // 11333;
    }

    my $mail    = _read_inputmsg('md_async_check_rspamd');
    my $request = join("\r\n",
        "POST /checkv2 HTTP/1.0",
        "Host: $host:$port",
        "User-Agent: MIMEDefang",
        "Content-Type: text/plain",
        "Content-Length: " . length($mail),
        '',
        $mail,
    );

    return {
        name => $args{name} // 'rspamd',
        type => 'socket',
        args => {
            host       => $host,
            port       => $port,
            request    => $request,
            read_until => qr/(?!)/,    # never matches - HTTP/1.0 closes after response
            max_bytes  => 131072,
            timeout    => $args{timeout} // 30,
        },
    };
}

=back

=head1 SEE ALSO

L<Mail::MIMEDefang::Async>, L<Mail::MIMEDefang::Async::Results>

=cut

1;
