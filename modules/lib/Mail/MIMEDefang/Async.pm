#
# This program may be distributed under the terms of the GNU General
# Public License, Version 2.
#

=head1 NAME

Mail::MIMEDefang::Async - Asynchronous I/O engine for MIMEDefang external checks

=head1 DESCRIPTION

Mail::MIMEDefang::Async provides concurrent DNS, socket-based, and
process-based checks for use in MIMEDefang filter callbacks.  All checks
share a single AnyEvent event loop and the call blocks until every check has
completed or the global timeout fires.

Requires the optional modules B<AnyEvent>, B<AnyEvent::DNS>,
B<AnyEvent::Socket>, and B<AnyEvent::Util> from CPAN.

=head1 METHODS

=over 4

=cut

package Mail::MIMEDefang::Async;

use strict;
use warnings;
use Exporter;
use Carp qw(croak carp);

use Mail::MIMEDefang qw(%Features $CWD $ClamdSock $Sender @Recipients
                        $AddApparentlyToForSpamAssassin md_syslog);
use Mail::MIMEDefang::Antispam qw(spam_assassin_check);
use Mail::MIMEDefang::Net qw(reverse_ip_address_for_rbl);
use Mail::MIMEDefang::SPF qw(md_spf_verify);
use Mail::MIMEDefang::Utils qw(synthesize_received_header);
use Mail::MIMEDefang::Async::Checks qw(
    md_async_check_dnsbl
    md_async_check_spf_record
    md_async_check_mx_exists
    md_async_check_rdns
    md_async_check_dkim_record
    md_async_check_dmarc_record
);
use Mail::MIMEDefang::Async::Results qw(
    md_async_interpret_dnsbl
    md_async_interpret_spamassassin
    md_async_interpret_clamav
    md_async_interpret_rdns
    md_async_interpret_spf_txt
    md_async_interpret_dmarc
    md_async_score_results
);

our @ISA = qw(Exporter);
our @EXPORT = qw(
    md_async_init
    md_async_run_checks
    md_async_relay_is_blacklisted
    md_async_email_is_blacklisted
    md_async_spf_verify
    md_async_dmarc_verify
    md_async_message_contains_virus_clamd
    md_async_message_contains_virus_clamdscan
    md_async_spamc_check
    md_async_spam_assassin_check
    md_async_rspamd_check
    md_async_check_dnsbl
    md_async_check_spf_record
    md_async_check_mx_exists
    md_async_check_rdns
    md_async_check_dkim_record
    md_async_check_dmarc_record
    md_async_interpret_dnsbl
    md_async_interpret_spamassassin
    md_async_interpret_clamav
    md_async_interpret_rdns
    md_async_interpret_spf_txt
    md_async_interpret_dmarc
    md_async_score_results
);
our @EXPORT_OK;

our $VERSION = '1.0.0';

# Module-level engine instance, created by md_async_init().
my $_ENGINE;

# Internal engine class

sub _new {
    my ($class, %args) = @_;

    my $self = bless {
        max_concurrency => $args{max_concurrency} // 10,
        global_timeout  => $args{global_timeout}  // 10,
        dns_timeout     => $args{dns_timeout}      // 5,
        socket_timeout  => $args{socket_timeout}   // 5,
        _results        => {},
        _errors         => {},
        _pending        => 0,
        _cv             => undef,
        _generation     => 0,
    }, $class;

    $self->_build_resolver;

    return $self;
}

# Build (or rebuild) the private DNS resolver for the current process and
# record the PID that owns it.
sub _build_resolver {
    my ($self) = @_;

    eval { require AnyEvent::DNS };
    croak "AnyEvent::DNS is required for Mail::MIMEDefang::Async: $@" if $@;

    my $resolver = AnyEvent::DNS->new(
        timeout => [ $self->{dns_timeout} ],
        reuse   => 1,
    );
    $resolver->os_config;
    $self->{_resolver} = $resolver;
    $self->{_pid}      = $$;
    return $resolver;
}

# Recreate the resolver if we have crossed a fork() boundary, so the inherited
# (shared) socket from the master is never used to send queries.
sub _ensure_resolver {
    my ($self) = @_;
    $self->_build_resolver if ($self->{_pid} // 0) != $$;
}

sub _run_checks {
    my ($self, $checks) = @_;

    croak "_run_checks expects an arrayref" unless ref $checks eq 'ARRAY';
    return {} unless @$checks;

    eval { require AnyEvent };
    croak "AnyEvent is required for Mail::MIMEDefang::Async: $@" if $@;

    $self->_ensure_resolver;
    AnyEvent->now_update;

    $self->{_results} = {};
    $self->{_errors}  = {};
    $self->{_pending} = scalar @$checks;
    $self->{_cv}      = AnyEvent->condvar;

    my $gen = ++$self->{_generation};

    my $deadline = AnyEvent->timer(
        after => $self->{global_timeout},
        cb    => sub {
            return if $gen != $self->{_generation};
            carp "[Mail::MIMEDefang::Async] Global timeout reached – cancelling remaining checks";
            $self->{_cv}->send('timeout');
        },
    );

    my $sem  = $self->{max_concurrency};
    my @queue = @$checks;

    my $drain;
    $drain = sub {
        while ($sem > 0 && @queue) {
            $sem--;
            my $check = shift @queue;
            my $fired = 0;
            $self->_dispatch($check, sub {
                return if $gen != $self->{_generation};  # leaked from a prior batch
                return if $fired++;   # prevent double-completion from stale callbacks
                $sem++;
                $drain->();
                $self->{_pending}--;
                $self->{_cv}->send('done') if $self->{_pending} <= 0;
            });
        }
    };
    $drain->();

    $self->{_cv}->recv;
    undef $deadline;

    return {
        results => $self->{_results},
        errors  => $self->{_errors},
    };
}

sub _dispatch {
    my ($self, $check, $done_cb) = @_;

    my $type = lc($check->{type} // '');
    my $name = $check->{name}    // 'unnamed';

    if    ($type eq 'dns')     { $self->_dns_check($name,     $check->{args}, $done_cb) }
    elsif ($type eq 'socket')  { $self->_socket_check($name,  $check->{args}, $done_cb) }
    elsif ($type eq 'process') { $self->_process_check($name, $check->{args}, $done_cb) }
    else {
        $self->{_errors}{$name} = "Unknown check type: $type";
        $done_cb->();
    }
}

# DNS check
# args: { host => '...', type => 'A'|'TXT'|'MX'|'PTR' }

sub _dns_check {
    my ($self, $name, $args, $done_cb) = @_;

    my $host    = $args->{host} or do {
        $self->{_errors}{$name} = "No host for DNS check";
        $done_cb->();
        return;
    };
    my $rrtype  = lc($args->{type} // 'a');
    my $timeout = $args->{timeout} // $self->{dns_timeout};

    my $timer = AnyEvent->timer(
        after => $timeout,
        cb    => sub {
            $self->{_errors}{$name} = "DNS timeout after ${timeout}s for $host";
            $done_cb->();
        },
    );

    $self->{_resolver}->resolve(
        $host, $rrtype,
        sub {
            undef $timer;
            my @records = @_;
            $self->{_results}{$name} = @records
                ? [ map { $_->[-1] } @records ]
                : undef;
            $done_cb->();
        }
    );
}

# Socket check (Clamd, Spamd, custom line-protocol daemons)
# args: { host, port, unix_path, request, read_until, max_bytes }

sub _socket_check {
    my ($self, $name, $args, $done_cb) = @_;

    my $timeout   = $args->{timeout}    // $self->{socket_timeout};
    my $request   = $args->{request}    // '';
    my $sentinel  = $args->{read_until} // qr/\n/;
    my $max_bytes = $args->{max_bytes}  // 65536;

    eval { require AnyEvent::Socket };
    if ($@) {
        $self->{_errors}{$name} = "AnyEvent::Socket not available: $@";
        $done_cb->();
        return;
    }

    my ($connect_host, $connect_port);
    if (my $path = $args->{unix_path}) {
        $connect_host = 'unix/';
        $connect_port = $path;
    } else {
        $connect_host = $args->{host} or do {
            $self->{_errors}{$name} = "No host/unix_path for socket check";
            $done_cb->();
            return;
        };
        $connect_port = $args->{port} or do {
            $self->{_errors}{$name} = "No port for socket check";
            $done_cb->();
            return;
        };
    }

    my ($handle, $timer);

    my $cleanup = sub {
        undef $timer;
        undef $handle;
    };

    $timer = AnyEvent->timer(
        after => $timeout,
        cb    => sub {
            $cleanup->();
            $self->{_errors}{$name} = "Socket timeout after ${timeout}s";
            $done_cb->();
        },
    );

    AnyEvent::Socket::tcp_connect($connect_host, $connect_port, sub {
        my ($fh) = @_ or do {
            undef $timer;
            $self->{_errors}{$name} = "Connection failed: $!";
            $done_cb->();
            return;
        };

        unless (eval { require AnyEvent::Handle; 1 }) {
            undef $timer;
            $self->{_errors}{$name} = "AnyEvent::Handle not available: $@";
            $done_cb->();
            return;
        }
        my $buf = '';
        $handle = AnyEvent::Handle->new(
            fh       => $fh,
            on_error => sub {
                my (undef, undef, $msg) = @_;
                $cleanup->();
                $self->{_errors}{$name} = "Socket error: $msg";
                $done_cb->();
            },
            on_eof => sub {
                $cleanup->();
                if (length $buf) {
                    $self->{_results}{$name} = $buf;
                } else {
                    $self->{_errors}{$name} = "Connection closed with no data";
                }
                $done_cb->();
            },
        );

        $handle->push_write($request) if length $request;

        my $reader;
        $reader = sub {
            my (undef, $chunk) = @_;
            $buf .= $chunk;
            if ($buf =~ $sentinel || length($buf) >= $max_bytes) {
                $cleanup->();
                $self->{_results}{$name} = $buf;
                $done_cb->();
            } else {
                $handle->push_read(chunk => 1024, $reader);
            }
        };
        $handle->push_read(chunk => 1024, $reader);
    });
}

# Process check (external command via AnyEvent::Util::run_cmd)
# args: { cmd => \@argv, timeout => N }
# result: { stdout => '...', stderr => '...', exit_code => N }

sub _process_check {
    my ($self, $name, $args, $done_cb) = @_;

    my $cmd = $args->{cmd} or do {
        $self->{_errors}{$name} = "No cmd for process check";
        $done_cb->(); return;
    };
    my $timeout = $args->{timeout} // $self->{socket_timeout};

    unless (eval { require AnyEvent::Util; 1 }) {
        $self->{_errors}{$name} = "AnyEvent::Util not available: $@";
        $done_cb->(); return;
    }

    my ($stdout, $stderr) = ('', '');
    my ($cv, $timer);

    $timer = AnyEvent->timer(
        after => $timeout,
        cb    => sub {
            undef $cv;
            $self->{_errors}{$name} = "Process timeout after ${timeout}s";
            $done_cb->();
        },
    );

    $cv = AnyEvent::Util::run_cmd($cmd, '>' => \$stdout, '2>' => \$stderr);
    $cv->cb(sub {
        undef $timer;
        my $status = eval { shift->recv };
        if ($@) {
            $self->{_errors}{$name} = "Process error: $@";
            $done_cb->(); return;
        }
        $self->{_results}{$name} = {
            stdout    => $stdout,
            stderr    => $stderr,
            exit_code => ($status >> 8),
        };
        $done_cb->();
    });
}

# Public functional API

=item md_async_init(%opts)

Initialise the async engine.  Call once per process (e.g. at the top of your
mimedefang-filter, after C<use Mail::MIMEDefang::Async>).

Options:

  max_concurrency  Max parallel checks in flight (default: 10)
  global_timeout   Hard wall-clock limit for the whole batch (default: 10s)
  dns_timeout      Per-DNS-query timeout (default: 5s)
  socket_timeout   Per-socket-connection timeout (default: 5s)

=cut

sub md_async_init {
    my (%args) = @_;
    $_ENGINE = Mail::MIMEDefang::Async->_new(%args);
    return $_ENGINE;
}

=item md_async_run_checks(\@checks)

Run a list of check descriptors concurrently. Blocks until all checks complete or
the global timeout fires. Returns C<{ results =E<gt> \%r, errors =E<gt> \%e }>.

Each check is a hashref with C<name>, C<type> (C<'dns'>, C<'socket'>, or
C<'process'>), and C<args>.  Use L<Mail::MIMEDefang::Async::Checks> to build
them.

=cut

sub md_async_run_checks {
    my ($checks) = @_;
    unless (defined $_ENGINE) {
        carp "md_async_run_checks() called before md_async_init() -- initialising with defaults";
        $_ENGINE = Mail::MIMEDefang::Async->_new();
    }
    return $_ENGINE->_run_checks($checks);
}

=item md_async_relay_is_blacklisted($addr, $zone)

Async drop-in replacement for C<relay_is_blacklisted> from
L<Mail::MIMEDefang::Net>.

Looks up C<reverse_ip($addr).$zone> as a DNS A record. Returns the first
matching IP string on a listing, C<0> if not listed, or C<undef> on
error/timeout.

=cut

sub md_async_relay_is_blacklisted {
    my ($addr, $zone) = @_;
    croak "Call md_async_init() first" unless defined $_ENGINE;

    my $host = reverse_ip_address_for_rbl($addr) . ".$zone";
    my $out  = $_ENGINE->_run_checks([{
        name => '_rbl_check',
        type => 'dns',
        args => { host => $host, type => 'A' },
    }]);

    return if $out->{errors}{_rbl_check};

    my $records = $out->{results}{_rbl_check};
    my @hits = grep { !/^127\.255\.255\./ } @$records;
    return 0 unless scalar @hits > 0;

    return \@hits;
}

=item md_async_email_is_blacklisted($email, $zone, $hash_type)

Async drop-in replacement for C<email_is_blacklisted> from
L<Mail::MIMEDefang::Net>.

Hashes C<$email> using B<MD5> or B<SHA1> (controlled by C<$hash_type>), then
looks up C<$hash.$zone>. Returns the first matching IP string, C<0> if not
listed, or C<undef> on error/timeout.

=cut

sub md_async_email_is_blacklisted {
    my ($email, $zone, $hash_type) = @_;
    croak "Call md_async_init() first" unless defined $_ENGINE;

    my $hashed;
    if ($Features{'Digest::MD5'} && uc($hash_type) eq 'MD5') {
        require Digest::MD5;
        $hashed = Digest::MD5::md5_hex($email);
    } elsif ($Features{'Digest::SHA'} && uc($hash_type) eq 'SHA1') {
        require Digest::SHA;
        $hashed = Digest::SHA::sha1_hex($email);
    } else {
        md_syslog('warning', "Invalid or unsupported hash type in md_async_email_is_blacklisted call");
        return 0;
    }

    my $out = $_ENGINE->_run_checks([{
        name => '_hashbl_check',
        type => 'dns',
        args => { host => "$hashed.$zone", type => 'A' },
    }]);

    return if $out->{errors}{_hashbl_check};

    my $records = $out->{results}{_hashbl_check};
    return 0 unless defined $records && @$records;
    return $records->[0];
}

=item md_async_spf_verify($mail, $relayip, $helo)

Async-enhanced replacement for C<md_spf_verify> from L<Mail::MIMEDefang::SPF>.

Pre-fetches the sender domain's SPF TXT record via the async engine, then
evaluates it using L<Mail::SPF> synchronously. Returns the same values as
C<md_spf_verify>. Returns C<undef> immediately if C<Mail::SPF> is not
installed.

=cut

sub md_async_spf_verify {
    my ($spfmail, $relayip, $helo) = @_;
    croak "Call md_async_init() first" unless defined $_ENGINE;

    eval { require Mail::SPF };
    if ($@) {
        md_syslog('warning', "Mail::SPF not available for md_async_spf_verify");
        return;
    }

    # Extract sender domain for async DNS pre-fetch (warms resolver cache)
    (my $mail = $spfmail // '') =~ s/^<|>$//g;
    my ($domain) = ($mail =~ /\@([\w.\-]+)/);
    if ($domain) {
        $_ENGINE->_run_checks([{
            name => '_spf_prefetch',
            type => 'dns',
            args => { host => $domain, type => 'TXT' },
        }]);
    }

    # Delegate to md_spf_verify, cache is warm, logic is identical
    return md_spf_verify($spfmail, $relayip, $helo);
}

=item md_async_dmarc_verify($domain)

Async replacement for C<md_get_dmarc_record> from L<Mail::MIMEDefang::Net>.

Performs an async TXT lookup on C<_dmarc.$domain> and returns the raw DMARC
policy string, or C<undef> if none exists. Applies the same parent-domain
fallback logic as the original.

=cut

sub md_async_dmarc_verify {
    my ($domain) = @_;
    croak "Call md_async_init() first" unless defined $_ENGINE;
    return unless defined $domain;

    return _async_dmarc_lookup($domain);
}

sub _async_dmarc_lookup {
    my ($domain) = @_;
    return unless defined $domain;

    my $out = $_ENGINE->_run_checks([{
        name => '_dmarc_lookup',
        type => 'dns',
        args => { host => "_dmarc.$domain", type => 'TXT' },
    }]);

    if ($out->{errors}{_dmarc_lookup}) {
        # Try parent domain (strip leftmost label)
        my @dots = $domain =~ /\./g;
        return if @dots <= 1;
        (my $parent = $domain) =~ s/[^.]+\.//;
        return _async_dmarc_lookup($parent);
    }

    my $records = $out->{results}{_dmarc_lookup};
    unless (defined $records && @$records) {
        my @dots = $domain =~ /\./g;
        return if @dots <= 1;
        (my $parent = $domain) =~ s/[^.]+\.//;
        return _async_dmarc_lookup($parent);
    }

    my $raw = $records->[0];
    return unless defined $raw;
    $raw =~ s/^"|"$//g;
    chomp $raw;
    return $raw;
}

=item md_async_message_contains_virus_clamd($clamd_sock)

Async replacement for C<message_contains_virus_clamd> from
L<Mail::MIMEDefang::Antivirus>.

Sends a C<SCAN $CWD/Work> command to the clamd daemon over a socket and
interprets the response. C<$clamd_sock> may be a Unix socket path or a
C<host:port> string; defaults to C<$ClamdSock>.

B<Note>: the C<SCAN> command instructs clamd to open the path on its own
filesystem. This only works when clamd runs on the same host as MIMEDefang.
For remote clamd, use C<md_async_message_contains_virus_clamdscan> instead.

Returns the standard virus-scanner triplet C<($code, $category, $action)>:

  (0,   'ok',             'ok')          clean
  (1,   'virus',          'quarantine')  virus found
  (999, 'cannot-execute', 'tempfail')    cannot connect
  (999, 'swerr',          'tempfail')    scan error

=cut

sub md_async_message_contains_virus_clamd {
    my ($clamd_sock) = @_;
    $clamd_sock //= $ClamdSock;
    croak "Call md_async_init() first" unless defined $_ENGINE;

    unless (defined $clamd_sock) {
        md_syslog('err', "md_async_message_contains_virus_clamd: no clamd socket configured");
        return wantarray ? (999, 'swerr', 'tempfail') : 999;
    }

    my %sock_args = (
        request    => "SCAN $CWD/Work\n",
        read_until => qr/\n/,
        max_bytes  => 4096,
        timeout    => 30,
    );

    if ($clamd_sock =~ /:/) {
        my ($host, $port) = split /:/, $clamd_sock, 2;
        $sock_args{host} = $host;
        $sock_args{port} = $port;
    } else {
        $sock_args{unix_path} = $clamd_sock;
    }

    my $out = $_ENGINE->_run_checks([{
        name => '_clamd_scan',
        type => 'socket',
        args => \%sock_args,
    }]);

    if ($out->{errors}{_clamd_scan}) {
        md_syslog('err', "md_async_message_contains_virus_clamd: $out->{errors}{_clamd_scan}");
        return wantarray ? (999, 'cannot-execute', 'tempfail') : 999;
    }

    my $output = $out->{results}{_clamd_scan} // '';

    if ($output =~ /: (.+) FOUND/) {
        my $virus = $1;
        md_syslog('info', "md_async_message_contains_virus_clamd: clamd found $virus");
        return wantarray ? (1, 'virus', 'quarantine') : 1;
    }
    if ($output =~ /: (.+) ERROR/) {
        md_syslog('err', "md_async_message_contains_virus_clamd: clamd error: $1");
        return wantarray ? (999, 'swerr', 'tempfail') : 999;
    }

    return wantarray ? (0, 'ok', 'ok') : 0;
}

=item md_async_message_contains_virus_clamdscan($conf)

Async replacement for C<message_contains_virus_clamdscan> from
L<Mail::MIMEDefang::Antivirus>.

Spawns C<clamdscan --stream> which uses the C<INSTREAM> wire protocol,
streaming file data to clamd rather than asking it to open a local path.
This makes it suitable for both a local Unix-socket clamd and a remote TCP
clamd. C<$conf> is the path to C<clamd.conf>; defaults to
C<$Features{'Path:CLAMDCONF'}>. The socket clamd listens on (Unix or TCP)
is determined by the C<LocalSocket> / C<TCPAddr> + C<TCPSocket> directives in
that config file.

Returns the standard virus-scanner triplet C<($code, $category, $action)>:

  (0,   'ok',             'ok')           clean
  (1,   'virus',          'quarantine')   virus found
  (1,   'not-installed',  'tempfail')     clamdscan binary not found
  (999, 'cannot-execute', 'tempfail')     could not spawn / timeout
  (999, 'swerr',          'tempfail')     scan error (clamdscan exit >= 2)

=cut

sub md_async_message_contains_virus_clamdscan {
    my ($conf) = @_;
    $conf //= $Features{'Path:CLAMDCONF'};
    croak "Call md_async_init() first" unless defined $_ENGINE;

    unless ($Features{'Virus:CLAMDSCAN'}) {
        md_syslog('err', "md_async_message_contains_virus_clamdscan: clamdscan not installed");
        return wantarray ? (1, 'not-installed', 'tempfail') : 1;
    }

    my @cmd = (
        $Features{'Virus:CLAMDSCAN'},
        '-c', $conf,
        '--no-summary', '--infected', '--fdpass', '--stream',
        "$CWD/Work",
    );

    my $out = $_ENGINE->_run_checks([{
        name => '_clamdscan',
        type => 'process',
        args => { cmd => \@cmd, timeout => 60 },
    }]);

    if ($out->{errors}{_clamdscan}) {
        md_syslog('err', "md_async_message_contains_virus_clamdscan: $out->{errors}{_clamdscan}");
        return wantarray ? (999, 'cannot-execute', 'tempfail') : 999;
    }

    my $result    = $out->{results}{_clamdscan} // {};
    my $exit_code = $result->{exit_code} // 999;
    my $output    = ($result->{stdout} // '') . ($result->{stderr} // '');

    if ($exit_code == 0) {
        return wantarray ? (0, 'ok', 'ok') : 0;
    }
    if ($exit_code == 1) {
        my $virus = 'unknown-Clamav-virus';
        $virus = $1 if $output =~ /: (.+) FOUND/;
        md_syslog('info', "md_async_message_contains_virus_clamdscan: found $virus");
        return wantarray ? (1, 'virus', 'quarantine') : 1;
    }
    md_syslog('err', "md_async_message_contains_virus_clamdscan: clamdscan error (code $exit_code)");
    return wantarray ? (999, 'swerr', 'tempfail') : 999;
}

=item md_async_spamc_check(%args)

Async replacement for C<md_spamc_check> from L<Mail::MIMEDefang::Antispam>.

Sends the message to spamd using the raw SPAMC wire protocol over an async
socket, without requiring L<Mail::SpamAssassin::Client>.

Args: C<host> (default C<127.0.0.1>), C<port> (default 783),
C<user> (default current user), C<timeout> (default 30s).

Returns the same four-element list as C<md_spamc_check>:
C<($score, $threshold, $report, $isspam)>, or C<undef> on failure.

=cut

sub md_async_spamc_check {
    my (%args) = @_;
    croak "Call md_async_init() first" unless defined $_ENGINE;

    my $host    = $args{host}    // '127.0.0.1';
    my $port    = $args{port}    // 783;
    my $user    = $args{user}    // getpwuid($<);
    my $timeout = $args{timeout} // 30;

    open(my $in, '<', './INPUTMSG') or do {
        md_syslog('err', "md_async_spamc_check: cannot open INPUTMSG: $!");
        return;
    };
    my @msg = <$in>;
    close($in);

    my @sahdrs;
    push @sahdrs, "Return-Path: $Sender\n";
    push @sahdrs, split(/^/m, synthesize_received_header());
    if ($AddApparentlyToForSpamAssassin && @Recipients) {
        push @sahdrs, "Apparently-To: " . join(', ', @Recipients) . "\n";
    }
    unshift @msg, @sahdrs;
    my $msg = join('', @msg);

    my $length  = length($msg);
    my $request = join("\r\n",
        "CHECK SPAMC/1.5",
        "Content-length: $length",
        "User: $user",
        '',
        $msg,
    );

    my $out = $_ENGINE->_run_checks([{
        name => '_spamc_check',
        type => 'socket',
        args => {
            host       => $host,
            port       => $port,
            request    => $request,
            read_until => qr/\r\n\r\n/,
            max_bytes  => 65536,
            timeout    => $timeout,
        },
    }]);

    if ($out->{errors}{_spamc_check}) {
        md_syslog('err', "md_async_spamc_check: $out->{errors}{_spamc_check}");
        return;
    }

    my $raw = $out->{results}{_spamc_check} // '';

    my ($score, $threshold, $isspam) = (0, 5.0, 0);
    if ($raw =~ /(?:^|\r?\n)Spam:\s*(True|False|Yes|No)\s*;\s*([\d.]+)\s*\/\s*([\d.]+)/i) {
        my ($flag, $s, $t) = ($1, $2, $3);
        $isspam    = ($flag =~ /^(True|Yes)$/i) ? 1 : 0;
        $score     = $s + 0;
        $threshold = $t + 0;
    } else {
        md_syslog('warning', "md_async_spamc_check: unexpected spamd response");
        return;
    }

    my $report = '';
    if ($raw =~ /\r\n\r\n(.+)$/s) {
        $report = $1;
    }

    return ($score, $threshold, $report, $isspam ? 'true' : 'false');
}

=item md_async_spam_assassin_check()

Drop-in replacement for C<spam_assassin_check> from
L<Mail::MIMEDefang::Antispam>.

Runs SpamAssassin in-process (no spamd required), reading C<./INPUTMSG>.
Returns the same four-element list: C<($hits, $required_hits, $tests_list,
$full_report)>, or C<undef> when SpamAssassin is not installed or INPUTMSG
cannot be read.

For a network check against a running spamd, use C<md_async_spamc_check>
instead.

=cut

sub md_async_spam_assassin_check {
    croak "Call md_async_init() first" unless defined $_ENGINE;
    return spam_assassin_check();
}

=item md_async_rspamd_check($uri)

Async replacement for C<rspamd_check> from L<Mail::MIMEDefang::Antispam>.

POSTs the message to the Rspamd HTTP API at C<$uri/checkv2> using a raw
HTTP/1.0 request over an async TCP socket (no C<LWP::UserAgent> required).
Requires L<JSON::PP> (Perl core since 5.14) for response parsing.

C<$uri> defaults to C<http://127.0.0.1:11333>.

Returns the same six-element list as C<rspamd_check>:
C<($hits, $required_score, $tests, $report, $action, $is_spam)>,
or C<(0, 0, '', '', 'soft reject', 'false')> on connection failure.

=cut

sub md_async_rspamd_check {
    my ($uri) = @_;
    $uri //= 'http://127.0.0.1:11333';
    croak "Call md_async_init() first" unless defined $_ENGINE;

    eval { require JSON::PP };
    if ($@) {
        md_syslog('err', "md_async_rspamd_check: JSON::PP not available: $@");
        return;
    }

    open(my $fh, '<', './INPUTMSG') or do {
        md_syslog('err', "md_async_rspamd_check: cannot open INPUTMSG: $!");
        return;
    };
    local $/;
    my $mail = <$fh>;
    close($fh);

    # Parse host:port from URI
    my ($host, $port) = ('127.0.0.1', 11333);
    if ($uri =~ m{https?://([^/:]+)(?::(\d+))?}) {
        $host = $1;
        $port = $2 // 11333;
    }

    my $len     = length($mail);
    my $request = join("\r\n",
        "POST /checkv2 HTTP/1.0",
        "Host: $host:$port",
        "User-Agent: MIMEDefang",
        "Content-Type: text/plain",
        "Content-Length: $len",
        '',
        $mail,
    );

    # Use undef sentinel so the reader runs until EOF (HTTP/1.0 closes after response)
    my $out = $_ENGINE->_run_checks([{
        name => '_rspamd_check',
        type => 'socket',
        args => {
            host       => $host,
            port       => $port,
            request    => $request,
            read_until => qr/(?!)/,    # never matches - rely on on_eof
            max_bytes  => 131072,
            timeout    => 30,
        },
    }]);

    if ($out->{errors}{_rspamd_check}) {
        md_syslog('warning', "md_async_rspamd_check: $out->{errors}{_rspamd_check}");
        return (0, 0, '', '', 'soft reject', 'false');
    }

    my $raw = $out->{results}{_rspamd_check} // '';

    # Extract JSON body (after HTTP headers)
    my $json_body = '';
    if ($raw =~ /\r\n\r\n(.+)$/s) {
        $json_body = $1;
    } elsif ($raw =~ /\n\n(.+)$/s) {
        $json_body = $1;
    }

    unless ($json_body) {
        md_syslog('warning', "md_async_rspamd_check: empty response body");
        return (0, 0, '', '', 'soft reject', 'false');
    }

    my $res = eval { JSON::PP::decode_json($json_body) };
    if ($@ || ref($res) ne 'HASH') {
        md_syslog('warning', "md_async_rspamd_check: JSON parse error: $@");
        return (0, 0, '', '', 'soft reject', 'false');
    }

    my $hits   = $res->{score}          // 0;
    my $req    = $res->{required_score} // 0;
    my $action = $res->{action}         // '';
    my $tests  = '';

    if (ref($res->{symbols}) eq 'HASH') {
        my %sym = %{ $res->{symbols} };
        $tests = join(', ', map { "$sym{$_}{name} ($sym{$_}{score})" } keys %sym);
    }

    my $is_spam = ($hits >= $req) ? 'true' : 'false';

    return ($hits, $req, $tests, $json_body, $action, $is_spam);
}

=back

=head1 SYNOPSIS

  use Mail::MIMEDefang::Async;
  use Mail::MIMEDefang::Async::Checks qw(...);
  use Mail::MIMEDefang::Async::Results qw(...);

  md_async_init(max_concurrency => 8, global_timeout => 10);

  my $result = md_async_run_checks([
      md_async_check_dnsbl(ip => $client_ip, zone => 'zen.spamhaus.org'),
      md_async_check_rdns(ip => $client_ip),
  ]);

  # Drop-in replacements
  my $listed                    = md_async_relay_is_blacklisted($client_ip, 'zen.spamhaus.org');
  my $dmarc                     = md_async_dmarc_verify($sender_domain);
  my ($code, $cat, $act)        = md_async_message_contains_virus();
  my ($score, $thr, $rep, $spam) = md_async_spamc_check();
  my ($hits, $req, $sym, $rpt, $action, $spam) = md_async_rspamd_check();

=head1 SEE ALSO

L<Mail::MIMEDefang::Async::Checks>, L<Mail::MIMEDefang::Async::Results>,
L<Mail::MIMEDefang::Net>, L<Mail::MIMEDefang::SPF>

=cut

1;
