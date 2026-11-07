package Mail::MIMEDefang::Unit::Smtp;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;
use File::Copy qw(copy);

sub _smtp_enabled {
	return (defined $ENV{'SMTP_TEST'} and $ENV{'SMTP_TEST'} eq 'yes');
}

# Path to the multiplexor control socket (override via MX_SOCK env var).
sub _mx_sock {
	return $ENV{'MX_SOCK'} // '/var/spool/MIMEDefang/mimedefang-multiplexor.sock';
}

my $FILTER = '/etc/mail/mimedefang-filter';
my $BACKUP = "$FILTER.smtp-t.bak";

# Install a filter file and tell the multiplexor to reload it.
# The current filter is saved once, so _restore_filter can put it back.
# Returns true on success.
sub _install_filter {
	my ($src) = @_;
	if (! -e $BACKUP) {
		copy($FILTER, $BACKUP) or do {
			diag("Cannot back up $FILTER to $BACKUP: $!");
			return 0;
		};
	}
	return _load_filter($src);
}

# Put back the filter saved by _install_filter.
sub _restore_filter {
	return 0 unless -e $BACKUP;
	_load_filter($BACKUP) or return 0;
	unlink $BACKUP;
	return 1;
}

sub _load_filter {
	my ($src) = @_;
	copy($src, $FILTER) or do {
		diag("Cannot copy $src to $FILTER: $!");
		return 0;
	};
	my $sock = _mx_sock();
	my $rc = system('md-mx-ctrl', '-s', $sock, 'reread');
	if ($rc != 0) {
		diag("md-mx-ctrl reread failed (exit $rc); filter may not have reloaded");
	}
	sleep 2; # give workers a moment to reload
	return 1;
}

sub t0_smtp_basic : Test(1)
{
	SKIP: {
		skip "Smtp test disabled", 1 unless _smtp_enabled();
		my $ret = Mail::MIMEDefang::Unit::smtp_mail('defang', 'defang', 't/data/multipart.eml');
		unlike($ret, qr/[45]\.\d+\.\d+ /, 'clean multipart message accepted without errors');
	};
}

sub t1_smtp_gtube : Test(1)
{
	SKIP: {
		skip "Smtp test disabled", 1 unless _smtp_enabled();
		my $ret = Mail::MIMEDefang::Unit::smtp_mail('defang', 'defang', 't/data/gtube.eml');
		like($ret, qr/[45]\.\d+\.\d+ /, 'GTUBE message rejected or tempfailed');
	};
}

sub t2_smtp_exe : Test(2)
{
	SKIP: {
		skip "Smtp test disabled", 2 unless _smtp_enabled();
		my $ret = Mail::MIMEDefang::Unit::smtp_mail('defang', 'defang', 't/data/exe.eml');
		sleep 5;
		unlike($ret, qr/[45]\.\d+\.\d+ /, 'exe message delivered with attachment stripped');
		my $warning = 0;
		if (open(my $fh, '<', '/var/spool/mail/defang')) {
			while (my $line = <$fh>) {
				$warning = 1 if $line =~ /An attachment named test\.exe was removed/;
			}
			close $fh;
		}
		is($warning, 1, 'exe attachment removal warning present in delivered mail');
	};
}

# Async filter tests

sub t3_smtp_async_basic : Test(2)
{
	SKIP: {
		skip "Smtp test disabled", 2 unless _smtp_enabled();

		my $installed = _install_filter('t/data/mimedefang-async-filter');
		skip "Could not install async filter", 2 unless $installed;

		my $ret = Mail::MIMEDefang::Unit::smtp_mail('defang', 'defang', 't/data/multipart.eml');
		unlike($ret, qr/[45]\.\d+\.\d+ /, 'async filter: clean message accepted');

		ok(-e $BACKUP, "async filter: original filter saved");
	};
}

sub t4_smtp_async_gtube : Test(2)
{
	SKIP: {
		skip "Smtp test disabled", 2 unless _smtp_enabled();

		my $ret = Mail::MIMEDefang::Unit::smtp_mail('defang', 'defang', 't/data/gtube.eml');
		like($ret, qr/[45]\.\d+\.\d+ /, 'async filter: GTUBE rejected or tempfailed');

		ok(_restore_filter(), "async filter: original filter restored after gtube test");
	};
}

__PACKAGE__->runtests();
