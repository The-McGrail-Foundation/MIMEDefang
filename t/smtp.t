package Mail::MIMEDefang::Unit::Smtp;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

sub _smtp_enabled {
	return (defined $ENV{'SMTP_TEST'} and $ENV{'SMTP_TEST'} eq 'yes');
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

__PACKAGE__->runtests();
