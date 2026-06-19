package Mail::MIMEDefang::Unit::BIMI;
use strict;
use warnings;
use lib qw(modules/lib);
use base qw(Mail::MIMEDefang::Unit);
use Test::Most;

use Mail::MIMEDefang;
use Mail::MIMEDefang::BIMI;
use MIME::Parser;

init_globals;
Mail::MIMEDefang::BIMI::md_init();
$Features{"Net::DNS"} = 1;

sub t_bimi_verify_no_dmarc : Test(1)
{
  # DMARC policy "none" must cause BIMI to fail
  my $res = md_bimi_verify('example.com', 'pass', 'none');
  is($res, 'fail', 'BIMI fails when DMARC policy is none');
}

sub t_bimi_verify_fail_dmarc : Test(1)
{
  # DMARC result "fail" must cause BIMI to fail regardless of policy
  my $res = md_bimi_verify('example.com', 'fail', 'reject');
  is($res, 'fail', 'BIMI fails when DMARC result is fail');
}

sub t_bimi_verify_missing_params : Test(3)
{
  is(md_bimi_verify(undef, 'pass', 'reject'), 'fail', 'BIMI fails with undefined domain');
  is(md_bimi_verify('example.com', undef, 'reject'), 'fail', 'BIMI fails with undefined dmarc_result');
  is(md_bimi_verify('example.com', 'pass', undef), 'fail', 'BIMI fails with undefined dmarc_policy');
}

sub t_bimi_lookup_invalid : Test(1)
{
  # A domain that has no BIMI record should return undef
  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 1;
    }
    my $rec = md_bimi_lookup('invalid-domain-that-cannot-have-bimi.example');
    is($rec, undef, 'md_bimi_lookup returns undef for unknown domain');
  };
}

sub t_bimi_lookup_live : Test(3)
{
  SKIP: {
    if ( (not defined $ENV{'NET_TEST'}) or ($ENV{'NET_TEST'} ne 'yes' )) {
      skip "Net test disabled", 3;
    }
    # valimail.com publishes a BIMI record
    my $rec = md_bimi_lookup('valimail.com');
    if (!defined $rec) {
      skip "valimail.com BIMI record not found (may have changed)", 3;
    }
    is($rec->{version}, 'BIMI1', 'BIMI record version is BIMI1');
    ok(defined $rec->{l} && $rec->{l} ne '', 'BIMI record has a logo URL');
    ok(defined $rec->{raw}, 'BIMI record has raw TXT string');
  };
}

sub t_bimi_get_selector_present : Test(1)
{
  # t/data/dkim1.eml contains: BIMI-Selector: v=BIMI1; s=brand1;
  my $parser = MIME::Parser->new;
  $parser->output_to_core(1);
  my $entity = $parser->parse_open('t/data/dkim1.eml');
  is(md_bimi_get_selector($entity), 'brand1',
     'md_bimi_get_selector returns selector from BIMI-Selector header');
}

sub t_bimi_get_selector_absent : Test(1)
{
  my $parser = MIME::Parser->new;
  $parser->output_to_core(1);
  my $entity = $parser->parse_open('t/data/uri.eml');
  is(md_bimi_get_selector($entity), 'default',
     'md_bimi_get_selector returns default when header is absent');
}

sub t_bimi_get_selector_undef : Test(1)
{
  is(md_bimi_get_selector(undef), 'default',
     'md_bimi_get_selector returns default for undef entity');
}

sub t_bimi_lookup_invalid_selector : Test(1)
{
  my $rec = md_bimi_lookup('example.com', '../evil');
  ok(!defined($rec) || ref($rec) eq 'HASH',
     'md_bimi_lookup survives an invalid selector string');
}

sub t_bimi_mail_bimi_module : Test(1)
{
  SKIP: {
    skip "Mail::BIMI not installed", 1 unless $Features{"Mail::BIMI"};
    # DMARC pre-condition check fires before Mail::BIMI is consulted
    my $res = md_bimi_verify('example.com', 'pass', 'none');
    is($res, 'fail', 'Mail::BIMI path: BIMI fails when DMARC policy is none');
  };
}

__PACKAGE__->runtests();
