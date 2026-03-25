#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for "rfc=" parameter of the syslog directive.
# Uses "nginx -t" config-check mode; no server is started.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new();

###############################################################################

# Write a minimal nginx.conf containing $syslog_param as a global error_log
# directive and run "nginx -t" against it.  Returns combined stdout+stderr.

sub config_check {
	my ($syslog_param) = @_;

	$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

error_log $syslog_param info;

daemon off;

events {
}

EOF

	my $testdir = $t->testdir();
	return qx{$Test::Nginx::NGINX -t -p $testdir/ -c nginx.conf 2>&1};
}

###############################################################################

my $out;

# rfc=rfc3164 is the default and must be accepted explicitly.

$out = config_check('syslog:server=127.0.0.1:5140,rfc=rfc3164');
like($out, qr/test is successful/i, 'rfc=rfc3164 accepted');

# rfc=rfc5424 must be accepted.

$out = config_check('syslog:server=127.0.0.1:5140,rfc=rfc5424');
like($out, qr/test is successful/i, 'rfc=rfc5424 accepted');

# An unknown rfc= value must be rejected with a descriptive error.

$out = config_check('syslog:server=127.0.0.1:5140,rfc=rfc9999');
like($out, qr/unknown syslog "rfc" value/, 'rfc=rfc9999 rejected');

# A hyphenated tag is printable ASCII and must be accepted with rfc5424.

$out = config_check('syslog:server=127.0.0.1:5140,rfc=rfc5424,tag=my-app');
like($out, qr/test is successful/i, 'rfc5424: hyphenated tag accepted');

# The same hyphenated tag must be rejected with rfc3164.

$out = config_check('syslog:server=127.0.0.1:5140,rfc=rfc3164,tag=my-app');
like($out, qr/only allows alphanumeric/, 'rfc3164: hyphenated tag rejected');

# A tag with a dot is printable ASCII and must be accepted with rfc5424.

$out = config_check('syslog:server=127.0.0.1:5140,rfc=rfc5424,tag=nginx.1');
like($out, qr/test is successful/i, 'rfc5424: dot in tag accepted');

# A 33-character tag is within the rfc5424 limit (48) and must be accepted.

my $tag33 = 'a' x 33;
$out = config_check("syslog:server=127.0.0.1:5140,rfc=rfc5424,tag=$tag33");
like($out, qr/test is successful/i, 'rfc5424: 33-char tag accepted');

# The same 33-character tag exceeds the rfc3164 limit (32) and must fail.

$out = config_check("syslog:server=127.0.0.1:5140,rfc=rfc3164,tag=$tag33");
like($out, qr/tag length exceeds 32/, 'rfc3164: 33-char tag rejected');

# A 49-character tag exceeds the maximum of both protocol versions (48).

my $tag49 = 'a' x 49;
$out = config_check("syslog:server=127.0.0.1:5140,rfc=rfc5424,tag=$tag49");
like($out, qr/tag length exceeds 48/, 'rfc5424: 49-char tag rejected');

$out = config_check("syslog:server=127.0.0.1:5140,rfc=rfc3164,tag=$tag49");
like($out, qr/tag length exceeds 48/, 'rfc3164: 49-char tag rejected');

done_testing;

###############################################################################
