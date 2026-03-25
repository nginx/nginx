#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for RFC 5424 syslog message format.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new()->has(qw/http/)->plan(21);

###############################################################################

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

error_log syslog:server=127.0.0.1:%%PORT_8981_UDP%%,rfc=rfc5424 info;

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format logf "$uri:$status";

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        # RFC 5424 access log — basic format check
        location /a5424 {
            access_log syslog:server=127.0.0.1:%%PORT_8982_UDP%%,rfc=rfc5424
                       logf;
        }

        # RFC 5424 nohostname — HOSTNAME must be the nil value "-"
        location /nohostname5424 {
            access_log
                syslog:server=127.0.0.1:%%PORT_8982_UDP%%,rfc=rfc5424,nohostname
                logf;
        }

        # RFC 5424 error log with custom tag (hyphen) and facility
        location /e5424 {
            error_log
                syslog:server=127.0.0.1:%%PORT_8982_UDP%%,rfc=rfc5424,tag=my-app,facility=user;
        }

        # RFC 3164 access log — verify backward compatibility
        location /a3164 {
            access_log syslog:server=127.0.0.1:%%PORT_8983_UDP%% logf;
        }
    }
}

EOF

# Port 8981: background daemon that writes global error_log messages to a file.
# Port 8982: the test binds this socket directly after run().
# Port 8983: the test binds this socket directly after run().

$t->run_daemon(\&syslog_daemon, port(8981), $t, 's_glob.log');
$t->waitforfile($t->testdir() . '/s_glob.log');

$t->run();

###############################################################################

my $s5424 = IO::Socket::INET->new(
	Proto     => 'udp',
	LocalAddr => '127.0.0.1:' . port(8982)
) or die "Can't open syslog socket (8982): $!";

my $s3164 = IO::Socket::INET->new(
	Proto     => 'udp',
	LocalAddr => '127.0.0.1:' . port(8983)
) or die "Can't open syslog socket (8983): $!";

###############################################################################

# RFC 5424 access log — full field-by-field check

parse_rfc5424_message('access_log', get_syslog($s5424, '/a5424'));

# RFC 5424 with nohostname — HOSTNAME field must be nil "-"

my $msg = get_syslog($s5424, '/nohostname5424');
like($msg,
     qr/^<\d+>1\s          # PRI + VERSION
         \S+\s              # TIMESTAMP
         -\s                # HOSTNAME = nil "-"
         \S+\s              # APP-NAME
         \d+\s              # PROCID
         -\s-\s/x,
     'rfc5424 nohostname: HOSTNAME is nil "-"');

# RFC 5424 error log — custom hyphenated tag (only valid in rfc5424)

$msg = get_syslog($s5424, '/e5424');
like($msg, qr/my-app/, 'rfc5424: hyphenated tag present in APP-NAME');

# RFC 5424 facility=user must be encoded as facility 1 in PRI

my ($pri) = $msg =~ /^<(\d+)>/;
my $fac = ($pri & 0x03f8) >> 3;
is($fac, 1, 'rfc5424: facility=user (1) encoded in PRI');

# Global error_log uses rfc5424 — check via background-daemon log file

http_get('/a5424');

my $glob = '';
for (1 .. 50) {
	select undef, undef, undef, 0.1;
	$glob = $t->read_file('s_glob.log');
	last if $glob;
}
like($glob, qr/^<\d+>1\s/m, 'rfc5424 global error_log: VERSION "1" present');

# Millisecond field is live (ngx_timeofday()->msec, not once-per-second cache).
# Send several messages with small gaps and verify that the ms field is not
# permanently stuck at "000" as it would be with a second-boundary-only cache.

my @ms_vals;
for (1..10) {
	select undef, undef, undef, 0.02;    # 20 ms gap
	my $m = get_syslog($s5424, '/a5424');
	my ($ms_field) = $m =~ /T\d{2}:\d{2}:\d{2}\.(\d{3})/;
	push @ms_vals, $ms_field if defined $ms_field;
}
ok((grep { $_ ne '000' } @ms_vals) > 0,
   'rfc5424: millisecond field is not always zero (live ngx_timeofday)');

# RFC 3164 format is unchanged (backward compatibility)

$msg = get_syslog($s3164, '/a3164');
like($msg,
     qr/^<\d+>                        # PRI  (no VERSION field)
        [A-Z][a-z]{2}\s               # mon  (BSD syslog timestamp)
        [ \d]\d\s\d{2}:\d{2}:\d{2}\s  # day HH:MM:SS
        /x,
     'rfc3164: BSD syslog timestamp unchanged');
unlike($msg, qr/^<\d+>1\s/, 'rfc3164: no VERSION field');

###############################################################################

sub get_syslog {
	my ($sock, $uri) = @_;
	my $data = '';

	http_get($uri);

	IO::Select->new($sock)->can_read(1);
	while (IO::Select->new($sock)->can_read(0.1)) {
		my $buf;
		sysread($sock, $buf, 4096);
		$data .= $buf;
	}
	return $data;
}

# Validate that $line looks like a valid RFC 5424 message and run
# 14 individual Test::More assertions, one per protocol field.

sub parse_rfc5424_message {
	my ($desc, $line) = @_;

	unless ($line) {
		fail("$desc: no syslog message received");
		return;
	}

	# RFC 5424 SYSLOG-MSG:
	#   <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP
	#   PROCID SP MSGID SP STRUCTURED-DATA SP MSG

	my ($pri, $ts, $host, $app, $pid, $msgid, $sd, $msg) =
		$line =~ /^<(\d{1,3})>       # PRI
		           1\s               # VERSION (literal "1")
		           (\S+)\s           # TIMESTAMP
		           (\S+)\s           # HOSTNAME
		           (\S+)\s           # APP-NAME
		           (\S+)\s           # PROCID
		           (\S+)\s           # MSGID
		           (\S+)\s           # STRUCTURED-DATA
		           (.*)/x;           # MSG

	ok(defined($pri), "$desc: has PRI");

	my $sev = $pri & 0x07;
	my $fac = ($pri & 0x03f8) >> 3;
	ok($sev >= 0 && $sev <= 7, "$desc: severity in PRI is 0-7");
	ok($fac >= 0 && $fac < 24, "$desc: facility in PRI is 0-23");

	ok(defined($ts), "$desc: has TIMESTAMP");
	like($ts,
	     qr/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$/,
	     "$desc: TIMESTAMP is ISO 8601 with ms and tz offset");

	ok(defined($host), "$desc: has HOSTNAME");
	ok(length($host) > 0 && $host ne '-', "$desc: HOSTNAME is non-nil");

	ok(defined($app), "$desc: has APP-NAME");
	like($app, qr/^[!-~]+$/, "$desc: APP-NAME is printable US-ASCII");

	ok(defined($pid), "$desc: has PROCID");
	like($pid, qr/^\d+$/, "$desc: PROCID is a decimal integer");

	is($msgid, '-', "$desc: MSGID is nil");
	is($sd,    '-', "$desc: STRUCTURED-DATA is nil");

	ok(defined($msg) && length($msg) > 0, "$desc: MSG is non-empty");
}

###############################################################################

sub syslog_daemon {
	my ($port, $t, $file) = @_;

	my $s = IO::Socket::INET->new(
		Proto     => 'udp',
		LocalAddr => "127.0.0.1:$port"
	);

	open my $fh, '>', $t->testdir() . '/' . $file;
	select $fh; $| = 1;

	while (1) {
		my $buffer;
		$s->recv($buffer, 4096);
		print $fh $buffer . "\n";
	}
}

###############################################################################
