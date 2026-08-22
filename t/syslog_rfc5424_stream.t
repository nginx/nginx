#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for RFC 5424 syslog format in the stream access_log directive.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new()->has(qw/stream http/)->plan(15);

###############################################################################

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 ok;
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    log_format streamf "$remote_addr $protocol";

    server {
        listen      127.0.0.1:8081;
        proxy_pass  127.0.0.1:8080;
        access_log  syslog:server=127.0.0.1:%%PORT_8982_UDP%%,rfc=rfc5424
                    streamf;
    }

    server {
        listen      127.0.0.1:8082;
        proxy_pass  127.0.0.1:8080;
        access_log  syslog:server=127.0.0.1:%%PORT_8982_UDP%%,rfc=rfc5424,nohostname
                    streamf;
    }
}

EOF

$t->run();

###############################################################################

my $s5424 = IO::Socket::INET->new(
	Proto     => 'udp',
	LocalAddr => '127.0.0.1:' . port(8982)
) or die "Can't open syslog socket: $!";

# RFC 5424 stream access log — full field-by-field check

stream('127.0.0.1:' . port(8081))->read();
parse_rfc5424_message('stream access_log', get_syslog_raw($s5424));

# RFC 5424 stream with nohostname

stream('127.0.0.1:' . port(8082))->read();
my $msg = get_syslog_raw($s5424);
like($msg,
     qr/^<\d+>1\s          # PRI + VERSION
         \S+\s              # TIMESTAMP
         -\s                # HOSTNAME = nil "-"
         \S+\s              # APP-NAME
         \d+\s              # PROCID
         -\s-\s/x,
     'stream rfc5424 nohostname: HOSTNAME is nil "-"');

###############################################################################

sub get_syslog_raw {
	my ($sock) = @_;
	my $data = '';

	IO::Select->new($sock)->can_read(2);
	while (IO::Select->new($sock)->can_read(0.1)) {
		my $buf;
		sysread($sock, $buf, 4096);
		$data .= $buf;
	}
	return $data;
}

# Validate all RFC 5424 header fields; runs 14 assertions.

sub parse_rfc5424_message {
	my ($desc, $line) = @_;

	unless ($line) {
		fail("$desc: no syslog message received");
		return;
	}

	my ($pri, $ts, $host, $app, $pid, $msgid, $sd, $msg) =
		$line =~ /^<(\d{1,3})>       # PRI
		           1\s               # VERSION
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
