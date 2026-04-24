#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 write to UDP upstream in stream proxy.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use Socket qw/ inet_aton /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# PPv2 magic signature (12 bytes)
my $SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

# Fixed header: 16 bytes.  IPv4 address block: 12 bytes.  Total: 28 bytes.
my $PPV2_HDR = 28;

# Prime the port cache with TCP locks before write_file_expand processes
# 127.0.0.1:8080 and 127.0.0.1:8081 via its auto-substitution regex.
# The default port() holds a UDP lock which would conflict with nginx's
# "listen udp" directive and the daemon's UDP socket.
port(8080, udp => 1);
port(8081, udp => 1);

my $t = Test::Nginx->new()->has(qw/stream/)->plan(9)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen          127.0.0.1:8080 udp;
        proxy_pass      127.0.0.1:8081;
        proxy_protocol  on;
        proxy_protocol_version 2;
    }
}

EOF

$t->run_daemon(\&udp_daemon, port(8081));
$t->run();

###############################################################################

my $dp = port(8080);

my $s = IO::Socket::INET->new(
	Proto    => 'udp',
	PeerAddr => "127.0.0.1:$dp",
) or die "Can't create UDP socket: $!\n";

$s->send('hello') or die "send: $!\n";

my $data = '';
my $sel  = IO::Select->new($s);
if ($sel->can_read(5)) {
	$s->recv($data, 65536);
}

my $sp = $s->sockport();

is(substr($data, 0, 12), $SIG,                          'udp v2 signature');
is(unpack('C', substr($data, 12, 1)), 0x21,              'udp v2 version and command');
is(unpack('C', substr($data, 13, 1)), 0x12,              'udp v2 AF_INET DGRAM');
is(unpack('n', substr($data, 14, 2)), 12,                'udp v2 addr block length');
is(substr($data, 16, 4), inet_aton('127.0.0.1'),         'udp v2 src addr');
is(substr($data, 20, 4), inet_aton('127.0.0.1'),         'udp v2 dst addr');
is(unpack('n', substr($data, 24, 2)), $sp,               'udp v2 src port');
is(unpack('n', substr($data, 26, 2)), $dp,               'udp v2 dst port');
is(substr($data, $PPV2_HDR), 'hello',                    'udp v2 payload after header');

###############################################################################

sub udp_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto     => 'udp',
		LocalAddr => "127.0.0.1:$port",
		Reuse     => 1,
	) or die "Can't create listening UDP socket: $!\n";

	while (1) {
		my $buf  = '';
		my $peer = $server->recv($buf, 65536);
		next unless defined $peer;

		log2i("recv " . length($buf) . " bytes");

		$server->send($buf, 0, $peer);

		log2o("sent " . length($buf) . " bytes");
	}
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||',    @_); }

###############################################################################
