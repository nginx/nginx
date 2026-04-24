#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests that PROXY protocol version 1 is rejected for UDP connections.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

port(8080, udp => 1);
port(8081, udp => 1);

my $t = Test::Nginx->new()->has(qw/stream/)->plan(2)
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
        # proxy_protocol_version defaults to 1
    }
}

EOF

$t->run_daemon(\&udp_daemon, port(8081));
$t->run();

###############################################################################

my $s = IO::Socket::INET->new(
	Proto    => 'udp',
	PeerAddr => '127.0.0.1:' . port(8080),
) or die "Can't create UDP socket: $!\n";

$s->send('hello') or die "send: $!\n";

my @ready = IO::Select->new($s)->can_read(2);
is(scalar @ready, 0, 'udp v1 no response');

$t->stop();

like($t->read_file('error.log'),
	qr/PROXY protocol version 1 is not supported for UDP/,
	'udp v1 error logged');

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
		$server->send($buf, 0, $peer);
	}
}

###############################################################################
