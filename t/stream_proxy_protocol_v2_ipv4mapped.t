#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 write with IPv4-mapped IPv6 downstream.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use IO::Socket::INET;
use Socket qw/ inet_aton /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# Verify that a dual-stack [::]:port socket with IPV6_V6ONLY=0 accepts
# an IPv4 client and presents its address as ::ffff:x.x.x.x.

eval { require IO::Socket::IP; };
plan(skip_all => 'IO::Socket::IP not installed') if $@;

eval {
    my $srv = IO::Socket::IP->new(
        LocalHost => '::',
        LocalPort => 0,
        Proto     => 'tcp',
        Listen    => 1,
        ReuseAddr => 1,
        V6Only    => 0,
    ) or die "bind: $!";
    my $port = $srv->sockport();
    IO::Socket::INET->new(
        Proto    => 'tcp',
        PeerAddr => "127.0.0.1:$port",
    ) or die "connect: $!";
    my $c = $srv->accept or die "accept: $!";
    $c->peerhost =~ /^::ffff:/i or die "not IPv4-mapped";
};
plan(skip_all => 'no IPv4-mapped IPv6 support') if $@;

# PPv2 magic signature (12 bytes)
my $SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

# Fixed header: 16 bytes.  IPv4 address block: 12 bytes.  Total: 28 bytes.
my $PPV2_HDR = 28;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(9)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen          [::]:%%PORT_8080%% ipv6only=off;
        proxy_pass      127.0.0.1:8081;
        proxy_protocol  on;
        proxy_protocol_version 2;
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8081));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my $dp = port(8080);
my $s  = stream('127.0.0.1:' . $dp);
my $sp = $s->sockport();
my $data = $s->io('hello');

is(substr($data, 0, 12), $SIG,                         'mapped v2 signature');
is(unpack('C', substr($data, 12, 1)), 0x21,             'mapped v2 version and command');
is(unpack('C', substr($data, 13, 1)), 0x11,             'mapped v2 AF_INET STREAM');
is(unpack('n', substr($data, 14, 2)), 12,               'mapped v2 addr block length');
is(substr($data, 16, 4), inet_aton('127.0.0.1'),        'mapped v2 src addr');
is(substr($data, 20, 4), inet_aton('127.0.0.1'),        'mapped v2 dst addr');
is(unpack('n', substr($data, 24, 2)), $sp,              'mapped v2 src port');
is(unpack('n', substr($data, 26, 2)), $dp,              'mapped v2 dst port');
is(substr($data, $PPV2_HDR), 'hello',                   'mapped v2 payload after header');

###############################################################################

sub stream_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalAddr => '127.0.0.1:' . $port,
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create listening socket: $!\n";

	my $sel = IO::Select->new($server);

	local $SIG{PIPE} = 'IGNORE';

	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if ($server == $fh) {
				my $new = $fh->accept;
				$new->autoflush(1);
				$sel->add($new);

			} elsif (stream_handle_client($fh)) {
				$sel->remove($fh);
				$fh->close;
			}
		}
	}
}

sub stream_handle_client {
	my ($client) = @_;

	log2c("(new connection $client)");

	my $buffer = '';
	my $csel   = IO::Select->new($client);
	while ($csel->can_read(0.5)) {
		my $n = $client->sysread(my $chunk, 65536);
		last unless $n;
		$buffer .= $chunk;
	}

	log2i("$client recv " . length($buffer) . " bytes");

	$client->syswrite($buffer);

	log2o("$client sent " . length($buffer) . " bytes");

	return 1;
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||',    @_); }

###############################################################################
