#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 write on a dual-stack [::]:port server.
# An IPv4 client's address arrives as ::ffff:x.x.x.x (both src and dst
# v4mapped); nginx normalises and emits an AF_INET header.  A pure IPv6
# client produces addresses that are not v4mapped, so nginx emits AF_INET6.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use IO::Socket::INET;
use Socket qw/ inet_aton inet_pton AF_INET6 /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::IP; };
plan(skip_all => 'IO::Socket::IP not installed') if $@;

# Verify that a dual-stack [::]:port socket presents IPv4 clients as
# ::ffff:x.x.x.x.
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

# Verify IPv6 loopback is available.
eval {
    IO::Socket::IP->new(
        LocalHost => '::1',
        LocalPort => 0,
        Proto     => 'tcp',
        Listen    => 1,
    ) or die "$!";
};
plan(skip_all => 'no IPv6 loopback') if $@;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(16)
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

# IPv4 client connects to the dual-stack server.
# c->sockaddr and c->local_sockaddr are both ::ffff:127.0.0.1.
# Both are v4mapped; nginx emits AF_INET (0x11).
#
# Fixed header (16) + IPv4 block (12) = 28 bytes.

my $s4  = stream('127.0.0.1:' . $dp);
my $sp4 = $s4->sockport();
my $d4  = $s4->io('hello');

is(unpack('C', substr($d4, 12, 1)), 0x21,           'v4mapped cmd');
is(unpack('C', substr($d4, 13, 1)), 0x11,           'v4mapped AF_INET STREAM');
is(unpack('n', substr($d4, 14, 2)), 12,             'v4mapped addr block len');
is(substr($d4, 16, 4), inet_aton('127.0.0.1'),      'v4mapped src addr');
is(substr($d4, 20, 4), inet_aton('127.0.0.1'),      'v4mapped dst addr');
is(unpack('n', substr($d4, 24, 2)), $sp4,           'v4mapped src port');
is(unpack('n', substr($d4, 26, 2)), $dp,            'v4mapped dst port');
is(substr($d4, 28), 'hello',                        'v4mapped payload');

# IPv6 client connects to the same dual-stack server.
# c->sockaddr = ::1, c->local_sockaddr = ::1.
# Neither is v4mapped; nginx emits AF_INET6 (0x21).
#
# Fixed header (16) + IPv6 block (36) = 52 bytes.

my $s6 = IO::Socket::IP->new(
	Proto    => 'tcp',
	PeerHost => '::1',
	PeerPort => $dp,
) or die "Can't connect to nginx via IPv6: $!\n";
$s6->autoflush(1);

my $sp6 = $s6->sockport();
$s6->syswrite('world');

my $d6 = '';
my $sel = IO::Select->new($s6);
while ($sel->can_read(5)) {
	my $n = $s6->sysread(my $buf, 65536);
	last unless $n;
	$d6 .= $buf;
	last if length($d6) >= 57;
}
$s6->close();

is(unpack('C', substr($d6, 12, 1)), 0x21,                 'pure6 cmd');
is(unpack('C', substr($d6, 13, 1)), 0x21,                 'pure6 AF_INET6 STREAM');
is(unpack('n', substr($d6, 14, 2)), 36,                   'pure6 addr block len');
is(substr($d6, 16, 16), inet_pton(AF_INET6, '::1'),       'pure6 src addr');
is(substr($d6, 32, 16), inet_pton(AF_INET6, '::1'),       'pure6 dst addr');
is(unpack('n', substr($d6, 48, 2)), $sp6,                 'pure6 src port');
is(unpack('n', substr($d6, 50, 2)), $dp,                  'pure6 dst port');
is(substr($d6, 52), 'world',                              'pure6 payload');

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
