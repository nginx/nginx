#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 IPv6 upstream write in stream proxy.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use Socket qw/ inet_pton AF_INET6 /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::IP; };
plan(skip_all => 'IO::Socket::IP not installed') if $@;

# Verify IPv6 loopback is available on this system.
eval {
	IO::Socket::IP->new(
		LocalHost => '::1',
		LocalPort => 0,
		Proto     => 'tcp',
		Listen    => 1,
	) or die "$!";
};
plan(skip_all => 'no IPv6 loopback') if $@;

# PPv2 magic signature (12 bytes)
my $SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

# Fixed header: 16 bytes.  IPv6 address block: 36 bytes.  Total: 52 bytes.
my $PPV2_HDR = 52;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(9)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen          [::1]:%%PORT_8083%%;
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

my $dp = port(8083);

my $s = IO::Socket::IP->new(
	Proto    => 'tcp',
	PeerHost => '::1',
	PeerPort => $dp,
) or die "Can't connect to nginx: $!\n";
$s->autoflush(1);

my $sp = $s->sockport();

$s->syswrite('hello');

my $data = '';
my $sel  = IO::Select->new($s);
while ($sel->can_read(5)) {
	my $n = $s->sysread(my $buf, 65536);
	last unless $n;
	$data .= $buf;
	last if length($data) >= $PPV2_HDR + 5;
}

is(substr($data, 0, 12), $SIG,                              'ipv6 v2 signature');
is(unpack('C', substr($data, 12, 1)), 0x21,                  'ipv6 v2 version and command');
is(unpack('C', substr($data, 13, 1)), 0x21,                  'ipv6 v2 AF_INET6 STREAM');
is(unpack('n', substr($data, 14, 2)), 36,                    'ipv6 v2 addr block length');
is(substr($data, 16, 16), inet_pton(AF_INET6, '::1'),        'ipv6 v2 src addr');
is(substr($data, 32, 16), inet_pton(AF_INET6, '::1'),        'ipv6 v2 dst addr');
is(unpack('n', substr($data, 48, 2)), $sp,                   'ipv6 v2 src port');
is(unpack('n', substr($data, 50, 2)), $dp,                   'ipv6 v2 dst port');
is(substr($data, $PPV2_HDR), 'hello',                        'ipv6 v2 payload after header');

###############################################################################

sub stream_daemon {
	my ($port_num) = @_;

	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalAddr => '127.0.0.1:' . $port_num,
		Listen    => 5,
		Reuse     => 1
	)
		or die "Can't create listening socket: $!\n";

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
	my $csel = IO::Select->new($client);
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
