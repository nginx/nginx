#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for proxy_protocol_tlv directive in stream proxy.

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

# PPv2 magic signature (12 bytes)
my $SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

# Fixed header 16 + IPv4 addr block 12 = 28
# TLV1: type(1) + len(2) + "foo"(3)  =  6 bytes  [offset 28]
# TLV2: type(1) + len(2) + "bar"(3)  =  6 bytes  [offset 34]
# TLV3: type(1) + len(2) + addr(9)   = 12 bytes  [offset 40]
# payload at offset 52
my $PPV2_HDR = 52;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(14)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen          127.0.0.1:%%PORT_8080%%;
        proxy_pass      127.0.0.1:%%PORT_8081%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv     0x05 "foo";
        proxy_protocol_tlv     0x06 "bar";
        proxy_protocol_tlv     0x07 $remote_addr;
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8081));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my $s    = stream('127.0.0.1:' . port(8080));
my $data = $s->io('hello');

is(substr($data, 0, 12),              $SIG,  'tlv v2 signature');
is(unpack('C', substr($data, 12, 1)), 0x21,  'tlv v2 version and command');
is(unpack('C', substr($data, 13, 1)), 0x11,  'tlv v2 AF_INET STREAM');

# header->len: 12-byte addr block + 6 + 6 + 12 bytes of TLVs = 36
is(unpack('n', substr($data, 14, 2)), 36,    'tlv v2 len includes TLVs');

# TLV1 at offset 28: type 0x05, length 3, value "foo"
is(unpack('C', substr($data, 28, 1)), 0x05,  'tlv1 type');
is(unpack('n', substr($data, 29, 2)), 3,     'tlv1 length');
is(substr($data, 31, 3),              'foo', 'tlv1 value');

# TLV2 at offset 34: type 0x06, length 3, value "bar"
is(unpack('C', substr($data, 34, 1)), 0x06,  'tlv2 type');
is(unpack('n', substr($data, 35, 2)), 3,     'tlv2 length');
is(substr($data, 37, 3),              'bar', 'tlv2 value');

# TLV3 at offset 40: type 0x07, variable $remote_addr = "127.0.0.1" (9 bytes)
is(unpack('C', substr($data, 40, 1)), 0x07,       'tlv3 type');
is(unpack('n', substr($data, 41, 2)), 9,           'tlv3 length');
is(substr($data, 43, 9),              '127.0.0.1', 'tlv3 value (remote_addr)');

is(substr($data, $PPV2_HDR), 'hello', 'payload after TLVs');

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
