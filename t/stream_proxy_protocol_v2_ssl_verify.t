#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for the ssl_verify pseudo-type in proxy_protocol_tlv.

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

my $t = Test::Nginx->new()->has(qw/stream/)->plan(18)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # Server 1: ssl_verify with ssl sub-TLVs; verify field = 42
    server {
        listen          127.0.0.1:%%PORT_8080%%;
        proxy_pass      127.0.0.1:%%PORT_8082%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl_verify  "42";
        proxy_protocol_tlv ssl_version "TLSv1.3";
        proxy_protocol_tlv ssl_cn      "example.com";
    }

    # Server 2: ssl_verify alone (no ssl sub-TLVs); minimal PP2_TYPE_SSL TLV
    server {
        listen          127.0.0.1:%%PORT_8081%%;
        proxy_pass      127.0.0.1:%%PORT_8082%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl_verify "0";
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8082));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8082));

###############################################################################

# Server 1: ssl_verify "42" + ssl_version "TLSv1.3" + ssl_cn "example.com"
#
# Fixed header (16) + IPv4 addr block (12) + outer 0x20 TLV (32) = 60 bytes
# header->len = 12 + 32 = 44
#
# outer 0x20 TLV value = client(1) + verify(4) + sub-TLVs(24) = 29 bytes
#   verify field = 42 = 0x0000002A (big-endian)
#   ssl_version [36]: type 0x21, len  7, value "TLSv1.3"
#   ssl_cn      [46]: type 0x22, len 11, value "example.com"
# payload at offset 60

my $d1 = stream('127.0.0.1:' . port(8080))->io('hello');

is(unpack('n', substr($d1, 14, 2)), 44,   'ssl_verify len field');
is(unpack('C', substr($d1, 28, 1)), 0x20, 'ssl_verify outer type');
is(unpack('n', substr($d1, 29, 2)), 29,   'ssl_verify outer length');
is(unpack('C', substr($d1, 31, 1)), 0x01, 'ssl_verify client flags');
is(unpack('N', substr($d1, 32, 4)), 42,   'ssl_verify verify field');

is(unpack('C', substr($d1, 36, 1)), 0x21,     'ssl_verify ssl_version type');
is(unpack('n', substr($d1, 37, 2)), 7,         'ssl_verify ssl_version length');
is(substr($d1, 39, 7),              'TLSv1.3', 'ssl_verify ssl_version value');

is(unpack('C', substr($d1, 46, 1)), 0x22,          'ssl_verify ssl_cn type');
is(unpack('n', substr($d1, 47, 2)), 11,             'ssl_verify ssl_cn length');
is(substr($d1, 49, 11),             'example.com', 'ssl_verify ssl_cn value');

is(substr($d1, 60), 'hello', 'ssl_verify payload after header');

# Server 2: ssl_verify "0" alone, no ssl sub-TLVs
#
# Fixed header (16) + IPv4 addr block (12) + outer 0x20 TLV (8) = 36 bytes
# header->len = 12 + 8 = 20
#
# outer 0x20 TLV value = client(1) + verify(4) = 5 bytes (no sub-TLVs)
#   verify field = 0 = 0x00000000
# payload at offset 36

my $d2 = stream('127.0.0.1:' . port(8081))->io('hello');

is(unpack('n', substr($d2, 14, 2)), 20,   'ssl_verify_only len field');
is(unpack('C', substr($d2, 28, 1)), 0x20, 'ssl_verify_only outer type');
is(unpack('n', substr($d2, 29, 2)), 5,    'ssl_verify_only outer length');
is(unpack('C', substr($d2, 31, 1)), 0x01, 'ssl_verify_only client flags');
is(unpack('N', substr($d2, 32, 4)), 0,    'ssl_verify_only verify field');

is(substr($d2, 36), 'hello', 'ssl_verify_only payload after header');

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
