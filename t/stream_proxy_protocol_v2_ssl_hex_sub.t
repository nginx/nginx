#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for the ssl_0x<hex> SSL sub-TLV syntax in proxy_protocol_tlv.
# Verifies that an arbitrary SSL sub-TLV type can be specified with the
# "ssl_0x<hex>" prefix, which sets is_ssl_sub and folds the entry into
# the compound PP2_TYPE_SSL (0x20) TLV.

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

my $t = Test::Nginx->new()->has(qw/stream/)->plan(17)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # Server 1: ssl_0x21 is the hex form of ssl_version (type 0x21)
    server {
        listen          127.0.0.1:%%PORT_8080%%;
        proxy_pass      127.0.0.1:%%PORT_8082%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl_0x21 "TLSv1.3";
    }

    # Server 2: named ssl_version + custom ssl_0x26 sub-TLV
    server {
        listen          127.0.0.1:%%PORT_8081%%;
        proxy_pass      127.0.0.1:%%PORT_8082%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl_version "TLSv1.3";
        proxy_protocol_tlv ssl_0x26    "custom";
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8082));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8082));

###############################################################################

# Server 1: ssl_0x21 "TLSv1.3" (hex form of ssl_version)
#
# Fixed header (16) + IPv4 addr block (12) + outer 0x20 TLV (18) = 46 bytes
# header->len = 12 + 18 = 30
#
# outer 0x20 TLV value = client(1) + verify(4) + ssl_0x21 TLV(10) = 15 bytes
#   ssl_0x21 [36]: type 0x21, len 7, value "TLSv1.3"
# client byte = 0x01: PP2_CLIENT_SSL only; no ssl_cn so no CERT_SESS
# payload at offset 46

my $d1 = stream('127.0.0.1:' . port(8080))->io('hello');

is(unpack('n', substr($d1, 14, 2)), 30,   'hex_sub len field');
is(unpack('C', substr($d1, 28, 1)), 0x20, 'hex_sub outer type');
is(unpack('n', substr($d1, 29, 2)), 15,   'hex_sub outer length');
is(unpack('C', substr($d1, 31, 1)), 0x01, 'hex_sub client flags');
is(unpack('C', substr($d1, 36, 1)), 0x21, 'hex_sub sub-TLV type');
is(unpack('n', substr($d1, 37, 2)), 7,    'hex_sub sub-TLV length');
is(substr($d1, 39, 7),              'TLSv1.3', 'hex_sub sub-TLV value');
is(substr($d1, 46), 'hello', 'hex_sub payload after header');

# Server 2: ssl_version "TLSv1.3" + ssl_0x26 "custom"
#
# Fixed header (16) + IPv4 addr block (12) + outer 0x20 TLV (27) = 55 bytes
# header->len = 12 + 27 = 39
#
# outer 0x20 TLV value = client(1) + verify(4) + sub-TLVs(19) = 24 bytes
#   ssl_version [36]: type 0x21, len  7, value "TLSv1.3"
#   ssl_0x26    [46]: type 0x26, len  6, value "custom"
# client byte = 0x01: PP2_CLIENT_SSL only; no ssl_cn
# payload at offset 55

my $d2 = stream('127.0.0.1:' . port(8081))->io('hello');

is(unpack('n', substr($d2, 14, 2)), 39,   'mixed len field');
is(unpack('C', substr($d2, 28, 1)), 0x20, 'mixed outer type');
is(unpack('n', substr($d2, 29, 2)), 24,   'mixed outer length');
is(unpack('C', substr($d2, 31, 1)), 0x01, 'mixed client flags');
is(unpack('C', substr($d2, 36, 1)), 0x21, 'mixed ssl_version type');
is(unpack('C', substr($d2, 46, 1)), 0x26, 'mixed ssl_0x26 type');
is(unpack('n', substr($d2, 47, 2)), 6,    'mixed ssl_0x26 length');
is(substr($d2, 49, 6),              'custom', 'mixed ssl_0x26 value');
is(substr($d2, 55), 'hello', 'mixed payload after header');

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
