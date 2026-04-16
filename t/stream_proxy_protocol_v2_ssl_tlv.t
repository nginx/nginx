#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for proxy_protocol_tlv named aliases (ssl_*, authority, unique_id)
# in stream proxy.

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

# CRC32c (Castagnoli) lookup table and compute function.
# Polynomial (reflected): 0x82F63B78

my @crc32c_table;
{
    my $poly = 0x82F63B78;
    for my $i (0..255) {
        my $crc = $i;
        for (1..8) {
            $crc = ($crc & 1)
                 ? ((($crc >> 1) ^ $poly) & 0xFFFFFFFF)
                 :  (($crc >> 1)          & 0xFFFFFFFF);
        }
        $crc32c_table[$i] = $crc;
    }
}

sub crc32c {
    my ($data) = @_;
    my $crc = 0xFFFFFFFF;
    for my $byte (unpack('C*', $data)) {
        $crc = ($crc32c_table[($crc ^ $byte) & 0xFF]
                ^ ($crc >> 8)) & 0xFFFFFFFF;
    }
    return ($crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
}

my $t = Test::Nginx->new()->has(qw/stream/)->plan(28)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # Server 1: three ssl sub-TLVs assembled into a PP2_TYPE_SSL (0x20) TLV
    server {
        listen          127.0.0.1:%%PORT_8080%%;
        proxy_pass      127.0.0.1:%%PORT_8083%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl_version "TLSv1.3";
        proxy_protocol_tlv ssl_cipher  "TLS_AES_256_GCM_SHA384";
        proxy_protocol_tlv ssl_cn      "example.com";
    }

    # Server 2: same ssl sub-TLVs followed by a CRC32c TLV
    server {
        listen          127.0.0.1:%%PORT_8081%%;
        proxy_pass      127.0.0.1:%%PORT_8083%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl_version "TLSv1.3";
        proxy_protocol_tlv ssl_cipher  "TLS_AES_256_GCM_SHA384";
        proxy_protocol_tlv ssl_cn      "example.com";
        proxy_protocol_crc32c on;
    }

    # Server 3: simple named aliases (authority 0x02, unique_id 0x05)
    server {
        listen          127.0.0.1:%%PORT_8082%%;
        proxy_pass      127.0.0.1:%%PORT_8083%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv authority "example.com";
        proxy_protocol_tlv unique_id "req123";
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8083));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8083));

###############################################################################

# Server 1: compound PP2_TYPE_SSL (0x20) TLV
#
# Fixed header (16) + IPv4 addr block (12) + outer 0x20 TLV (57) = 85 bytes
# header->len = 12 + 57 = 69
#
# outer 0x20 TLV value = client(1) + verify(4) + sub-TLVs(49) = 54 bytes
# sub-TLV layout (offsets from start of PROXY header):
#   ssl_version [36]: type 0x21, len  7, value "TLSv1.3"
#   ssl_cipher  [46]: type 0x23, len 22, value "TLS_AES_256_GCM_SHA384"
#   ssl_cn      [71]: type 0x22, len 11, value "example.com"
# client byte = PP2_CLIENT_SSL|PP2_CLIENT_CERT_SESS = 0x05 (ssl_cn is set)
# payload at offset 85

my $d1 = stream('127.0.0.1:' . port(8080))->io('hello');

is(unpack('n', substr($d1, 14, 2)), 69,   'ssl_tlv len field');
is(unpack('C', substr($d1, 28, 1)), 0x20, 'ssl_tlv outer type');
is(unpack('n', substr($d1, 29, 2)), 54,   'ssl_tlv outer length');
is(unpack('C', substr($d1, 31, 1)), 0x05, 'ssl_tlv client flags');
is(unpack('N', substr($d1, 32, 4)), 0xFFFFFFFF, 'ssl_tlv verify');

is(unpack('C', substr($d1, 36, 1)), 0x21,           'ssl_version type');
is(unpack('n', substr($d1, 37, 2)), 7,               'ssl_version length');
is(substr($d1, 39, 7),              'TLSv1.3',       'ssl_version value');

is(unpack('C', substr($d1, 46, 1)), 0x23,                   'ssl_cipher type');
is(unpack('n', substr($d1, 47, 2)), 22,                     'ssl_cipher length');
is(substr($d1, 49, 22),             'TLS_AES_256_GCM_SHA384', 'ssl_cipher value');

is(unpack('C', substr($d1, 71, 1)), 0x22,          'ssl_cn type');
is(unpack('n', substr($d1, 72, 2)), 11,             'ssl_cn length');
is(substr($d1, 74, 11),             'example.com', 'ssl_cn value');

is(substr($d1, 85), 'hello', 'ssl_tlv payload after header');

# Server 2: same ssl sub-TLVs + CRC32c TLV
#
# header->len = 69 + 7 = 76
# CRC TLV at offset 85: type 0x03, length 4, checksum at [88..91]
# payload at offset 92

my $d2 = stream('127.0.0.1:' . port(8081))->io('hello');

is(unpack('n', substr($d2, 14, 2)), 76,   'ssl+crc len field');
is(unpack('C', substr($d2, 85, 1)), 0x03, 'ssl+crc crc type');
is(unpack('n', substr($d2, 86, 2)), 4,    'ssl+crc crc length');

{
    my $hdr = substr($d2, 0, 92);
    substr($hdr, 88, 4) = "\x00\x00\x00\x00";
    is(unpack('N', substr($d2, 88, 4)), crc32c($hdr),
       'ssl+crc value correct');
}

is(substr($d2, 92), 'hello', 'ssl+crc payload after header');

# Server 3: authority (0x02) + unique_id (0x05) named aliases
#
# Fixed header (16) + IPv4 addr block (12)
#   + authority TLV (3 + 11 = 14) + unique_id TLV (3 + 6 = 9) = 51 bytes
# header->len = 12 + 14 + 9 = 35
# authority [28]: type 0x02, len 11, value "example.com"
# unique_id [42]: type 0x05, len  6, value "req123"
# payload at offset 51

my $d3 = stream('127.0.0.1:' . port(8082))->io('hello');

is(unpack('n', substr($d3, 14, 2)), 35,   'aliases len field');
is(unpack('C', substr($d3, 28, 1)), 0x02, 'authority type');
is(unpack('n', substr($d3, 29, 2)), 11,   'authority length');
is(substr($d3, 31, 11),             'example.com', 'authority value');
is(unpack('C', substr($d3, 42, 1)), 0x05, 'unique_id type');
is(unpack('n', substr($d3, 43, 2)), 6,    'unique_id length');
is(substr($d3, 45, 6),              'req123', 'unique_id value');
is(substr($d3, 51), 'hello', 'aliases payload after header');

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
