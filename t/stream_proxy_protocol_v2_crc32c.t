#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for proxy_protocol_crc32c directive in stream proxy.

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

my $t = Test::Nginx->new()->has(qw/stream/)->plan(13)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # Server 1: CRC32c only, no user TLVs
    server {
        listen          127.0.0.1:%%PORT_8080%%;
        proxy_pass      127.0.0.1:%%PORT_8081%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_crc32c  on;
    }

    # Server 2: user TLV followed by CRC32c
    server {
        listen          127.0.0.1:%%PORT_8082%%;
        proxy_pass      127.0.0.1:%%PORT_8081%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv     0x05 "hi";
        proxy_protocol_crc32c  on;
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8081));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# Server 1: CRC32c TLV only
# Fixed header (16) + IPv4 addr block (12) + CRC TLV (7) = 35 bytes
# header->len = 12 + 7 = 19
# CRC TLV: byte[28]=0x03, bytes[29-30]=4, bytes[31-34]=checksum

my $data1 = stream('127.0.0.1:' . port(8080))->io('hello');

is(unpack('n', substr($data1, 14, 2)), 19,   'crc32c len field');
is(unpack('C', substr($data1, 28, 1)), 0x03, 'crc32c tlv type');
is(unpack('n', substr($data1, 29, 2)), 4,    'crc32c tlv length');

{
    # Recompute with the checksum field zeroed; must match what nginx wrote
    my $hdr = substr($data1, 0, 35);
    substr($hdr, 31, 4) = "\x00\x00\x00\x00";
    is(unpack('N', substr($data1, 31, 4)), crc32c($hdr),
       'crc32c value correct');
}

is(substr($data1, 35), 'hello', 'crc32c payload after header');

# Server 2: TLV 0x05 "hi" (5 bytes) + CRC32c TLV (7 bytes)
# Fixed header (16) + IPv4 addr block (12) + TLV1 (5) + CRC TLV (7) = 40 bytes
# header->len = 12 + 5 + 7 = 24
# TLV1:    byte[28]=0x05, bytes[29-30]=2, bytes[31-32]="hi"
# CRC TLV: byte[33]=0x03, bytes[34-35]=4, bytes[36-39]=checksum

my $data2 = stream('127.0.0.1:' . port(8082))->io('hello');

is(unpack('n', substr($data2, 14, 2)), 24,   'crc32c+tlv len field');
is(unpack('C', substr($data2, 28, 1)), 0x05, 'crc32c+tlv tlv1 type');
is(unpack('n', substr($data2, 29, 2)), 2,    'crc32c+tlv tlv1 length');
is(substr($data2, 31, 2),              'hi', 'crc32c+tlv tlv1 value');
is(unpack('C', substr($data2, 33, 1)), 0x03, 'crc32c+tlv crc type');
is(unpack('n', substr($data2, 34, 2)), 4,    'crc32c+tlv crc length');

{
    my $hdr = substr($data2, 0, 40);
    substr($hdr, 36, 4) = "\x00\x00\x00\x00";
    is(unpack('N', substr($data2, 36, 4)), crc32c($hdr),
       'crc32c+tlv value correct');
}

is(substr($data2, 40), 'hello', 'crc32c+tlv payload after header');

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
