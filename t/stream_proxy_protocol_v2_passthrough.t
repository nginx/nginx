#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for proxy_protocol_passthrough directive in the stream proxy module.
# An upstream stream_return backend echoes received TLV values as text,
# allowing the test to verify what nginx forwarded.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(13)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # Backend: echoes authority, unique_id, custom TLV, ALPN values.
    server {
        listen      127.0.0.1:%%PORT_8090%% proxy_protocol;
        return      "auth:$proxy_protocol_tlv_authority
uid:$proxy_protocol_tlv_unique_id
cust:$proxy_protocol_tlv_0xae
alpn:$proxy_protocol_tlv_alpn
";
    }

    # S1: passthrough specific types.  Only authority and unique_id are
    # forwarded; ALPN and custom 0xae must be absent.
    server {
        listen      127.0.0.1:%%PORT_8081%% proxy_protocol;
        proxy_pass  127.0.0.1:%%PORT_8090%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
        proxy_protocol_passthrough authority unique_id;
    }

    # S2: passthrough all — forwards every incoming type except CRC32c.
    server {
        listen      127.0.0.1:%%PORT_8082%% proxy_protocol;
        proxy_pass  127.0.0.1:%%PORT_8090%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
        proxy_protocol_passthrough all;
    }

    # S3: suppression beats passthrough.  AUTHORITY is in the passthrough
    # list but is suppressed by proxy_protocol_tlv authority "".
    server {
        listen      127.0.0.1:%%PORT_8083%% proxy_protocol;
        proxy_pass  127.0.0.1:%%PORT_8090%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
        proxy_protocol_passthrough authority unique_id;
        proxy_protocol_tlv authority "";
    }

    # S4: explicit value beats passthrough.
    server {
        listen      127.0.0.1:%%PORT_8084%% proxy_protocol;
        proxy_pass  127.0.0.1:%%PORT_8090%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
        proxy_protocol_passthrough authority;
        proxy_protocol_tlv authority "override.example";
    }

    # S5: no incoming PP v2 header — passthrough silently skips.
    server {
        listen      127.0.0.1:%%PORT_8085%%;
        proxy_pass  127.0.0.1:%%PORT_8090%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
        proxy_protocol_passthrough all;
    }
}

EOF

$t->run();
$t->waitforsocket('127.0.0.1:' . port(8085));

###############################################################################

# Helpers to build a raw PP v2 packet.

sub pp2_tlv {
    my ($type, $value) = @_;
    return pack('Cn', $type, length($value)) . $value;
}

sub pp2_header {
    my ($tlvs) = @_;
    my $sig  = "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a";
    my $addr = pack('NNnn', 0xc0000201, 0xc0000202, 1000, 8081);
    return $sig . "\x21\x11" . pack('n', 12 + length($tlvs)) . $addr . $tlvs;
}

###############################################################################

# Build incoming TLVs: authority, unique_id, ALPN, and custom 0xae.
my $incoming = pp2_tlv(0x02, 'from-upstream.example')
             . pp2_tlv(0x05, 'req-id-001')
             . pp2_tlv(0x01, 'h2')
             . pp2_tlv(0xae, 'vendor-data');

my $pkt = pp2_header($incoming);

# --- 1. Specific type passthrough ---

my $r = stream('127.0.0.1:' . port(8081))->io($pkt);

like($r, qr/auth:from-upstream\.example/, 'specific: authority forwarded');
like($r, qr/uid:req-id-001/,              'specific: unique_id forwarded');
unlike($r, qr/alpn:h2/,                   'specific: ALPN not forwarded');
unlike($r, qr/cust:vendor-data/,           'specific: 0xae not forwarded');

# --- 2. All mode ---

$r = stream('127.0.0.1:' . port(8082))->io($pkt);

like($r, qr/auth:from-upstream\.example/, 'all: authority forwarded');
like($r, qr/uid:req-id-001/,              'all: unique_id forwarded');
like($r, qr/alpn:h2/,                     'all: ALPN forwarded');
like($r, qr/cust:vendor-data/,             'all: custom 0xae forwarded');

# --- 3. Suppression beats passthrough ---

$r = stream('127.0.0.1:' . port(8083))->io($pkt);

unlike($r, qr/auth:\S/,         'suppress: AUTHORITY absent');
like($r, qr/uid:req-id-001/,    'suppress: unique_id still forwarded');

# --- 4. Explicit value beats passthrough ---

$r = stream('127.0.0.1:' . port(8084))->io($pkt);

like($r, qr/auth:override\.example/, 'explicit: override value used');
unlike($r, qr/from-upstream/,         'explicit: incoming value not used');

# --- 5. No incoming PP v2 header (plain TCP downstream) ---

$r = stream('127.0.0.1:' . port(8085))->io('');

unlike($r, qr/auth:\S|uid:\S|alpn:\S/, 'no-pp: passthrough silent-skips');

###############################################################################
