#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 TLV variable passthrough and end-to-end
# readability.  An nginx backend using stream_return reads the forwarded
# PP v2 header through $proxy_protocol_tlv_* variables, exercising the
# full write/parse round-trip.  Three scenarios are covered:
#
#   1. Variable passthrough: incoming TLV values re-emitted upstream via
#      $proxy_protocol_tlv_* variables.
#   2. SSL TLV body passthrough: the raw $proxy_protocol_tlv_ssl blob
#      forwarded as a proxy_protocol_tlv ssl value.
#   3. Ordering: ssl sub-TLV directives configured before regular TLVs.

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

my $t = Test::Nginx->new()->has(qw/stream/)->plan(10)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # Backend A: echoes basic TLV values.
    server {
        listen      127.0.0.1:%%PORT_8090%% proxy_protocol;
        return      "alpn:$proxy_protocol_tlv_alpn
auth:$proxy_protocol_tlv_authority
uid:$proxy_protocol_tlv_unique_id
cust:$proxy_protocol_tlv_0xae
";
    }

    # Backend B: echoes SSL and regular TLV values.
    server {
        listen      127.0.0.1:%%PORT_8091%% proxy_protocol;
        return      "alpn:$proxy_protocol_tlv_alpn
auth:$proxy_protocol_tlv_authority
ssl_ver:$proxy_protocol_tlv_ssl_version
ssl_cn:$proxy_protocol_tlv_ssl_cn
";
    }

    # Server 1: variable passthrough — forward incoming TLVs upstream
    # via $proxy_protocol_tlv_* variables.
    server {
        listen      127.0.0.1:%%PORT_8081%% proxy_protocol;
        proxy_pass  127.0.0.1:%%PORT_8090%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
        proxy_protocol_tlv  alpn       $proxy_protocol_tlv_alpn;
        proxy_protocol_tlv  authority  $proxy_protocol_tlv_authority;
        proxy_protocol_tlv  unique_id  $proxy_protocol_tlv_unique_id;
        proxy_protocol_tlv  0xae       $proxy_protocol_tlv_0xae;
    }

    # Server 2: SSL TLV body passthrough — the raw $proxy_protocol_tlv_ssl
    # blob forwarded verbatim as proxy_protocol_tlv ssl.
    server {
        listen      127.0.0.1:%%PORT_8082%% proxy_protocol;
        proxy_pass  127.0.0.1:%%PORT_8091%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
        proxy_protocol_tlv  ssl  $proxy_protocol_tlv_ssl;
    }

    # Server 3: ordering test — SSL sub-TLV directives appear before
    # regular TLV directives in the configuration.
    server {
        listen      127.0.0.1:%%PORT_8083%%;
        proxy_pass  127.0.0.1:%%PORT_8091%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
        proxy_protocol_tlv  ssl_version  "TLSv1.3";
        proxy_protocol_tlv  ssl_cn       "test.example.com";
        proxy_protocol_tlv  alpn         "h2";
        proxy_protocol_tlv  authority    "example.com";
    }
}

EOF

$t->run();
$t->waitforsocket('127.0.0.1:' . port(8083));

###############################################################################

# Helpers to build a raw PP v2 packet.

sub pp2_tlv {
    my ($type, $value) = @_;
    return pack('Cn', $type, length($value)) . $value;
}

sub pp2_ssl_body {
    my ($client, $verify, $subtlvs) = @_;
    return pack('CN', $client, $verify) . $subtlvs;
}

sub pp2_header {
    my ($tlvs) = @_;
    my $sig  = "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a";
    my $addr = pack('NNnn', 0xc0000201, 0xc0000202, 1000, 8081);
    return $sig . "\x21\x11" . pack('n', 12 + length($tlvs)) . $addr . $tlvs;
}

###############################################################################

# 1. Variable passthrough — basic named TLVs.
#
# Send PP v2 to relay server 1 carrying alpn, authority, unique_id, and a
# custom 0xae TLV.  The relay reads their values via $proxy_protocol_tlv_*
# variables and re-emits them to backend A, which echoes them as text.

{
    my $tlvs = pp2_tlv(0x01, 'HTTP/1.1')
             . pp2_tlv(0x02, 'example.com')
             . pp2_tlv(0x05, 'uid001')
             . pp2_tlv(0xae, 'myval');

    my $r = stream('127.0.0.1:' . port(8081))->io(pp2_header($tlvs));

    like($r, qr/alpn:HTTP\/1\.1/,  'passthrough alpn');
    like($r, qr/auth:example\.com/, 'passthrough authority');
    like($r, qr/uid:uid001/,        'passthrough unique_id');
    like($r, qr/cust:myval/,        'passthrough custom 0xae');
}

# 2. SSL TLV body passthrough.
#
# Send PP v2 carrying a PP2_TYPE_SSL TLV with version and cn sub-TLVs to
# relay server 2.  The relay reads $proxy_protocol_tlv_ssl (the raw 0x20
# body) and forwards it verbatim via "proxy_protocol_tlv ssl".  Backend B
# then parses the forwarded SSL TLV via its own $proxy_protocol_tlv_ssl_*
# variables and echoes the values.

{
    my $sub  = pp2_tlv(0x21, 'TLSv1.2') . pp2_tlv(0x22, 'test.com');
    my $ssl  = pp2_ssl_body(0x01, 0, $sub);
    my $tlvs = pp2_tlv(0x20, $ssl);

    my $r = stream('127.0.0.1:' . port(8082))->io(pp2_header($tlvs));

    like($r, qr/ssl_ver:TLSv1\.2/, 'passthrough ssl_version');
    like($r, qr/ssl_cn:test\.com/, 'passthrough ssl_cn');
}

# 3. TLV ordering — ssl sub-TLV directives before regular TLV directives.
#
# Server 3 is configured with ssl_version and ssl_cn first, then alpn and
# authority.  Verify that the assembled PP v2 header is parseable and all
# four values are visible to backend B.

{
    my $r = stream('127.0.0.1:' . port(8083))->io('');

    like($r, qr/ssl_ver:TLSv1\.3/,          'ordered ssl_version');
    like($r, qr/ssl_cn:test\.example\.com/,  'ordered ssl_cn');
    like($r, qr/alpn:h2/,                    'ordered alpn');
    like($r, qr/auth:example\.com/,          'ordered authority');
}

###############################################################################
