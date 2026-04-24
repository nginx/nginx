#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PP2_CLIENT_CERT_SESS flag in the PP2_TYPE_SSL client byte.
# PP2_CLIENT_SSL      (0x01) is always set when any ssl sub-TLV is present.
# PP2_CLIENT_CERT_SESS (0x04) is set when the ssl_cn sub-TLV is configured.
# PP2_CLIENT_CERT_CONN (0x02) requires a TLS downstream connection; tested
# separately in the SSL test suite.

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

my $t = Test::Nginx->new()->has(qw/stream/)->plan(14)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # Server 1: ssl sub-TLV without ssl_cn
    # client byte must be PP2_CLIENT_SSL (0x01) only
    server {
        listen          127.0.0.1:%%PORT_8080%%;
        proxy_pass      127.0.0.1:%%PORT_8082%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl_version "TLSv1.3";
    }

    # Server 2: ssl sub-TLVs including ssl_cn
    # client byte must be PP2_CLIENT_SSL|PP2_CLIENT_CERT_SESS (0x05)
    server {
        listen          127.0.0.1:%%PORT_8081%%;
        proxy_pass      127.0.0.1:%%PORT_8082%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl_version "TLSv1.3";
        proxy_protocol_tlv ssl_cn      "example.com";
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8082));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8082));

###############################################################################

# Server 1: ssl_version only, no ssl_cn
#
# Fixed header (16) + IPv4 addr block (12) + outer 0x20 TLV (18) = 46 bytes
# header->len = 12 + 18 = 30
#
# outer 0x20 TLV value = client(1) + verify(4) + ssl_version TLV(10) = 15 bytes
# client byte = 0x01: PP2_CLIENT_SSL only; ssl_cn absent so no CERT_SESS
#   ssl_version [36]: type 0x21, len 7, value "TLSv1.3"
# payload at offset 46

my $d1 = stream('127.0.0.1:' . port(8080))->io('hello');

is(unpack('n', substr($d1, 14, 2)), 30,   'no_cn len field');
is(unpack('C', substr($d1, 28, 1)), 0x20, 'no_cn outer type');
is(unpack('n', substr($d1, 29, 2)), 15,   'no_cn outer length');
is(unpack('C', substr($d1, 31, 1)), 0x01, 'no_cn client flags');
is(unpack('C', substr($d1, 36, 1)), 0x21, 'no_cn ssl_version type');
is(substr($d1, 46), 'hello', 'no_cn payload after header');

# Server 2: ssl_version + ssl_cn
#
# Fixed header (16) + IPv4 addr block (12) + outer 0x20 TLV (32) = 60 bytes
# header->len = 12 + 32 = 44
#
# outer 0x20 TLV value = client(1) + verify(4) + sub-TLVs(24) = 29 bytes
# client byte = 0x05: PP2_CLIENT_SSL|PP2_CLIENT_CERT_SESS (ssl_cn is set)
#   ssl_version [36]: type 0x21, len  7, value "TLSv1.3"
#   ssl_cn      [46]: type 0x22, len 11, value "example.com"
# payload at offset 60

my $d2 = stream('127.0.0.1:' . port(8081))->io('hello');

is(unpack('n', substr($d2, 14, 2)), 44,   'with_cn len field');
is(unpack('C', substr($d2, 28, 1)), 0x20, 'with_cn outer type');
is(unpack('n', substr($d2, 29, 2)), 29,   'with_cn outer length');
is(unpack('C', substr($d2, 31, 1)), 0x05, 'with_cn client flags');
is(unpack('C', substr($d2, 36, 1)), 0x21, 'with_cn ssl_version type');
is(unpack('C', substr($d2, 46, 1)), 0x22, 'with_cn ssl_cn type');
is(substr($d2, 49, 11),             'example.com', 'with_cn ssl_cn value');
is(substr($d2, 60), 'hello', 'with_cn payload after header');

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
