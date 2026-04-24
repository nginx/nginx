#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for the "ssl" named alias in proxy_protocol_tlv, which passes
# the PP2_TYPE_SSL (0x20) TLV body verbatim without nginx assembling it
# from individual ssl sub-TLV directives.

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

my $t = Test::Nginx->new()->has(qw/stream/)->plan(13)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # Server 1: ssl raw body only; emitted as 0x20 TLV verbatim
    server {
        listen          127.0.0.1:%%PORT_8080%%;
        proxy_pass      127.0.0.1:%%PORT_8082%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv ssl "rawssl";
    }

    # Server 2: authority TLV followed by ssl raw body
    server {
        listen          127.0.0.1:%%PORT_8081%%;
        proxy_pass      127.0.0.1:%%PORT_8082%%;
        proxy_protocol  on;
        proxy_protocol_version 2;
        proxy_protocol_tlv authority "example.com";
        proxy_protocol_tlv ssl       "rawssl";
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8082));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8082));

###############################################################################

# Server 1: ssl "rawssl" (6 bytes)
#
# Fixed header (16) + IPv4 addr block (12) + 0x20 TLV (9) = 37 bytes
# header->len = 12 + 9 = 21
#
# 0x20 TLV [28]: type 0x20, len 6, value "rawssl"
# payload at offset 37

my $d1 = stream('127.0.0.1:' . port(8080))->io('hello');

is(unpack('n', substr($d1, 14, 2)), 21,      'ssl_raw len field');
is(unpack('C', substr($d1, 28, 1)), 0x20,    'ssl_raw type');
is(unpack('n', substr($d1, 29, 2)), 6,       'ssl_raw length');
is(substr($d1, 31, 6),              'rawssl', 'ssl_raw value');
is(substr($d1, 37),                 'hello',  'ssl_raw payload after header');

# Server 2: authority "example.com" + ssl "rawssl"
#
# Fixed header (16) + IPv4 addr block (12)
#   + authority TLV (3 + 11 = 14) + ssl raw TLV (3 + 6 = 9) = 51 bytes
# header->len = 12 + 14 + 9 = 35
#
# authority [28]: type 0x02, len 11, value "example.com"
# ssl raw   [42]: type 0x20, len  6, value "rawssl"
# payload at offset 51

my $d2 = stream('127.0.0.1:' . port(8081))->io('hello');

is(unpack('n', substr($d2, 14, 2)), 35,          'ssl_raw_mix len field');
is(unpack('C', substr($d2, 28, 1)), 0x02,        'ssl_raw_mix authority type');
is(unpack('n', substr($d2, 29, 2)), 11,          'ssl_raw_mix authority length');
is(substr($d2, 31, 11),             'example.com', 'ssl_raw_mix authority value');
is(unpack('C', substr($d2, 42, 1)), 0x20,        'ssl_raw_mix ssl type');
is(unpack('n', substr($d2, 43, 2)), 6,           'ssl_raw_mix ssl length');
is(substr($d2, 45, 6),              'rawssl',    'ssl_raw_mix ssl value');
is(substr($d2, 51),                 'hello',     'ssl_raw_mix payload after header');

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
