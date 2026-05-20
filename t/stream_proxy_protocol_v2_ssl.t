#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 write to SSL upstream in stream proxy.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ inet_aton /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;

my $t = Test::Nginx->new()->has(qw/stream stream_ssl/)->has_daemon('openssl')
	->plan(9);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    proxy_ssl on;

    server {
        listen          127.0.0.1:8080;
        proxy_pass      127.0.0.1:8081;
        proxy_protocol  on;
        proxy_protocol_version 2;
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}


# Fixed header: 16 bytes.  IPv4 address block: 12 bytes.  Total: 28 bytes.
my $PPV2_HDR = 28;

$t->run_daemon(\&stream_daemon_ssl, port(8081), path => $d);
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# PPv2 magic signature (12 bytes)
my $SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

my $dp = port(8080);
my $s  = stream('127.0.0.1:' . $dp);
my $sp = $s->sockport();
my $data = $s->io('hello');

is(substr($data, 0, 12), $SIG,                         'ssl v2 signature');
is(unpack('C', substr($data, 12, 1)), 0x21,             'ssl v2 version and command');
is(unpack('C', substr($data, 13, 1)), 0x11,             'ssl v2 AF_INET STREAM');
is(unpack('n', substr($data, 14, 2)), 12,               'ssl v2 addr block length');
is(substr($data, 16, 4), inet_aton('127.0.0.1'),        'ssl v2 src addr');
is(substr($data, 20, 4), inet_aton('127.0.0.1'),        'ssl v2 dst addr');
is(unpack('n', substr($data, 24, 2)), $sp,              'ssl v2 src port');
is(unpack('n', substr($data, 26, 2)), $dp,              'ssl v2 dst port');
is(substr($data, $PPV2_HDR), 'hello',                   'ssl v2 payload after header');

###############################################################################

sub stream_daemon_ssl {
	my ($port, %extra) = @_;
	my $d = $extra{path};

	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalHost => "127.0.0.1:$port",
		Listen    => 5,
		Reuse     => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		log2c("(new connection $client on $port)");

		# Read the PPv2 header sent over plain TCP before SSL.
		my $header = '';
		while (length($header) < $PPV2_HDR) {
			my $n = $client->sysread(my $buf, $PPV2_HDR - length($header));
			last unless $n;
			$header .= $buf;
		}

		log2i("$client header " . length($header) . " bytes");

		# Upgrade to SSL; fails silently on the waitforsocket probe.
		eval {
			IO::Socket::SSL->start_SSL($client,
				SSL_server       => 1,
				SSL_cert_file    => "$d/localhost.crt",
				SSL_key_file     => "$d/localhost.key",
				SSL_error_trap   => sub { die $_[1] }
			);
		};
		next if $@;

		$client->sysread(my $payload, 65536) or next;

		log2i("$client payload " . length($payload) . " bytes");

		my $response = $header . $payload;

		log2o("$client sending " . length($response) . " bytes");

		$client->syswrite($response);

		close $client;
	}
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||',    @_); }

###############################################################################
