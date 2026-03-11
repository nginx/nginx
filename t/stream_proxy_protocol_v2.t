#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 write to upstream in stream proxy.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use Socket qw/ inet_aton /;

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

    server {
        listen          127.0.0.1:8080;
        proxy_pass      127.0.0.1:8081;
        proxy_protocol  on;
        proxy_protocol_version 2;
    }

    server {
        listen          127.0.0.1:8082;
        proxy_pass      127.0.0.1:8081;
        proxy_protocol  on;
    }
}

EOF

$t->run_daemon(\&stream_daemon);
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

# PPv2 magic signature (12 bytes)
my $SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

# Fixed header: 16 bytes.  IPv4 address block: 12 bytes.  Total: 28 bytes.
my $PPV2_HDR = 28;

my $dp = port(8080);
my $s  = stream('127.0.0.1:' . $dp);
my $data = $s->io('hello');
my $sp = $s->sockport();

is(substr($data, 0, 12), $SIG,                         'v2 signature');
is(unpack('C', substr($data, 12, 1)), 0x21,             'v2 version and command');
is(unpack('C', substr($data, 13, 1)), 0x11,             'v2 AF_INET STREAM');
is(unpack('n', substr($data, 14, 2)), 12,               'v2 addr block length');
is(substr($data, 16, 4), inet_aton('127.0.0.1'),        'v2 src addr');
is(substr($data, 20, 4), inet_aton('127.0.0.1'),        'v2 dst addr');
is(unpack('n', substr($data, 24, 2)), $sp,              'v2 src port');
is(unpack('n', substr($data, 26, 2)), $dp,              'v2 dst port');
is(substr($data, $PPV2_HDR), 'hello',                   'v2 payload after header');

# version 1 is still the default when proxy_protocol_version is not set
like(stream('127.0.0.1:' . port(8082))->io('hello'),
	qr/^PROXY TCP4 /, 'v1 default');

###############################################################################

sub stream_daemon {
	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalAddr => '127.0.0.1:' . port(8081),
		Listen    => 5,
		Reuse     => 1
	)
		or die "Can't create listening socket: $!\n";

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

	$client->sysread(my $buffer, 65536) or return 1;

	log2i("$client recv " . length($buffer) . " bytes");

	$client->syswrite($buffer);

	log2o("$client sent " . length($buffer) . " bytes");

	return 1;
}

sub log2i { Test::Nginx::log_core('|| <<', @_); }
sub log2o { Test::Nginx::log_core('|| >>', @_); }
sub log2c { Test::Nginx::log_core('||',    @_); }

###############################################################################
