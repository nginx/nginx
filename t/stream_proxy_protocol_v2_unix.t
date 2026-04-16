#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 write with AF_UNIX downstream in stream proxy.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use IO::Socket::INET;
use IO::Socket::UNIX;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

# PPv2 magic signature (12 bytes)
my $SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

# Fixed header: 16 bytes.  Unix address block: 216 bytes.  Total: 232 bytes.
my $PPV2_HDR = 232;

my $t = Test::Nginx->new()->has(qw/stream/)->plan(7)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen          unix:%%TESTDIR%%/nginx.sock;
        proxy_pass      127.0.0.1:8080;
        proxy_protocol  on;
        proxy_protocol_version 2;
    }
}

EOF

$t->run_daemon(\&stream_daemon, port(8080));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8080));

###############################################################################

my $ngx_sock = $t->testdir() . '/nginx.sock';

my $s = IO::Socket::UNIX->new(Peer => $ngx_sock)
	or die "Can't connect to $ngx_sock: $!\n";

$s->syswrite('hello') or die "send: $!\n";

my $data = '';
my $sel  = IO::Select->new($s);
while ($sel->can_read(1)) {
	my $n = $s->sysread(my $chunk, 65536);
	last unless $n;
	$data .= $chunk;
}

my $src = substr($data, 16, 108);
$src =~ s/\x00.*//s;

my $dst = substr($data, 124, 108);
$dst =~ s/\x00.*//s;

is(substr($data, 0, 12), $SIG,                     'unix v2 signature');
is(unpack('C', substr($data, 12, 1)), 0x21,         'unix v2 version and command');
is(unpack('C', substr($data, 13, 1)), 0x31,         'unix v2 AF_UNIX STREAM');
is(unpack('n', substr($data, 14, 2)), 216,           'unix v2 addr block length');
is($src, '',                                         'unix v2 src addr (unbound)');
is($dst, $ngx_sock,                                  'unix v2 dst addr');
is(substr($data, $PPV2_HDR), 'hello',                'unix v2 payload after header');

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
