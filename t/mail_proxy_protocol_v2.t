#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for proxy_protocol_version 2 in the mail proxy module.
# The backend daemon captures the PP v2 header nginx sends, then completes
# the IMAP LOGIN handshake nginx performs with it, so nginx sends the forged
# login-ok to the client.  The test reads the captured header from a temp
# file and verifies the PP v2 structure.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/mail imap/)->plan(6)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http  127.0.0.1:%%PORT_8080%%;

    server {
        listen          127.0.0.1:%%PORT_8143%%;
        protocol        imap;
        proxy           on;
        proxy_protocol  on;
        proxy_protocol_version  2;
    }
}

EOF

my $tmpfile = $t->testdir() . '/pp2.bin';

$t->run_daemon(\&auth_daemon,    port(8080), port(8144));
$t->run_daemon(\&imap_backend,   port(8144), $tmpfile);
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8080));
$t->waitforsocket('127.0.0.1:' . port(8143));
$t->waitforsocket('127.0.0.1:' . port(8144));

###############################################################################

my $sock = IO::Socket::INET->new(
	Proto    => 'tcp',
	PeerAddr => '127.0.0.1:' . port(8143),
) or die "Cannot connect to nginx: $!\n";
$sock->autoflush(1);

readline_sock($sock);                   # nginx IMAP banner
$sock->syswrite("1 LOGIN user pass\r\n");
readline_sock($sock);                   # forged login-ok forwarded by nginx

$sock->close();

# Read the PP v2 header captured by the backend daemon

my $pp = '';
if (-f $tmpfile) {
	open(my $fh, '<', $tmpfile) or die "Cannot open $tmpfile: $!";
	binmode $fh;
	local $/;
	$pp = <$fh>;
	close $fh;
}

# PP v2 fixed header layout:
#   [0..11]  signature "\r\n\r\n\0\r\nQUIT\n"
#   [12]     version_command = 0x21 (version 2, PROXY command)
#   [13]     family_transport = 0x11 (AF_INET + SOCK_STREAM)
#   [14..15] len = 12  (IPv4 addr block only, no TLVs)
#   [16..19] src_addr  (client -> nginx)
#   [20..23] dst_addr  (nginx listen addr = 127.0.0.1)
#   [24..25] src_port
#   [26..27] dst_port  (nginx IMAP listen port)

ok(length($pp) >= 28,                           'mail pp2 header received');
is(substr($pp, 0, 12), "\r\n\r\n\0\r\nQUIT\n", 'mail pp2 signature');
is(unpack('C', substr($pp, 12, 1)), 0x21,       'mail pp2 version_command');
is(unpack('C', substr($pp, 13, 1)), 0x11,       'mail pp2 family_transport');
is(unpack('n', substr($pp, 14, 2)), 12,         'mail pp2 addr_len');
is(substr($pp, 20, 4), "\x7f\x00\x00\x01",     'mail pp2 dst_addr');

###############################################################################

sub readline_sock {
	my ($sock) = @_;
	my $line = '';
	my $sel = IO::Select->new($sock);
	while ($sel->can_read(5)) {
		my $n = $sock->sysread(my $ch, 1);
		last unless $n;
		$line .= $ch;
		last if $ch eq "\n";
	}
	return $line;
}


sub auth_daemon {
	my ($port, $backend_port) = @_;

	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalAddr => '127.0.0.1:' . $port,
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create auth socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $buf = '';
		my $sel = IO::Select->new($client);
		while ($sel->can_read(1)) {
			my $n = $client->sysread(my $chunk, 4096);
			last unless $n;
			$buf .= $chunk;
			last if $buf =~ /\r\n\r\n/;
		}

		$client->syswrite(
			"HTTP/1.0 200 OK\r\n"
			. "Auth-Status: OK\r\n"
			. "Auth-Server: 127.0.0.1\r\n"
			. "Auth-Port: $backend_port\r\n"
			. "\r\n"
		);

		close $client;
	}
}


sub imap_backend {
	my ($port, $tmpfile) = @_;

	my $server = IO::Socket::INET->new(
		Proto     => 'tcp',
		LocalAddr => '127.0.0.1:' . $port,
		Listen    => 5,
		Reuse     => 1,
	) or die "Can't create IMAP backend socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);
		binmode $client;
		my $sel = IO::Select->new($client);

		# Nginx sends the PP v2 header immediately on connect, before our
		# greeting.  Collect it with a short read timeout.
		my $pp = '';
		while ($sel->can_read(0.5)) {
			my $n = $client->sysread(my $buf, 4096);
			last unless $n;
			$pp .= $buf;
		}

		# Persist the PP header for the test to verify
		if (open(my $fh, '>', $tmpfile)) {
			binmode $fh;
			print $fh $pp;
			close $fh;
		}

		# Send a valid IMAP greeting so nginx accepts this backend
		$client->syswrite("* OK nginx IMAP4 ready\r\n");

		# Complete the IMAP LOGIN handshake nginx performs with the backend.
		# Nginx uses the IMAP literal mechanism:
		#   nginx sends: TAG LOGIN {login_len}\r\n
		#   we respond:  + ok\r\n
		#   nginx sends: login {passwd_len}\r\n
		#   we respond:  + ok\r\n
		#   nginx sends: passwd\r\n
		#   we respond:  TAG OK Logged in\r\n
		#
		# The tag nginx uses is the client's original IMAP tag including the
		# trailing space (e.g. "1 "), so the final response starts with it.

		my $cmd = daemon_readline($client, $sel);   # TAG LOGIN {len}\r\n
		my ($tag) = ($cmd =~ /^(\S+ )/);
		$tag //= '';
		$client->syswrite("+ ok\r\n");

		daemon_readline($client, $sel);             # login {len}\r\n
		$client->syswrite("+ ok\r\n");

		daemon_readline($client, $sel);             # passwd\r\n
		$client->syswrite("${tag}OK Logged in\r\n");

		$sel->can_read(1);
		close $client;
	}
}


sub daemon_readline {
	my ($client, $sel) = @_;
	my $line = '';
	while ($sel->can_read(5)) {
		my $n = $client->sysread(my $ch, 1);
		last unless $n;
		$line .= $ch;
		last if $ch eq "\n";
	}
	return $line;
}

###############################################################################
