#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 auto-fill in the mail proxy module.
# A downstream SSL IMAP listener produces an upstream PP v2 header whose
# TLVs are auto-populated from the SSL session (SSL TLV with version and
# cipher sub-TLVs, AUTHORITY from SNI).  The auto-fill works through the
# unified write entry point without any mail-module code changes.

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

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;

my $t = Test::Nginx->new()->has(qw/mail imap mail_ssl/)->has_daemon('openssl')
	->plan(7);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http  127.0.0.1:%%PORT_8080%%;

    ssl_certificate     localhost.crt;
    ssl_certificate_key localhost.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    server {
        listen                  127.0.0.1:%%PORT_8143%% ssl;
        protocol                imap;
        proxy                   on;
        proxy_protocol          on;
        proxy_protocol_version  2;
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

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate: $!\n";

my $tmpfile = $d . '/pp2.bin';

$t->run_daemon(\&auth_daemon,  port(8080), port(8144));
$t->run_daemon(\&imap_backend, port(8144), $tmpfile);
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8080));
$t->waitforsocket('127.0.0.1:' . port(8143));
$t->waitforsocket('127.0.0.1:' . port(8144));

###############################################################################

my $sock = IO::Socket::SSL->new(
	PeerHost        => '127.0.0.1',
	PeerPort        => port(8143),
	SSL_hostname    => 'example.com',
	SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
) or die "SSL connect failed: $!,$IO::Socket::SSL::SSL_ERROR";

$sock->autoflush(1);

readline_sock($sock);              # nginx IMAP banner
$sock->syswrite("1 LOGIN user pass\r\n");
readline_sock($sock);              # forged login-ok

$sock->close();

# Read the PP v2 header captured by the backend daemon.
my $pp = '';
if (-f $tmpfile) {
	open(my $fh, '<', $tmpfile) or die "Cannot open $tmpfile: $!";
	binmode $fh;
	local $/;
	$pp = <$fh>;
	close $fh;
}

ok(length($pp) >= 28, 'mail-auto pp header received');

my $addr_len = unpack('n', substr($pp, 14, 2));
cmp_ok($addr_len, '>', 12, 'mail-auto header length > addr block');

my $tlvs = parse_tlvs(substr($pp, 28, $addr_len - 12));

is($tlvs->{0x02}, 'example.com',  'mail-auto AUTHORITY from SNI');
ok(defined($tlvs->{0x20}),         'mail-auto SSL TLV present');

my $ssl_body = $tlvs->{0x20};
my $sub      = parse_tlvs(substr($ssl_body, 5));

ok(defined($sub->{0x21}),           'mail-auto ssl_version present');
like($sub->{0x21}, qr/^TLSv1\.[23]$/, 'mail-auto ssl_version value');
ok(defined($sub->{0x23}),           'mail-auto ssl_cipher present');

###############################################################################

sub parse_tlvs {
	my ($buf) = @_;
	my %tlvs;
	my $off = 0;
	while ($off + 3 <= length($buf)) {
		my $type = unpack('C', substr($buf, $off, 1));
		my $len  = unpack('n', substr($buf, $off + 1, 2));
		last if $off + 3 + $len > length($buf);
		$tlvs{$type} = substr($buf, $off + 3, $len);
		$off += 3 + $len;
	}
	return \%tlvs;
}

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

		my $pp = '';
		while ($sel->can_read(0.5)) {
			my $n = $client->sysread(my $buf, 4096);
			last unless $n;
			$pp .= $buf;
		}

		if (open(my $fh, '>', $tmpfile)) {
			binmode $fh;
			print $fh $pp;
			close $fh;
		}

		$client->syswrite("* OK nginx IMAP4 ready\r\n");

		my $cmd = daemon_readline($client, $sel);
		my ($tag) = ($cmd =~ /^(\S+ )/);
		$tag //= '';
		$client->syswrite("+ ok\r\n");

		daemon_readline($client, $sel);
		$client->syswrite("+ ok\r\n");

		daemon_readline($client, $sel);
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
