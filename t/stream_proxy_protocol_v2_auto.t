#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 auto-fill from downstream SSL session.
# When `proxy_protocol_version 2` is set and the downstream is SSL, the
# upstream PP v2 header carries auto-populated PP2_TYPE_SSL (with
# sub-TLVs ssl_version, ssl_cipher), PP2_TYPE_ALPN, and PP2_TYPE_AUTHORITY.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;
use IO::Socket::INET;
use Socket qw/ inet_aton /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;

my $t = Test::Nginx->new()->has(qw/stream stream_ssl/)->has_daemon('openssl')
	->plan(14);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    # SSL downstream listener: auto-fill should populate SSL TLV, ALPN,
    # AUTHORITY.
    server {
        listen                  127.0.0.1:%%PORT_8080%%  ssl;
        ssl_certificate         localhost.crt;
        ssl_certificate_key     localhost.key;
        ssl_protocols           TLSv1.2 TLSv1.3;
        ssl_alpn                h2 http/1.1;
        proxy_pass              127.0.0.1:%%PORT_8082%%;
        proxy_protocol          on;
        proxy_protocol_version  2;
    }

    # Non-SSL downstream listener: auto-fill silently skips, no TLVs.
    server {
        listen                  127.0.0.1:%%PORT_8081%%;
        proxy_pass              127.0.0.1:%%PORT_8082%%;
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

$t->run_daemon(\&stream_daemon, port(8082));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8082));

###############################################################################

my $SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

# ---- Case 1: SSL downstream listener ----

my $sock = IO::Socket::SSL->new(
	PeerHost           => '127.0.0.1',
	PeerPort           => port(8080),
	SSL_hostname       => 'example.com',
	SSL_alpn_protocols => ['h2'],
	SSL_verify_mode    => IO::Socket::SSL::SSL_VERIFY_NONE(),
) or die "SSL connect failed: $!,$IO::Socket::SSL::SSL_ERROR";

$sock->syswrite('hello');

my $data = '';
my $sel  = IO::Select->new($sock);
while ($sel->can_read(2)) {
	my $n = $sock->sysread(my $chunk, 65536);
	last unless $n;
	$data .= $chunk;
}

is(substr($data, 0, 12), $SIG,                'ssl-auto v2 signature');
is(unpack('C', substr($data, 12, 1)), 0x21,    'ssl-auto version+command');

my $addr_len = unpack('n', substr($data, 14, 2));
cmp_ok($addr_len, '>', 12, 'ssl-auto header length > addr block');

my $tlvs   = parse_tlvs(substr($data, 28, $addr_len - 12));
my $payload = substr($data, 16 + $addr_len);

is(defined($tlvs->{0x01}) ? 1 : 0, 1, 'ssl-auto ALPN TLV present');
is($tlvs->{0x01}, 'h2',               'ssl-auto ALPN value');

is(defined($tlvs->{0x02}) ? 1 : 0, 1, 'ssl-auto AUTHORITY TLV present');
is($tlvs->{0x02}, 'example.com',       'ssl-auto AUTHORITY value');

ok(defined($tlvs->{0x20}),             'ssl-auto SSL TLV present');

my $ssl_body = $tlvs->{0x20};
# SSL TLV body: client(1) + verify(4) + sub-TLVs
my $sub = parse_tlvs(substr($ssl_body, 5));
ok(defined($sub->{0x21}),  'ssl-auto sub-TLV ssl_version present');
like($sub->{0x21}, qr/^TLSv1\.[23]$/, 'ssl-auto ssl_version value');
ok(defined($sub->{0x23}),  'ssl-auto sub-TLV ssl_cipher present');
cmp_ok(length($sub->{0x23}), '>', 0,  'ssl-auto ssl_cipher non-empty');

is($payload, 'hello', 'ssl-auto payload after PP v2 header');

# ---- Case 2: Non-SSL downstream listener (auto-fill silent-skip) ----

my $plain = IO::Socket::INET->new(
	Proto    => 'tcp',
	PeerAddr => '127.0.0.1:' . port(8081),
) or die "plain connect failed: $!";

$plain->syswrite('hello');

my $pdata = '';
my $psel  = IO::Select->new($plain);
while ($psel->can_read(2)) {
	my $n = $plain->sysread(my $chunk, 65536);
	last unless $n;
	$pdata .= $chunk;
}

# 16 fixed + 12 addr block, no TLVs
my $plen = unpack('n', substr($pdata, 14, 2));
is($plen, 12, 'plain-auto no TLVs (header len = addr block only)');

###############################################################################

# Parse a sequence of PP v2 TLV records into { type => value } pairs.
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

	my $buffer = '';
	my $csel   = IO::Select->new($client);
	while ($csel->can_read(0.5)) {
		my $n = $client->sysread(my $chunk, 65536);
		last unless $n;
		$buffer .= $chunk;
	}

	$client->syswrite($buffer);

	return 1;
}

###############################################################################
