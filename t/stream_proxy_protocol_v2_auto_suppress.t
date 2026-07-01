#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for PROXY protocol v2 auto-fill suppression via empty value.
# An empty proxy_protocol_tlv <type> "" suppresses both user override
# and auto-fill for that TLV type.

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

my $t = Test::Nginx->new()->has(qw/stream stream_ssl/)->has_daemon('openssl')
	->plan(8);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen                  127.0.0.1:%%PORT_8080%%  ssl;
        ssl_certificate         localhost.crt;
        ssl_certificate_key     localhost.key;
        ssl_protocols           TLSv1.2 TLSv1.3;
        ssl_alpn                h2 http/1.1;
        proxy_pass              127.0.0.1:%%PORT_8081%%;
        proxy_protocol          on;
        proxy_protocol_version  2;

        # Suppress top-level AUTHORITY auto-fill.
        proxy_protocol_tlv authority   "";

        # Suppress ssl_cipher sub-TLV inside auto-filled SSL TLV.
        proxy_protocol_tlv ssl_cipher  "";
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

$t->run_daemon(\&stream_daemon, port(8081));
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

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

my $addr_len = unpack('n', substr($data, 14, 2));
my $tlvs     = parse_tlvs(substr($data, 28, $addr_len - 12));

# Suppressed
is(defined($tlvs->{0x02}) ? 1 : 0, 0,  'AUTHORITY suppressed by empty value');

# Still auto-populated
is($tlvs->{0x01}, 'h2',                'ALPN still auto-filled');
ok(defined($tlvs->{0x20}),             'SSL TLV still present');

my $ssl_body = $tlvs->{0x20};
my $sub      = parse_tlvs(substr($ssl_body, 5));

# ssl_cipher suppressed
is(defined($sub->{0x23}) ? 1 : 0, 0,   'ssl_cipher suppressed by empty value');

# ssl_version still auto-filled
ok(defined($sub->{0x21}),               'ssl_version still auto-filled');
like($sub->{0x21}, qr/^TLSv1\.[23]$/,   'ssl_version value sensible');

# Sanity: confirm both suppressions in one assertion that the SSL TLV
# isn't unexpectedly large.
cmp_ok(length($ssl_body), '<', 50,     'SSL TLV body shrunk by suppression');

my $payload = substr($data, 16 + $addr_len);
is($payload, 'hello', 'suppress payload after PP v2 header');

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
