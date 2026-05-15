#!/usr/bin/perl

# Tests for $ssl_sigalgs variable.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl/)
	->has(qw/socket_ssl/)->has_daemon('openssl')->plan(4);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_certificate     localhost.crt;
        ssl_certificate_key localhost.key;

        location / {
            return 200 $ssl_sigalgs;
        }
    }
}

EOF

my $d = $t->testdir();

system('openssl req -x509 -new '
	. "-subj '/CN=localhost/' "
	. "-keyout $d/localhost.key -out $d/localhost.crt "
	. "-nodes -days 3650 -newkey rsa:2048 "
	. "2>/dev/null") == 0
	or die "Can't create certificate\n";

$t->run();

###############################################################################

my ($r, $p);

$p = port(8443);

# $ssl_sigalgs lists all sigalgs from ClientHello, colon-separated;
# on OpenSSL 4.0+ entries are TLS scheme names (e.g. "rsa_pkcs1_sha256"),
# on older OpenSSL entries are raw TLS SignatureScheme codes (e.g. "0x0401")

$r = get('/');
like($r, qr/\w/, 'ssl_sigalgs non-empty');

# format: colon-separated TLS scheme names or 0xHHHH hex codes

like($r, qr/^(?:[\w-]+|0x[0-9a-f]{4})(?::(?:[\w-]+|0x[0-9a-f]{4}))*$/,
	'ssl_sigalgs format');

# rsa_pkcs1_sha256 is always advertised; name on OpenSSL 4.0+, hex on older

like($r, qr/rsa_pkcs1_sha256|RSA-SHA256|0x0401/,
	'ssl_sigalgs rsa_pkcs1_sha256 present');

# rsa_pss_rsae_sha256: TLS scheme name on OpenSSL 4.0+, hex code on older

SKIP: {
	skip 'openssl does not support -sigalgs', 1
		unless `openssl s_client -help 2>&1` =~ /-sigalgs/;

	$r = get_openssl('rsa_pss_rsae_sha256');
	like($r, qr/^(?:rsa_pss_rsae_sha256|0x0804)$/,
		'ssl_sigalgs rsa_pss_rsae_sha256');
}

$t->stop();

###############################################################################

sub get {
	my ($url, %extra) = @_;

	my $r = http_get($url,
		SSL => 1,
		SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
		%extra
	);

	$r =~ s/.*?\r\n\r\n//s;
	chomp $r;
	return $r;
}

sub get_openssl {
	my ($sigalgs, @args) = @_;

	open my $fh, '>', "$d/req.bin"
		or die "Can't write request file: $!\n";
	print $fh "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
	close $fh;

	my $args_str = join(' ', @args);
	my $cmd = "openssl s_client -connect 127.0.0.1:$p -quiet"
		. " -sigalgs '$sigalgs' $args_str < $d/req.bin 2>/dev/null";

	my $out = `$cmd`;
	$out =~ s/.*?\r\n\r\n//s;
	chomp $out;
	return $out;
}
