#!/usr/bin/perl

# (C) Nginx, Inc.

# Tests for proxy_protocol_passthrough directive in the mail proxy module.
# A downstream daemon sends a PP v2 header with an AUTHORITY TLV to nginx;
# the backend captures what nginx forwards and the test verifies that the
# AUTHORITY is present, confirming passthrough works through the unified
# write entry point with no mail-module code changes.

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

my $t = Test::Nginx->new()->has(qw/mail imap/)->plan(3)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

mail {
    auth_http  127.0.0.1:%%PORT_8080%%;

    server {
        listen          127.0.0.1:%%PORT_8143%% proxy_protocol;
        protocol        imap;
        proxy           on;
        proxy_protocol  on;
        proxy_protocol_version  2;
        proxy_protocol_passthrough authority unique_id;
    }
}

EOF

my $tmpfile = $t->testdir() . '/pp2.bin';

$t->run_daemon(\&auth_daemon,   port(8080), port(8144));
$t->run_daemon(\&imap_backend,  port(8144), $tmpfile);
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8080));
$t->waitforsocket('127.0.0.1:' . port(8143));
$t->waitforsocket('127.0.0.1:' . port(8144));

###############################################################################

# Build a PP v2 header with AUTHORITY and UNIQUE_ID TLVs.

sub pp2_tlv {
    my ($type, $value) = @_;
    return pack('Cn', $type, length($value)) . $value;
}

sub pp2_header {
    my ($tlvs) = @_;
    my $sig  = "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a";
    my $addr = pack('NNnn', 0x7f000001, 0x7f000001, 12345, port(8143));
    return $sig . "\x21\x11" . pack('n', 12 + length($tlvs)) . $addr . $tlvs;
}

my $tlvs = pp2_tlv(0x02, 'mail.example.com')
         . pp2_tlv(0x05, 'mail-req-42');

# Connect with a raw PP v2 header (the listen port is proxy_protocol).
my $sock = IO::Socket::INET->new(
    Proto    => 'tcp',
    PeerAddr => '127.0.0.1:' . port(8143),
) or die "Cannot connect: $!\n";

$sock->autoflush(1);
$sock->syswrite(pp2_header($tlvs));

readline_sock($sock);                   # nginx IMAP banner
$sock->syswrite("1 LOGIN user pass\r\n");
readline_sock($sock);                   # forged login-ok
$sock->close();

# Give the backend time to write the file.
sleep 1;

my $pp = '';
if (-f $tmpfile) {
    open(my $fh, '<', $tmpfile) or die "open $tmpfile: $!";
    binmode $fh;
    local $/;
    $pp = <$fh>;
    close $fh;
}

ok(length($pp) >= 28, 'mail-passthrough: PP v2 header received');

# Parse TLVs from the upstream PP v2 header.
my $addr_len = unpack('n', substr($pp, 14, 2));
my $tlv_bytes = substr($pp, 28, $addr_len - 12);

sub parse_tlvs {
    my ($buf) = @_;
    my (%tlvs, $off);
    $off = 0;
    while ($off + 3 <= length($buf)) {
        my $type = unpack('C', substr($buf, $off, 1));
        my $len  = unpack('n', substr($buf, $off + 1, 2));
        last if $off + 3 + $len > length($buf);
        $tlvs{$type} = substr($buf, $off + 3, $len);
        $off += 3 + $len;
    }
    return \%tlvs;
}

my $fwdtlvs = parse_tlvs($tlv_bytes);

is($fwdtlvs->{0x02}, 'mail.example.com', 'mail-passthrough: AUTHORITY forwarded');
is($fwdtlvs->{0x05}, 'mail-req-42',      'mail-passthrough: UNIQUE_ID forwarded');

###############################################################################

sub readline_sock {
    my ($sock) = @_;
    my $line = '';
    my $sel  = IO::Select->new($sock);
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
