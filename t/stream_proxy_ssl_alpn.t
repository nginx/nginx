#!/usr/bin/perl

# (C) Nginx, Inc.

# stream proxy_ssl: upstream ALPN
#
# Expected behavior:
#   - proxy_ssl_alpn <proto>...; sets explicit upstream ALPN offer list
#   - proxy_ssl_alpn_send on|off; controls whether ALPN is sent upstream at all
#       default: on
#   - If proxy_ssl_alpn is UNSET and proxy_ssl_alpn_send is ON,
#     nginx inherits the *negotiated* downstream ALPN (selected protocol)
#     from the client->nginx TLS session and advertises exactly that upstream.
#
# Test cases:
#   A) inherit negotiated downstream ALPN (client negotiates h2 to nginx) =>
#      upstream selects h2
#   B) proxy_ssl_alpn_send off => upstream selects NONE (even though downstream
#      negotiated h2)
#   C) explicit proxy_ssl_alpn http/1.1 overrides inheritance => upstream
#       selects http/1.1

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()
    ->has(qw/stream stream_ssl/)
    ->plan(6);

my $d = $t->testdir();

my $crt = "$d/cert.pem";
my $key = "$d/key.pem";

my $py  = "$d/alpn_upstream.py";

my $out_inherit  = "$d/out_inherit.txt";
my $out_sendoff  = "$d/out_sendoff.txt";
my $out_override = "$d/out_override.txt";

# Generate a self-signed cert (good enough; proxy_ssl verifies nothing by
# default).
system(
    "openssl req -x509 -newkey rsa:2048 -nodes " .
    "-subj /CN=localhost " .
    "-keyout $key -out $crt -days 1 >/dev/null 2>&1"
);

# Upstream TLS server: one-shot; records selected ALPN to out_file.
$t->write_file('alpn_upstream.py', <<'PY');
#!/usr/bin/env python3
import ssl, socket, sys

# args: listen_port cert key out_file protocols_csv
port = int(sys.argv[1])
cert = sys.argv[2]
key  = sys.argv[3]
outf = sys.argv[4]
protos = sys.argv[5].split(",") if len(sys.argv) > 5 and sys.argv[5] else []

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert, keyfile=key)
if protos:
    ctx.set_alpn_protocols(protos)

ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(1)

conn, _ = ls.accept()
try:
    ss = ctx.wrap_socket(conn, server_side=True)
    sel = ss.selected_alpn_protocol()
    with open(outf, "w") as f:
        f.write(sel if sel else "NONE")
    try:
        ss.recv(1)
        ss.send(b"x")
    except Exception:
        pass
    ss.close()
finally:
    ls.close()
PY

system("chmod +x $py >/dev/null 2>&1");

# Ports

my $p_inherit  = port(8010);
my $p_sendoff  = port(8011);
my $p_override = port(8012);

my $u_inherit  = port(9010);
my $u_sendoff  = port(9011);
my $u_override = port(9012);

# Start upstream servers:

# A) backend supports only h2
$t->run_daemon('python3', $py, $u_inherit,  $crt, $key, $out_inherit,  'h2');

# B) backend supports only h2, but nginx must not send ALPN upstream
$t->run_daemon('python3', $py, $u_sendoff,  $crt, $key, $out_sendoff,  'h2');

# C) backend supports only http/1.1
$t->run_daemon('python3', $py, $u_override, $crt, $key, $out_override,
               'http/1.1');

# Nginx config
# We make downstream TLS mandatory (listen ... ssl) and offer "h2" to the
# client. The client uses "openssl s_client -alpn h2" so downstream negotiated
# ALPN is h2, enabling inheritance behavior (case A).
$t->write_file_expand('nginx.conf', <<"NGINX");
worker_processes  1;
daemon off;

events {
    worker_connections  128;
}

stream {
    # A) proxy_ssl_alpn UNSET, proxy_ssl_alpn_send default ON => inherit
    # negotiated downstream ALPN (h2)
    server {
        listen 127.0.0.1:$p_inherit ssl;
        ssl_certificate     $crt;
        ssl_certificate_key $key;
        ssl_alpn h2;

        proxy_pass 127.0.0.1:$u_inherit;
        proxy_ssl on;
    }

    # B) proxy_ssl_alpn_send off => do not send ALPN upstream (even though
    # downstream negotiated h2)
    server {
        listen 127.0.0.1:$p_sendoff ssl;
        ssl_certificate     $crt;
        ssl_certificate_key $key;
        ssl_alpn h2;

        proxy_pass 127.0.0.1:$u_sendoff;
        proxy_ssl on;
        proxy_ssl_alpn_send off;
    }

    # C) proxy_ssl_alpn explicit overrides inheritance
    server {
        listen 127.0.0.1:$p_override ssl;
        ssl_certificate     $crt;
        ssl_certificate_key $key;
        ssl_alpn h2;

        proxy_pass 127.0.0.1:$u_override;
        proxy_ssl on;
        proxy_ssl_alpn http/1.1;
    }
}
NGINX

$t->run();

sub trigger_h2 {
    my ($port) = @_;

    # Negotiate ALPN "h2" with nginx so inheritance sees selected downstream
    # ALPN.
    my $cmd = "printf x | openssl s_client -connect 127.0.0.1:$port -quiet " .
              "-servername localhost -alpn h2 >/dev/null 2>&1";
    system($cmd);
}

sub trigger_none {
    my ($port) = @_;

    # Negotiate no ALPN with nginx so inheritance sees no downstream ALPN.
    my $cmd = "printf x | openssl s_client -connect 127.0.0.1:$port -quiet " .
              "-servername localhost >/dev/null 2>&1";
    system($cmd);
}

# h2 downstream ALPN negotiated

# A) inheritance: backend should select h2
trigger_h2($p_inherit);
$t->waitforfile($out_inherit);
my $got_inherit = $t->read_file('out_inherit.txt');
chomp($got_inherit);
is($got_inherit, 'h2', 'inherits negotiated downstream ALPN (h2) when ' .
   'proxy_ssl_alpn is unset and send is on');

# B) send off: backend should see NONE
trigger_h2($p_sendoff);
$t->waitforfile($out_sendoff);
my $got_sendoff = $t->read_file('out_sendoff.txt');
chomp($got_sendoff);
is($got_sendoff, 'NONE', 'proxy_ssl_alpn_send off disables upstream ' .
   'ALPN (no inheritance)');

# C) explicit override: backend should select http/1.1
trigger_h2($p_override);
$t->waitforfile($out_override);
my $got_override = $t->read_file('out_override.txt');
chomp($got_override);
is($got_override, 'http/1.1', 'proxy_ssl_alpn explicit list overrides '.
   'negotiated downstream ALPN inheritance');


# no downstream ALPN negotiated

# A) inheritance: backend should select NONE
trigger_none($p_inherit);
$t->waitforfile($out_inherit);
$got_inherit = $t->read_file('out_inherit.txt');
chomp($got_inherit);
is($got_inherit, 'h2', 'inherits negotiated downstream ALPN (h2) when ' .
   'proxy_ssl_alpn is unset and send is on');

# B) send off: backend should see NONE
trigger_none($p_sendoff);
$t->waitforfile($out_sendoff);
$got_sendoff = $t->read_file('out_sendoff.txt');
chomp($got_sendoff);
is($got_sendoff, 'NONE', 'proxy_ssl_alpn_send off disables upstream ' .
   'ALPN (no inheritance)');

# C) explicit override: backend should select http/1.1
trigger_none($p_override);
$t->waitforfile($out_override);
$got_override = $t->read_file('out_override.txt');
chomp($got_override);
is($got_override, 'http/1.1', 'proxy_ssl_alpn explicit list overrides ' .
   'negotiated downstream ALPN inheritance');

$t->stop();
