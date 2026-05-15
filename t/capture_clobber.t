#!/usr/bin/perl

# Tests for PCRE capture state stability across the length and copy passes
# of ngx_http_complex_value() and ngx_http_script_regex_start_code().
#
# A regex-backed map variable evaluated during the length pass must not
# replace r->captures before the copy pass reads positional captures ($1...).
# Without the fix this produces an information disclosure (stale pool bytes
# in the response body) and a heap overflow (rewrite buffer sized for the
# location capture but filled with the larger map capture).

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

my $t = Test::Nginx->new()->has(qw/http map rewrite/)->plan(5);

# 200-byte strings used to make the size mismatch unambiguous.
my $long = 'A' x 200;
my $fill = 'B' x 200;

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%

daemon off;

events {}

http {
    %%TEST_GLOBALS_HTTP%%

    # Regex map: match sets r->captures[$1] to the scheme word, returns "tls".
    # Used to clobber the location capture during the return body length pass.
    map $http_x_scheme $scheme_tag {
        default      "plain";
        ~^(https?)$  "tls";
    }

    # Regex map: match sets r->captures[$1] to the payload after "data:",
    # returns "".  Used to clobber the location capture during the rewrite
    # target length pass.
    map $http_x_data $data_suffix {
        default      ".html";
        ~^data:(.+)$ "";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        # return path: $1 (location capture) is sized in the length pass;
        # $scheme_tag is evaluated second, triggering the regex map and
        # overwriting r->captures.  The copy pass must still use the original
        # location capture for $1.
        location ~ ^/return/(.+)$ {
            return 200 "$1|$scheme_tag";
        }

        # rewrite path: same TOCTOU inside ngx_http_script_regex_start_code.
        # The buffer is sized for the location capture; $data_suffix triggers
        # the regex map which replaces r->captures with a large value.  The
        # copy opcodes must use the captures saved before the length pass.
        # "last" triggers re-location-matching so the /dest/ block handles it.
        location ~ ^/rewrite/([^/]+)$ {
            rewrite ^/rewrite/([^/]+)$ /dest/$1$data_suffix last;
        }

        location /dest/ {
            return 200 "ok:$uri";
        }
    }
}

EOF

$t->run();

###############################################################################

# Baseline: no map trigger, no regex match, no capture clobber.

like(http_get('/return/hello'), qr/hello\|plain/, 'return: baseline');

# --- return body: capture state stable across two passes ---

# $1 from the large URI capture must appear in the body, not "http" from the
# scheme map capture.  With the bug, $1 copies "http" (4 bytes) and the rest
# of the over-allocated buffer leaks stale pool memory.

my $r = http("GET /return/$long HTTP/1.0\r\n"
           . "Host: localhost\r\n"
           . "X-Scheme: http\r\n"
           . "\r\n");

like($r, qr/\Q$long\E\|tls/, 'return: location capture not clobbered by map regex');

# Content-Length must exactly match the delivered body: any stale-byte tail
# would make length($body) < Content-Length.

my ($cl)   = ($r =~ /Content-Length:\s*(\d+)/i);
my ($body) = ($r =~ /\r\n\r\n(.*)/s);
is(length($body), $cl, 'return: Content-Length matches actual body (no leak tail)');

# --- rewrite target: capture state stable in regex_start_code ---

# Buffer is allocated for "/dest/" + "abc" (3 B) + "" = 9 bytes.
# $data_suffix map regex would replace $1 with the 200-byte fill value;
# without the fix the copy opcode writes 200 bytes into the 3-byte slot.
# After the fix the rewrite target is correctly /dest/abc and nginx survives.

$r = http("GET /rewrite/abc HTTP/1.0\r\n"
        . "Host: localhost\r\n"
        . "X-Data: data:$fill\r\n"
        . "\r\n");

like($r, qr|ok:/dest/abc\b|, 'rewrite: location capture not clobbered by map regex');

# Confirm the worker process is still alive after the overflow attempt.

like(http_get('/return/alive'), qr/alive\|plain/, 'worker alive after rewrite test');

###############################################################################
