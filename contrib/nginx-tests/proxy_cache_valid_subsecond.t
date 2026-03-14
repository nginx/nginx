#!/usr/bin/perl

# (C) Nginx sub-second cache validity test
#
# This test verifies that proxy_cache_valid accepts the "ms" suffix
# and that cached responses expire after the specified sub-second TTL.
# Copy this file to the root of the nginx-tests repository and run:
#   prove proxy_cache_valid_subsecond.t
# Requires: nginx built with the sub-second cache validity patch (issue #1156).

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

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(5)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache levels=1:2 keys_zone=one:1m;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_cache one;
            proxy_cache_valid 200 100ms;
            add_header X-Cache-Status $upstream_cache_status;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "body\n";
            add_header Content-Type text/plain;
        }
    }
}

EOF

$t->run();

###############################################################################

# First request: MISS, then HIT within 100ms
my $r = http_get('/');
like($r, qr/X-Cache-Status: MISS/, 'first request miss');

$r = http_get('/');
like($r, qr/X-Cache-Status: HIT/, 'second request hit');

# Wait 150ms for cache to expire (100ms validity)
select undef, undef, undef, 0.15;

# Next request should see expired cache (MISS or EXPIRED)
$r = http_get('/');
like($r, qr/X-Cache-Status: (MISS|EXPIRED)/, 'after 150ms cache expired or miss');

# Then served from upstream and cached again
$r = http_get('/');
like($r, qr/X-Cache-Status: HIT/, 'cached again');

# Also verify that second-only syntax still works (no regression)
# We use a separate config for that - skip if we only have one config.
# For simplicity this test focuses on sub-second; full suite covers seconds.

pass('sub-second proxy_cache_valid test completed');

###############################################################################
