#!/usr/bin/perl

# Regression test for the same-path COPY/MOVE detection bypass via
# "/./" dot-segments in the Destination header (GHSA-39cr-2jxh-xxhx).
#
# Background: ngx_http_dav_validate_paths() rejects COPY/MOVE when the
# source and destination paths refer to the same filesystem object.
# The original implementation compared the mapped paths as strings,
# which was bypassable: ngx_http_parse_unsafe_uri() only rejected
# "/../" segments, so a Destination URI containing "/./" produced a
# different mapped string from the canonical source path while
# resolving — at the kernel layer — to the same inode.  The string
# compare returned NGX_OK, COPY/MOVE proceeded, and ngx_copy_file()
# opened the same inode for write (O_TRUNC) it then read from,
# zeroing the source file.
#
# Two fixes close this:
#   (1) ngx_http_dav_validate_paths() now compares inodes via
#       ngx_file_info()/ngx_file_uniq() instead of strings.
#   (2) ngx_http_parse_unsafe_uri() now rejects "/./" segments
#       alongside "/../" (defence-in-depth, applied to both pre- and
#       post-percent-decode pattern sites).
#
# This test seeds a file, asserts the same-path control case is
# rejected, then exercises the literal "/./" and percent-encoded
# "%2e" bypass variants and confirms both that the request is
# rejected (any 4xx — fix #2 returns 400 from the URI validator,
# fix #1 alone would return 403 from validate_paths) and that the
# source file content is preserved.  A "/../" sanity case ensures
# the existing parent-traversal rejection is unaffected.

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

my $t = Test::Nginx->new()->has(qw/http dav/)->plan(9);

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

# Control: same-path COPY must be rejected, and the source must
# remain intact.
$r = http_copy('/file.txt', '/file.txt');
like($r, qr!^HTTP/1\.\d 403!, 'control: identical Destination → 403');
is(slurp("$t->{_testdir}/file.txt"), $body,
    'control: source content preserved');

# Bypass A — literal "/./" dot-segment in Destination must be
# rejected.  Either fix layer is sufficient to prevent the bug;
# accept any 4xx so the test stays green if either fix is reverted
# in isolation.  The source must remain intact.
$r = http_copy('/file.txt', '/./file.txt');
like($r, qr!^HTTP/1\.\d 4\d\d!,
    '/./ Destination rejected (4xx)');
is(slurp("$t->{_testdir}/file.txt"), $body,
    '/./ bypass: source content preserved');

# Bypass B — percent-encoded variant "%2e" decodes to "." after
# ngx_unescape_uri; both validator passes (pre- and post-decode) and
# the inode-based same-target check catch this.
http_put('/file2.txt', $body);
$r = http_copy('/file2.txt', '/%2e/file2.txt');
like($r, qr!^HTTP/1\.\d 4\d\d!,
    '%2e Destination rejected (4xx)');
is(slurp("$t->{_testdir}/file2.txt"), $body,
    '%2e bypass: source content preserved');

# Sanity: existing "/../" rejection still works.
http_put('/file3.txt', $body);
$r = http_copy('/file3.txt', '/sub/../file3.txt');
like($r, qr!^HTTP/1\.\d 400!,
    'sanity: /../ Destination still rejected as unsafe URI');

# Sanity: a benign COPY to a different path still succeeds, so the
# tightened URI validator has not over-blocked.
$r = http_copy('/file.txt', '/file_copied.txt');
like($r, qr!^HTTP/1\.\d 20[14]!,
    'sanity: ordinary COPY to a different path still succeeds');

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
