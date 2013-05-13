package nginx;

use 5.006001;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT = qw(
    OK
    DECLINED

    HTTP_OK
    HTTP_CREATED
    HTTP_ACCEPTED
    HTTP_NO_CONTENT
    HTTP_PARTIAL_CONTENT

    HTTP_MOVED_PERMANENTLY
    HTTP_MOVED_TEMPORARILY
    HTTP_REDIRECT
    HTTP_SEE_OTHER
    HTTP_NOT_MODIFIED
    HTTP_TEMPORARY_REDIRECT

    HTTP_BAD_REQUEST
    HTTP_UNAUTHORIZED
    HTTP_PAYMENT_REQUIRED
    HTTP_FORBIDDEN
    HTTP_NOT_FOUND
    HTTP_NOT_ALLOWED
    HTTP_NOT_ACCEPTABLE
    HTTP_REQUEST_TIME_OUT
    HTTP_CONFLICT
    HTTP_GONE
    HTTP_LENGTH_REQUIRED
    HTTP_REQUEST_ENTITY_TOO_LARGE
    HTTP_REQUEST_URI_TOO_LARGE
    HTTP_UNSUPPORTED_MEDIA_TYPE
    HTTP_RANGE_NOT_SATISFIABLE

    HTTP_INTERNAL_SERVER_ERROR
    HTTP_SERVER_ERROR
    HTTP_NOT_IMPLEMENTED
    HTTP_BAD_GATEWAY
    HTTP_SERVICE_UNAVAILABLE
    HTTP_GATEWAY_TIME_OUT
    HTTP_INSUFFICIENT_STORAGE
);

our $VERSION = '1.2.9';

require XSLoader;
XSLoader::load('nginx', $VERSION);

# Preloaded methods go here.

use constant OK                             => 0;
use constant DECLINED                       => -5;

use constant HTTP_OK                        => 200;
use constant HTTP_CREATED                   => 201;
use constant HTTP_ACCEPTED                  => 202;
use constant HTTP_NO_CONTENT                => 204;
use constant HTTP_PARTIAL_CONTENT           => 206;

use constant HTTP_MOVED_PERMANENTLY         => 301;
use constant HTTP_MOVED_TEMPORARILY         => 302;
use constant HTTP_REDIRECT                  => 302;
use constant HTTP_SEE_OTHER                 => 303;
use constant HTTP_NOT_MODIFIED              => 304;
use constant HTTP_TEMPORARY_REDIRECT        => 307;

use constant HTTP_BAD_REQUEST               => 400;
use constant HTTP_UNAUTHORIZED              => 401;
use constant HTTP_PAYMENT_REQUIRED          => 402;
use constant HTTP_FORBIDDEN                 => 403;
use constant HTTP_NOT_FOUND                 => 404;
use constant HTTP_NOT_ALLOWED               => 405;
use constant HTTP_NOT_ACCEPTABLE            => 406;
use constant HTTP_REQUEST_TIME_OUT          => 408;
use constant HTTP_CONFLICT                  => 409;
use constant HTTP_GONE                      => 410;
use constant HTTP_LENGTH_REQUIRED           => 411;
use constant HTTP_REQUEST_ENTITY_TOO_LARGE  => 413;
use constant HTTP_REQUEST_URI_TOO_LARGE     => 414;
use constant HTTP_UNSUPPORTED_MEDIA_TYPE    => 415;
use constant HTTP_RANGE_NOT_SATISFIABLE     => 416;

use constant HTTP_INTERNAL_SERVER_ERROR     => 500;
use constant HTTP_SERVER_ERROR              => 500;
use constant HTTP_NOT_IMPLEMENTED           => 501;
use constant HTTP_BAD_GATEWAY               => 502;
use constant HTTP_SERVICE_UNAVAILABLE       => 503;
use constant HTTP_GATEWAY_TIME_OUT          => 504;
use constant HTTP_INSUFFICIENT_STORAGE      => 507;


sub rflush {
    my $r = shift;

    $r->flush;
}


1;
__END__

=head1 NAME

nginx - Perl interface to the nginx HTTP server API

=head1 SYNOPSIS

  use nginx;

=head1 DESCRIPTION

This module provides a Perl interface to the nginx HTTP server API.


=head1 SEE ALSO

http://nginx.org/en/docs/http/ngx_http_perl_module.html

=head1 AUTHOR

Igor Sysoev

=head1 COPYRIGHT AND LICENSE

Copyright (C) Igor Sysoev
Copyright (C) Nginx, Inc.


=cut
