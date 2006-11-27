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
    HTTP_REDIRECT
    HTTP_NOT_FOUND
    HTTP_SERVER_ERROR
);

our $VERSION = '0.5.0';

require XSLoader;
XSLoader::load('nginx', $VERSION);

# Preloaded methods go here.

use constant OK                   => 0;
use constant DECLINED             => -5;

use constant HTTP_OK              => 200;
use constant HTTP_REDIRECT        => 302;
use constant HTTP_NOT_FOUND       => 404;
use constant HTTP_SERVER_ERROR    => 500;


1;
__END__

=head1 NAME

nginx - Perl interface to the nginx HTTP server API

=head1 SYNOPSIS

  use nginx;

=head1 DESCRIPTION

This module provides a Perl interface to the nginx HTTP server API.


=head1 SEE ALSO

http://sysoev.ru/nginx/docs/http/ngx_http_perl_module.html

=head1 AUTHOR

Igor Sysoev

=head1 COPYRIGHT AND LICENSE

Copyright (C) Igor Sysoev


=cut
