
# Copyright (C) Igor Sysoev
# Copyright (C) Nginx, Inc.

use 5.006001;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'nginx',
    VERSION_FROM      => 'nginx.pm',     # finds $VERSION
    PREREQ_PM         => {},             # e.g., Module::Name => 1.1

    ABSTRACT_FROM     => 'nginx.pm',     # retrieve abstract from module
    AUTHOR            => 'Igor Sysoev',

    CCFLAGS           => "$ENV{NGX_PM_CFLAGS}",
    OPTIMIZE          => '-O',

    INC               => "-I ../../../../../src/core " .
                         "-I ../../../../../src/event " .
                         "-I ../../../../../src/os/unix " .
                         "-I ../../../../../src/http " .
                         "-I ../../../../../src/http/modules " .
                         "-I ../../../../../src/http/modules/perl " .
                         "-I ../../../../../$ENV{NGX_OBJS} " .
                         ($ENV{NGX_PCRE} =~ /^(YES|NO)/ ? "" :
                             ($ENV{NGX_PCRE} =~ m#^/# ? "-I $ENV{NGX_PCRE} " :
                                  "-I ../../../../../$ENV{NGX_PCRE} ")) .
                         ($ENV{NGX_OPENSSL} =~ /^(YES|NO)/ ? "" :
                             ($ENV{NGX_OPENSSL} =~ m#^/# ?
                                  "-I $ENV{NGX_OPENSSL}/.openssl/include " :
                      "-I ../../../../../$ENV{NGX_OPENSSL}/.openssl/include ")),

    depend => {
        'nginx.c'     =>
                  "../../../../../src/http/modules/perl/ngx_http_perl_module.h"
    },

    PM => {
        'nginx.pm'    => '$(INST_LIBDIR)/nginx.pm'
    }
);
