
# Copyright (C) Igor Sysoev

use 5.006001;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'nginx',
    VERSION_FROM      => 'nginx.pm',     # finds $VERSION
    PREREQ_PM         => {},             # e.g., Module::Name => 1.1

    ABSTRACT_FROM     => 'nginx.pm',     # retrieve abstract from module
    AUTHOR            => 'Igor Sysoev',

    CCFLAGS           => "$ENV{NGX_PERL_CFLAGS}",
    OPTIMIZE          => '-O',

    INC               => "-I ../../../../../src/core " .
                         "-I ../../../../../src/event " .
                         "-I ../../../../../src/os/unix " .
                         "-I ../../../../../src/http " .
                         "-I ../../../../../src/http/modules " .
                         "-I ../../../../../src/http/modules/perl " .
                         "-I ../../../../../$ENV{NGX_OBJS} " .
                         "-I ../../../../../$ENV{NGX_PCRE} " .
                         "-I ../../../../../$ENV{NGX_ZLIB} ",

    depend => {
        'nginx.c'     =>
                  "../../../../../src/http/modules/perl/ngx_http_perl_module.h"
    },

    PM => {
        'nginx.pm'    => '$(INST_LIBDIR)/nginx.pm'
    }
);
