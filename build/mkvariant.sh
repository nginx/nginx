#!/bin/sh
# usage: mkvariant.sh NAME "FLAGS"   (run from nginx/ checkout, lt-trace branch)
set -e
sed -i '' -E "s/-DNGX_LT_TRACE=1( -DNGX_LT_[A-Z]+=[0-9.]+)*/-DNGX_LT_TRACE=1 $2/" objs-debug/Makefile
grep -q -- "-DNGX_LT_TRACE=1 $2" objs-debug/Makefile
rm -f objs-debug/src/http/modules/ngx_http_upstream_least_time_module.o objs-debug/nginx
make -j8 -f objs-debug/Makefile > /tmp/make.log 2>&1
grep -q "least_time_module.o" /tmp/make.log
cp objs-debug/nginx ../build/bin/nginx-$1
echo "built $1: $2"
