#!/bin/bash

set -e

cd "$(dirname "$0")/.."

echo "Building ModSecurity..."
cd modsecurity
git submodule init
git submodule update
./build.sh
./configure
make
make install
cd ..

echo "Building Vesta-NGINX..."
cd vesta-nginx
./configure --add-dynamic-module=../modsecurity-nginx
make
make install DESTDIR=../build/nginx
cd ..

echo "Building ModSecurity-NGINX connector..."
cd modsecurity-nginx
./configure
make

# Copy the dynamic module to build/
cp objs/ngx_http_modsecurity_module.so ../build/nginx/modules/
cd ..

echo "Build complete!"
