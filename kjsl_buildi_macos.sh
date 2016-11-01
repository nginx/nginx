#!/bin/bash
mkdir -p /usr/local/nginx
mkdir -p /usr/local/nginx/nginx
./auto/configure
make -j9
sudo make install
