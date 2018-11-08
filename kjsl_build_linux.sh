#!/bin/bash
git clone https://github.com/kevleyski/nginx-rtmp-module nginx-rtmp-module
git clone https://github.com/kevleyski/ngx_devel_kit ngx_devel_kit 

if [ ! -d openssl-1.0.2o ]; then
wget http://www.openssl.org/source/openssl-1.0.2o.tar.gz
tar -zxf openssl-1.0.2o.tar.gz
cd openssl-1.0.2o
./Configure --prefix=/usr
make
sudo make install
cd ..
fi

if [ ! -d zlib-1.2.11 ]; then
wget http://zlib.net/zlib-1.2.11.tar.gz
tar -zxf zlib-1.2.11.tar.gz
cd zlib-1.2.11
./configure
make
sudo make install
cd ..
fi

if [ ! -d pcre-8.42 ]; then
wget ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.42.tar.gz
tar -zxf pcre-8.42.tar.gz
cd pcre-8.42
./configure
make
sudo make install
cd ..
fi

mkdir -p /usr/nginx
mkdir -p /usr/nginx/nginx
./auto/configure --prefix=/etc/nginx \
	--with-cc-opt="-I/usr/include -I/usr/opt/openssl/include" \
	--with-ld-opt="-L/usr/lib -L/usr/opt/openssl/lib" \
        --with-http_stub_status_module \
	--prefix=/etc/nginx \
	--sbin-path=/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--error-log-path=/var/log/nginx/error.log \
	--http-log-path=/var/log/nginx/access.log \
	--pid-path=/var/run/nginx.pid \
	--lock-path=/var/run/nginx.lock \
        --modules-path=/etc/nginx/modules \
	--add-module=./ngx_devel_kit \
 	--add-module=./nginx-rtmp-module \
 	--add-module=../smootha/nginx-switch-module \
 	--add-module=../nginx_mod_smooth_streaming-1.9.5

make -j9
sudo make install

nginx -V
