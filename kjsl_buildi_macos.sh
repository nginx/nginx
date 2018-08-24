#!/bin/bash
git clone https://github.com/kevleyski/nginx-rtmp-module nginx-rtmp-module
git clone https://github.com/kevleyski/ngx_devel_kit ngx_devel_kit 

wget http://www.openssl.org/source/openssl-1.0.2o.tar.gz
tar -zxf openssl-1.0.2o.tar.gz
cd openssl-1.0.2o
./Configure darwin64-x86_64-cc --prefix=/usr
make
sudo make install

wget http://zlib.net/zlib-1.2.11.tar.gz
tar -zxf zlib-1.2.11.tar.gz
cd zlib-1.2.11
./configure
make
sudo make install

wget ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.42.tar.gz
tar -zxf pcre-8.42.tar.gz
cd pcre-8.42
./configure
make
sudo make install

mkdir -p /usr/local/nginx
mkdir -p /usr/local/nginx/nginx
./auto/configure --prefix=/etc/nginx \
	--prefix=/etc/nginx \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--error-log-path=/var/log/nginx/error.log \
	--http-log-path=/var/log/nginx/access.log \
	--pid-path=/var/run/nginx.pid \
	--lock-path=/var/run/nginx.lock \
	--with-pcre=../pcre-8.41 \
	--with-zlib=../zlib-1.2.11 \
	--with-openssl=../openss-1.0.2o \
	--with-http_ssl_module \
	--http-client-body-temp-path=/var/cache/nginx/client_temp \
	--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
	--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
	--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
	--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
	--user=nginx \
	--group=nginx \
	--with-http_realip_module \
	--with-http_addition_module \
	--with-http_sub_module \
	--with-http_dav_module \
	--with-http_flv_module \
	--with-http_mp4_module \
	--with-http_gunzip_module \
	--with-http_gzip_static_module \
	--with-http_random_index_module \
	--with-http_secure_link_module \
	--with-http_stub_status_module \
	--with-http_auth_request_module \
	--with-threads \
	--with-stream \
	--with-http_slice_module \
	--with-mail \
	--add-module=./ngx_devel_kit \
 	--add-module=./nginx-rtmp-module \
	--with-http_v2_module \
 	--add-module=../smootha/nginx-switch-module \
	--with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic'

make -j9
sudo make install

nginx -V
