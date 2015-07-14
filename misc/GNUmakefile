
VER =		$(shell grep 'define NGINX_VERSION' src/core/nginx.h	\
			| sed -e 's/^.*"\(.*\)".*/\1/')
NGINX =		nginx-$(VER)
TEMP =		tmp

OBJS =		objs.msvc8
OPENSSL =	openssl-1.0.1p
ZLIB =		zlib-1.2.8
PCRE =		pcre-8.35


release: export

	mv $(TEMP)/$(NGINX)/auto/configure $(TEMP)/$(NGINX)

	# delete incomplete sources
	rm $(TEMP)/$(NGINX)/src/event/ngx_event_acceptex.c
	rm $(TEMP)/$(NGINX)/src/event/ngx_event_connectex.c
	rm $(TEMP)/$(NGINX)/src/event/modules/ngx_iocp_module.*
	rm -r $(TEMP)/$(NGINX)/src/os/win32

	rm -r $(TEMP)/$(NGINX)/src/mysql

	mv $(TEMP)/$(NGINX)/docs/text/LICENSE $(TEMP)/$(NGINX)
	mv $(TEMP)/$(NGINX)/docs/text/README $(TEMP)/$(NGINX)
	mv $(TEMP)/$(NGINX)/docs/html $(TEMP)/$(NGINX)
	mv $(TEMP)/$(NGINX)/docs/man $(TEMP)/$(NGINX)

	$(MAKE) -f docs/GNUmakefile changes

	rm -r $(TEMP)/$(NGINX)/docs
	rm -r $(TEMP)/$(NGINX)/misc

	tar -c -z -f $(NGINX).tar.gz --directory $(TEMP) $(NGINX)


export:
	rm -rf $(TEMP)
	hg archive -X '.hg*' $(TEMP)/$(NGINX)


RELEASE:
	hg ci -m nginx-$(VER)-RELEASE
	hg tag -m "release-$(VER) tag" release-$(VER)

	$(MAKE) -f misc/GNUmakefile release


win32:
	./auto/configure						\
		--with-cc=cl						\
		--builddir=$(OBJS)					\
		--with-debug						\
		--prefix= 						\
		--conf-path=conf/nginx.conf				\
		--pid-path=logs/nginx.pid				\
		--http-log-path=logs/access.log				\
		--error-log-path=logs/error.log				\
		--sbin-path=nginx.exe					\
		--http-client-body-temp-path=temp/client_body_temp	\
		--http-proxy-temp-path=temp/proxy_temp			\
		--http-fastcgi-temp-path=temp/fastcgi_temp		\
		--http-scgi-temp-path=temp/scgi_temp			\
		--http-uwsgi-temp-path=temp/uwsgi_temp			\
		--with-cc-opt=-DFD_SETSIZE=1024				\
		--with-pcre=$(OBJS)/lib/$(PCRE)				\
		--with-zlib=$(OBJS)/lib/$(ZLIB)				\
		--with-select_module					\
		--with-http_realip_module				\
		--with-http_addition_module				\
		--with-http_sub_module					\
		--with-http_dav_module					\
		--with-http_stub_status_module				\
		--with-http_flv_module					\
		--with-http_mp4_module					\
		--with-http_gunzip_module				\
		--with-http_gzip_static_module				\
		--with-http_auth_request_module				\
		--with-http_random_index_module				\
		--with-http_secure_link_module				\
		--with-mail						\
		--with-stream						\
		--with-openssl=$(OBJS)/lib/$(OPENSSL)			\
		--with-openssl-opt=enable-tlsext			\
		--with-http_ssl_module					\
		--with-mail_ssl_module					\
		--with-stream_ssl_module				\
		--with-ipv6


zip: export
	rm -f $(NGINX).zip

	mkdir -p $(TEMP)/$(NGINX)/docs.new
	mkdir -p $(TEMP)/$(NGINX)/logs
	mkdir -p $(TEMP)/$(NGINX)/temp

	sed -i '' -e "s/$$/`printf '\r'`/" $(TEMP)/$(NGINX)/conf/*

	mv $(TEMP)/$(NGINX)/docs/text/LICENSE $(TEMP)/$(NGINX)/docs.new
	mv $(TEMP)/$(NGINX)/docs/text/README $(TEMP)/$(NGINX)/docs.new
	mv $(TEMP)/$(NGINX)/docs/html $(TEMP)/$(NGINX)

	rm -r $(TEMP)/$(NGINX)/docs
	mv $(TEMP)/$(NGINX)/docs.new $(TEMP)/$(NGINX)/docs

	cp -p $(OBJS)/nginx.exe $(TEMP)/$(NGINX)

	$(MAKE) -f docs/GNUmakefile changes
	mv $(TEMP)/$(NGINX)/CHANGES* $(TEMP)/$(NGINX)/docs/

	cp -p $(OBJS)/lib/$(OPENSSL)/LICENSE				\
		$(TEMP)/$(NGINX)/docs/OpenSSL.LICENSE

	cp -p $(OBJS)/lib/$(PCRE)/LICENCE				\
		$(TEMP)/$(NGINX)/docs/PCRE.LICENCE

	sed -ne '/^ (C) 1995-20/,/^  jloup@gzip\.org/p'			\
		$(OBJS)/lib/$(ZLIB)/README				\
		> $(TEMP)/$(NGINX)/docs/zlib.LICENSE

	touch -r $(OBJS)/lib/$(ZLIB)/README				\
		$(TEMP)/$(NGINX)/docs/zlib.LICENSE

	rm -r $(TEMP)/$(NGINX)/auto
	rm -r $(TEMP)/$(NGINX)/misc
	rm -r $(TEMP)/$(NGINX)/src

	cd $(TEMP) && zip -r ../$(NGINX).zip $(NGINX)


icons:	src/os/win32/nginx.ico

# 48x48, 32x32 and 16x16 icons

src/os/win32/nginx.ico:	src/os/win32/nginx_icon48.xpm			\
			src/os/win32/nginx_icon32.xpm			\
			src/os/win32/nginx_icon16.xpm

	test -d $(TEMP) || mkdir $(TEMP)

	xpmtoppm --alphaout=$(TEMP)/nginx48.pbm				\
		src/os/win32/nginx_icon48.xpm > $(TEMP)/nginx48.ppm

	xpmtoppm --alphaout=$(TEMP)/nginx32.pbm				\
		src/os/win32/nginx_icon32.xpm > $(TEMP)/nginx32.ppm

	xpmtoppm --alphaout=$(TEMP)/nginx16.pbm				\
		src/os/win32/nginx_icon16.xpm > $(TEMP)/nginx16.ppm

	ppmtowinicon -output src/os/win32/nginx.ico -andpgms		\
		$(TEMP)/nginx48.ppm $(TEMP)/nginx48.pbm			\
		$(TEMP)/nginx32.ppm $(TEMP)/nginx32.pbm			\
		$(TEMP)/nginx16.ppm $(TEMP)/nginx16.pbm
