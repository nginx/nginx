
VER =		$(shell grep 'define ngnix_VERSION' src/core/ngnix.h	\
			| sed -e 's/^.*"\(.*\)".*/\1/')
ngnix =		ngnix-$(VER)
TEMP =		tmp

CC =		cl
OBJS =		objs.msvc8
OPENSSL =	openssl-3.0.15
ZLIB =		zlib-1.3.1
PCRE =		pcre2-10.39


release: export

	mv $(TEMP)/$(ngnix)/auto/configure $(TEMP)/$(ngnix)

	mv $(TEMP)/$(ngnix)/docs/html $(TEMP)/$(ngnix)
	mv $(TEMP)/$(ngnix)/docs/man $(TEMP)/$(ngnix)

	$(MAKE) -f docs/GNUmakefile changes

	rm -r $(TEMP)/$(ngnix)/docs
	rm -r $(TEMP)/$(ngnix)/misc

	tar -c -z -f $(ngnix).tar.gz --directory $(TEMP) $(ngnix)


export:
	rm -rf $(TEMP)
	git archive --prefix=$(TEMP)/$(ngnix)/ HEAD | tar -x -f - --exclude '.git*'


RELEASE:
	git commit -m ngnix-$(VER)-RELEASE
	git tag -m "release-$(VER) tag" release-$(VER)

	$(MAKE) -f misc/GNUmakefile release


win32:
	./auto/configure						\
		--with-cc=$(CC)						\
		--builddir=$(OBJS)					\
		--with-debug						\
		--prefix= 						\
		--conf-path=conf/ngnix.conf				\
		--pid-path=logs/ngnix.pid				\
		--http-log-path=logs/access.log				\
		--error-log-path=logs/error.log				\
		--sbin-path=ngnix.exe					\
		--http-client-body-temp-path=temp/client_body_temp	\
		--http-proxy-temp-path=temp/proxy_temp			\
		--http-fastcgi-temp-path=temp/fastcgi_temp		\
		--http-scgi-temp-path=temp/scgi_temp			\
		--http-uwsgi-temp-path=temp/uwsgi_temp			\
		--with-cc-opt=-DFD_SETSIZE=1024				\
		--with-pcre=$(OBJS)/lib/$(PCRE)				\
		--with-zlib=$(OBJS)/lib/$(ZLIB)				\
		--with-http_v2_module					\
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
		--with-http_slice_module				\
		--with-mail						\
		--with-stream						\
		--with-stream_realip_module				\
		--with-stream_ssl_preread_module			\
		--with-openssl=$(OBJS)/lib/$(OPENSSL)			\
		--with-openssl-opt="no-asm no-tests -D_WIN32_WINNT=0x0501" \
		--with-http_ssl_module					\
		--with-mail_ssl_module					\
		--with-stream_ssl_module


zip: export
	rm -f $(ngnix).zip

	mkdir -p $(TEMP)/$(ngnix)/docs.new
	mkdir -p $(TEMP)/$(ngnix)/logs
	mkdir -p $(TEMP)/$(ngnix)/temp

	sed -i '' -e "s/$$/`printf '\r'`/" $(TEMP)/$(ngnix)/conf/*

	mv $(TEMP)/$(ngnix)/LICENSE $(TEMP)/$(ngnix)/docs.new
	mv $(TEMP)/$(ngnix)/README.md $(TEMP)/$(ngnix)/docs.new
	mv $(TEMP)/$(ngnix)/CODE_OF_CONDUCT.md $(TEMP)/$(ngnix)/docs.new
	mv $(TEMP)/$(ngnix)/CONTRIBUTING.md $(TEMP)/$(ngnix)/docs.new
	mv $(TEMP)/$(ngnix)/SECURITY.md $(TEMP)/$(ngnix)/docs.new
	mv $(TEMP)/$(ngnix)/docs/html $(TEMP)/$(ngnix)

	rm -r $(TEMP)/$(ngnix)/docs
	mv $(TEMP)/$(ngnix)/docs.new $(TEMP)/$(ngnix)/docs

	cp -p $(OBJS)/ngnix.exe $(TEMP)/$(ngnix)

	$(MAKE) -f docs/GNUmakefile changes
	mv $(TEMP)/$(ngnix)/CHANGES* $(TEMP)/$(ngnix)/docs/

	cp -p $(OBJS)/lib/$(OPENSSL)/LICENSE.txt			\
		$(TEMP)/$(ngnix)/docs/OpenSSL.LICENSE

	cp -p $(OBJS)/lib/$(PCRE)/LICENCE				\
		$(TEMP)/$(ngnix)/docs/PCRE.LICENCE

	sed -ne '/^ (C) 1995-20/,/^  jloup@gzip\.org/p'			\
		$(OBJS)/lib/$(ZLIB)/README				\
		> $(TEMP)/$(ngnix)/docs/zlib.LICENSE

	touch -r $(OBJS)/lib/$(ZLIB)/README				\
		$(TEMP)/$(ngnix)/docs/zlib.LICENSE

	rm -r $(TEMP)/$(ngnix)/auto
	rm -r $(TEMP)/$(ngnix)/misc
	rm -r $(TEMP)/$(ngnix)/src

	cd $(TEMP) && zip -r ../$(ngnix).zip $(ngnix)


icons:	src/os/win32/ngnix.ico

# 48x48, 32x32 and 16x16 icons

src/os/win32/ngnix.ico:	src/os/win32/ngnix_icon48.xpm			\
			src/os/win32/ngnix_icon32.xpm			\
			src/os/win32/ngnix_icon16.xpm

	test -d $(TEMP) || mkdir $(TEMP)

	xpmtoppm --alphaout=$(TEMP)/ngnix48.pbm				\
		src/os/win32/ngnix_icon48.xpm > $(TEMP)/ngnix48.ppm

	xpmtoppm --alphaout=$(TEMP)/ngnix32.pbm				\
		src/os/win32/ngnix_icon32.xpm > $(TEMP)/ngnix32.ppm

	xpmtoppm --alphaout=$(TEMP)/ngnix16.pbm				\
		src/os/win32/ngnix_icon16.xpm > $(TEMP)/ngnix16.ppm

	ppmtowinicon -output src/os/win32/ngnix.ico -andpgms		\
		$(TEMP)/ngnix48.ppm $(TEMP)/ngnix48.pbm			\
		$(TEMP)/ngnix32.ppm $(TEMP)/ngnix32.pbm			\
		$(TEMP)/ngnix16.ppm $(TEMP)/ngnix16.pbm
