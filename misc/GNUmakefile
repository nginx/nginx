
VER =		$(shell grep 'define NGINX_VERSION' src/core/nginx.h	\
			| sed -e 's/^.*\"\(.*\)\"/\1/')
NGINX =		nginx-$(VER)
TEMP =		tmp
REPO =		$(shell svn info | sed -n 's/^Repository Root: //p')

OBJS =		objs.msvc8
OPENSSL =	openssl-0.9.8u
ZLIB =		zlib-1.2.5
PCRE =		pcre-8.30


release:
	rm -rf $(TEMP)

	svn export -rHEAD . $(TEMP)/$(NGINX)

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


RELEASE:
	test -d $(TEMP) || mkdir -p $(TEMP)

	echo "nginx-$(VER)-RELEASE" > $(TEMP)/message
	svn ci -F $(TEMP)/message

	echo "release-$(VER) tag" > $(TEMP)/message
	svn copy $(REPO)/branches/stable-1.0				\
		$(REPO)/tags/release-$(VER)				\
		-F $(TEMP)/message

	svn up

	$(MAKE) -f misc/GNUmakefile release


snapshot:
	rm -rf $(TEMP)

	mkdir -p $(TEMP)
	svn export . $(TEMP)/$(NGINX)

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


zip:
	rm -rf $(TEMP)
	rm -f $(NGINX).zip

	mkdir -p $(TEMP)/$(NGINX)/docs
	mkdir -p $(TEMP)/$(NGINX)/logs
	mkdir -p $(TEMP)/$(NGINX)/temp

	svn export -rHEAD conf $(TEMP)/$(NGINX)/conf/
	perl -pi -e 's/$$/\r/' $(TEMP)/$(NGINX)/conf/*

	svn export -rHEAD contrib $(TEMP)/$(NGINX)/contrib/
	svn export -rHEAD docs/html $(TEMP)/$(NGINX)/html/

	$(MAKE) -f docs/GNUmakefile changes

	cp -p $(OBJS)/nginx.exe $(TEMP)/$(NGINX)

	cp -p docs/text/LICENSE $(TEMP)/$(NGINX)/docs/
	cp -p docs/text/README $(TEMP)/$(NGINX)/docs/
	mv $(TEMP)/$(NGINX)/CHANGES* $(TEMP)/$(NGINX)/docs/

	cp -p $(OBJS)/lib/$(OPENSSL)/LICENSE				\
		$(TEMP)/$(NGINX)/docs/OpenSSL.LICENSE

	cp -p $(OBJS)/lib/$(PCRE)/LICENCE				\
		$(TEMP)/$(NGINX)/docs/PCRE.LICENCE

	perl -ne 'print if /^ \(C\) 1995-20/ .. /^  jloup\@gzip.org/'	\
		$(OBJS)/lib/$(ZLIB)/README				\
		> $(TEMP)/$(NGINX)/docs/zlib.LICENSE

	touch -r $(OBJS)/lib/$(ZLIB)/README				\
		$(TEMP)/$(NGINX)/docs/zlib.LICENSE

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
