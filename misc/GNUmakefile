
VER=	$(shell grep NGINX_VER src/core/nginx.h				\
		| sed -e 's%^.*\"nginx/\(.*\)\"%\1%')
NGINX=	nginx-$(VER)
TEMP=	tmp


release:
	rm -rf $(TEMP)

	svn export -rHEAD . $(TEMP)/$(NGINX)

	mv $(TEMP)/$(NGINX)/auto/configure $(TEMP)/$(NGINX)

	# delete incomplete sources
	rm $(TEMP)/$(NGINX)/src/event/ngx_event_acceptex.c
	rm $(TEMP)/$(NGINX)/src/event/ngx_event_connectex.c
	rm $(TEMP)/$(NGINX)/src/event/modules/ngx_iocp_module.*
	rm -r $(TEMP)/$(NGINX)/src/os/win32

	rm $(TEMP)/$(NGINX)/src/core/ngx_slab.*
	rm $(TEMP)/$(NGINX)/src/core/ngx_resolver.*

	rm -r $(TEMP)/$(NGINX)/src/mysql

	rm $(TEMP)/$(NGINX)/src/http/modules/ngx_http_status_module.c

	mv $(TEMP)/$(NGINX)/docs/text/LICENSE $(TEMP)/$(NGINX)
	mv $(TEMP)/$(NGINX)/docs/text/README $(TEMP)/$(NGINX)
	mv $(TEMP)/$(NGINX)/docs/html $(TEMP)/$(NGINX)

	$(MAKE) -f docs/GNUmakefile changes

	rm -r $(TEMP)/$(NGINX)/docs
	rm -r $(TEMP)/$(NGINX)/misc

	tar -c -z -f $(NGINX).tar.gz --directory $(TEMP) $(NGINX)


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

	rm $(TEMP)/$(NGINX)/src/core/ngx_slab.*
	rm $(TEMP)/$(NGINX)/src/core/ngx_resolver.*

	rm -r $(TEMP)/$(NGINX)/src/mysql

	rm $(TEMP)/$(NGINX)/src/http/modules/ngx_http_status_module.c

	mv $(TEMP)/$(NGINX)/docs/text/LICENSE $(TEMP)/$(NGINX)
	mv $(TEMP)/$(NGINX)/docs/text/README $(TEMP)/$(NGINX)
	mv $(TEMP)/$(NGINX)/docs/html $(TEMP)/$(NGINX)

	$(MAKE) -f docs/GNUmakefile changes

	rm -r $(TEMP)/$(NGINX)/docs
	rm -r $(TEMP)/$(NGINX)/misc

	tar -c -z -f $(NGINX).tar.gz --directory $(TEMP) $(NGINX)


icons:	src/os/win32/nginx.ico src/os/win32/nginx_tray.ico

# 32x32 and 16x16 icons

src/os/win32/nginx.ico:	src/os/win32/nginx_icon32.xpm			\
			src/os/win32/nginx_icon16.xpm

	test -d $(TEMP) || mkdir $(TEMP)

	xpmtoppm --alphaout=$(TEMP)/nginx32.pbm				\
		src/os/win32/nginx_icon32.xpm > $(TEMP)/nginx32.ppm

	xpmtoppm --alphaout=$(TEMP)/nginx16.pbm				\
		src/os/win32/nginx_icon16.xpm > $(TEMP)/nginx16.ppm

	ppmtowinicon -output src/os/win32/nginx.ico -andpgms		\
		$(TEMP)/nginx32.ppm $(TEMP)/nginx32.pbm			\
		$(TEMP)/nginx16.ppm $(TEMP)/nginx16.pbm

# tray icon

src/os/win32/nginx_tray.ico:	src/os/win32/nginx_tray.xpm

	test -d $(TEMP) || mkdir $(TEMP)

	xpmtoppm --alphaout=$(TEMP)/nginx_tray.pbm			\
		src/os/win32/nginx_tray.xpm > $(TEMP)/nginx_tray.ppm

	ppmtowinicon -output src/os/win32/nginx_tray.ico -andpgms	\
		$(TEMP)/nginx_tray.ppm $(TEMP)/nginx_tray.pbm
