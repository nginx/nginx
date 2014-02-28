
VER=	$(shell grep 'define NGINX_VERSION' src/core/nginx.h		\
		| sed -e 's/^.*"\(.*\)".*/\1/')
NGINX=	nginx-$(VER)
TEMP=	tmp
XSLS?=	xslscript.pl


all:		changes

changes:	$(TEMP)/$(NGINX)/CHANGES.ru				\
		$(TEMP)/$(NGINX)/CHANGES


$(TEMP)/$(NGINX)/CHANGES.ru:	docs/dtd/changes.dtd			\
				docs/xml/nginx/changes.xml		\
				docs/xml/change_log_conf.xml		\
				docs/xslt/changes.xslt

	mkdir -p $(TEMP)/$(NGINX)

	xmllint --noout --valid docs/xml/nginx/changes.xml
	xsltproc --stringparam lang ru					\
		-o $@ docs/xslt/changes.xslt docs/xml/nginx/changes.xml


$(TEMP)/$(NGINX)/CHANGES:	docs/dtd/changes.dtd			\
				docs/xml/nginx/changes.xml		\
				docs/xml/change_log_conf.xml		\
				docs/xslt/changes.xslt

	mkdir -p $(TEMP)/$(NGINX)

	xmllint --noout --valid docs/xml/nginx/changes.xml
	xsltproc --stringparam lang en					\
		-o $@ docs/xslt/changes.xslt docs/xml/nginx/changes.xml


docs/xslt/changes.xslt:		docs/xsls/changes.xsls

	$(XSLS) -o $@ $<
