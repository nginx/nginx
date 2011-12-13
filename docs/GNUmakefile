
VER=	$(shell grep 'define NGINX_VERSION' src/core/nginx.h		\
		| sed -e 's/^.*\"\(.*\)\"/\1/')
NGINX=	nginx-$(VER)
TEMP=	tmp
CP=	$(HOME)/java

define  XSLScript
	java -cp $(CP)/xsls/saxon.jar:$(CP)/xsls/xsls.jar		\
		com.pault.StyleSheet					\
		-x com.pault.XX -y com.pault.XX				\
		$(1) docs/xsls/dump.xsls				\
	| sed 's/ *$$//;/^ *$$/N;/\n *$$/D' > $(2)

	if [ ! -s $(2) ]; then rm $(2); fi; test -s $(2)
endef

define  XSLT
	xmllint --noout --valid $2
	xsltproc -o $3							\
		$(shell echo $4						\\
		| sed -e "s/\([^= ]*\)=\([^= ]*\)/--param \1 \"'\2'\"/g") \
		$1 $2
endef


changes:	$(TEMP)/$(NGINX)/CHANGES.ru				\
		$(TEMP)/$(NGINX)/CHANGES


$(TEMP)/$(NGINX)/CHANGES.ru:	docs/xml/nginx/changes.xml		\
				docs/xml/change_log_conf.xml		\
				docs/xslt/changes.xslt

	test -d $(TEMP)/$(NGINX) || mkdir -p $(TEMP)/$(NGINX)

	xsltproc --stringparam lang ru					\
		-o $(TEMP)/$(NGINX)/CHANGES.ru				\
		docs/xslt/changes.xslt docs/xml/nginx/changes.xml


$(TEMP)/$(NGINX)/CHANGES:	docs/xml/nginx/changes.xml		\
				docs/xml/change_log_conf.xml		\
				docs/xslt/changes.xslt

	test -d $(TEMP)/$(NGINX) || mkdir -p $(TEMP)/$(NGINX)

	xsltproc --stringparam lang en					\
		-o $(TEMP)/$(NGINX)/CHANGES				\
		docs/xslt/changes.xslt docs/xml/nginx/changes.xml


docs/xslt/changes.xslt:		docs/xsls/changes.xsls

	$(call XSLScript, docs/xsls/changes.xsls, $@)

