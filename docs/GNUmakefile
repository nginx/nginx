
VER=	$(shell grep 'define NGINX_VERSION' src/core/nginx.h		\
		| sed -e 's/^.*\"\(.*\)\"/\1/')
NGINX=	nginx-$(VER)
TEMP=	tmp
CP=	$(HOME)/java

define  XSLScript
	javavm -cp $(CP)/xsls/saxon.jar:$(CP)/xsls/xsls.jar		\
		com.pault.StyleSheet					\
		-x com.pault.XX -y com.pault.XX				\
	$(1) docs/xsls/dump.xsls					\
	| awk 'BEGIN{e=0}/^\n*$$/{e=1;next}{if(e){print"";e=0};print}' > $(2)

	if [ ! -s $(2) ]; then rm $(2); fi; test -s $(2)
endef

define  XSLT
	xsltproc $(shell echo $4					\
		| sed -e "s/\([^= ]*\)=\([^= ]*\)/--param \1 \"'\2'\"/g") \
		$3 $1							\
	> $(HTML)/$(strip $(2))
endef


changes:	$(TEMP)/$(NGINX)/CHANGES.ru				\
		$(TEMP)/$(NGINX)/CHANGES


$(TEMP)/$(NGINX)/CHANGES.ru:	docs/xml/nginx/changes.xml		\
				docs/xslt/changes.xslt

	test -d $(TEMP)/$(NGINX) || mkdir -p $(TEMP)/$(NGINX)

	xsltproc --param lang "'ru'"					\
		-o $(TEMP)/$(NGINX)/CHANGES.ru				\
		docs/xslt/changes.xslt docs/xml/nginx/changes.xml


$(TEMP)/$(NGINX)/CHANGES:	docs/xml/nginx/changes.xml		\
				docs/xslt/changes.xslt

	test -d $(TEMP)/$(NGINX) || mkdir -p $(TEMP)/$(NGINX)

	xsltproc --param lang "'en'"					\
		-o $(TEMP)/$(NGINX)/CHANGES				\
		docs/xslt/changes.xslt docs/xml/nginx/changes.xml


docs/xslt/changes.xslt:		docs/xsls/changes.xsls

	$(call XSLScript, docs/xsls/changes.xsls, $@)

