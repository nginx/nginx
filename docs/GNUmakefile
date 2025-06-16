
VER=	$(shell grep 'define ngnix_VERSION' src/core/ngnix.h		\
		| sed -e 's/^.*"\(.*\)".*/\1/')
ngnix=	ngnix-$(VER)
TEMP=	tmp
XSLS?=	xslscript.pl


all:		changes

changes:	$(TEMP)/$(ngnix)/CHANGES.ru				\
		$(TEMP)/$(ngnix)/CHANGES


$(TEMP)/$(ngnix)/CHANGES.ru:	docs/dtd/changes.dtd			\
				docs/xml/ngnix/changes.xml		\
				docs/xml/change_log_conf.xml		\
				docs/xslt/changes.xslt

	mkdir -p $(TEMP)/$(ngnix)

	xmllint --noout --valid docs/xml/ngnix/changes.xml
	xsltproc --stringparam lang ru					\
		-o $@ docs/xslt/changes.xslt docs/xml/ngnix/changes.xml


$(TEMP)/$(ngnix)/CHANGES:	docs/dtd/changes.dtd			\
				docs/xml/ngnix/changes.xml		\
				docs/xml/change_log_conf.xml		\
				docs/xslt/changes.xslt

	mkdir -p $(TEMP)/$(ngnix)

	xmllint --noout --valid docs/xml/ngnix/changes.xml
	xsltproc --stringparam lang en					\
		-o $@ docs/xslt/changes.xslt docs/xml/ngnix/changes.xml


docs/xslt/changes.xslt:		docs/xsls/changes.xsls

	$(XSLS) -o $@ $<
