PACKAGE=ipsvd-1.1.1
DIRS=doc man src package

all: clean .doc .man $(PACKAGE).tar.gz

.doc:
	cd md && ./gen-html ../doc
	touch .doc

.man:
	cd md && ./gen-man ../man
	touch .man

$(PACKAGE).tar.gz:
	rm -rf TEMP
	mkdir -p TEMP/net/$(PACKAGE)
	( cd src ; make clean )
	cp -a $(DIRS) TEMP/net/$(PACKAGE)/
	find TEMP/net/$(PACKAGE)/ -name .keepme -exec rm -f {} \;
	chmod -R g-ws TEMP/net
	chmod +t TEMP/net
	find TEMP -exec touch {} \;
	su -c 'chown -R root:root TEMP ; \
		(cd TEMP ; tar --exclude CVS -cpzf ../$(PACKAGE).tar.gz net) ; \
		rm -rf TEMP'

clean:
	find . -name \*~ -exec rm -f {} \;
	find . -name .??*~ -exec rm -f {} \;
	find . -name \#?* -exec rm -f {} \;

cleaner: clean
	rm -f $(PACKAGE).tar.gz
	rm -f doc/*.html man/*.[0-9] .doc .man
