DESTDIR=

PACKAGE=ipsvd-0.9.7
DIRS=doc man src package
MANPAGES=man/ipsvd.7 man/tcpsvd.8 man/udpsvd.8 man/ipsvd-cdb.8 \
man/ipsvd-instruct.5 man/sslio.8

all: clean .manpages $(PACKAGE).tar.gz

.manpages:
	for i in $(MANPAGES); do \
	  rman -S -f html -r '' < $$i | \
	  sed -e "s}name='sect\([0-9]*\)' href='#toc[0-9]*'>\(.*\)}name='sect\1'>\2}g ; \
	  s}<a href='#toc'>Table of Contents</a><p>}<a href='http://smarden.org/pape/'>G. Pape</a><br><a href='index.html'>ipsvd</a><hr>}g ; \
	  s}<!--.*-->}}g" \
	  > doc/`basename $$i`.html ; \
	done ; \
	touch .manpages

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
		( cd TEMP ; tar cpfz ../$(PACKAGE).tar.gz net --exclude CVS ) ; \
		rm -rf TEMP'

clean:
	find . -name \*~ -exec rm -f {} \;
	find . -name .??*~ -exec rm -f {} \;
	find . -name \#?* -exec rm -f {} \;

cleaner: clean
	rm -f $(PACKAGE).tar.gz
	for i in $(MANPAGES); do rm -f doc/`basename $$i`.html; done
	rm -f .manpages

fixup:
	for i in src/*; do \
	  sed -e 's/ *$$//' $$i >$$i.fixup && mv -f $$i.fixup $$i; \
	done
