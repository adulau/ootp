# $Id: Makefile 13 2009-11-26 16:37:03Z maf $

INSTALLI=install -c -m0644
INSTALL=install -c -m0755

IMGS = spyrus1.3.hex oar.ee oar.str
BINS = str2ee
DOCS = eeprom-map.txt oar.str

FWDIR=/usr/local/ootp/firmware
BINDIR=/usr/local/ootp/bin
DOCDIR=/usr/local/ootp/doc

install:
	mkdir -p ${FWDIR}
	mkdir -p ${BINDIR}
	mkdir -p ${DOCDIR}
	${INSTALLI} ${IMGS} ${FWDIR}
	${INSTALL} ${BINS} ${BINDIR}
	${INSTALLI} ${DOCS} ${DOCDIR}
	@echo files installed in ${FWDIR}
	@echo files installed in ${BINDIR}
	@echo files installed in ${DOCDIR}

