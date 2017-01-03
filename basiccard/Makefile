# $Id: Makefile 13 2009-11-26 16:37:03Z maf $

INSTALL=install -c -m0644

IMGS = HOTPC.IMG SPYRUSP.IMG

FWDIR=/usr/local/ootp/firmware

install:
	mkdir -p ${FWDIR}
	${INSTALL} ${IMGS} ${FWDIR}
	@echo files installed in ${FWDIR}

