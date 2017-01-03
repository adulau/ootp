# $Id: Makefile 153 2011-04-01 02:38:36Z maf $

INSTALL=install -c -m0644

.SUFFIXES: .sgml .1 .7 .html

MAN1DIR=/usr/local/ootp/man/man1
MAN7DIR=/usr/local/ootp/man/man7
HTMLDIR=/usr/local/ootp/doc
MISCDIR=/usr/local/ootp/doc

.sgml.1:
	docbook-to-man $*.sgml > $@

.sgml.7:
	docbook-to-man $*.sgml > $@

.sgml.html:
	openjade -V nochunks -c /usr/local/share/sgml/docbook/dsssl/modular/catalog -c /usr/local/share/sgml/docbook/3.1/dtd/catalog -c /usr/local/share/sgml/jade/catalog -d /usr/local/share/sgml/docbook/dsssl/modular/html/docbook.dsl -t sgml $*.sgml > $*.html

MAN1S = htsoft-downloader.1 bcload.1 otp-control.1 otp-ov-plugin.1\
	pam_otp.1 urd.1 otp-sca.1 otp-sct.1

MAN7S = spyrus-par2.7

HTMLS = htsoft-downloader.html bcload.html otp-control.html otp-ov-plugin.html\
	pam_otp.html urd.html otp-sca.html otp-sct.html spyrus-par2.html

MISC = QUICKSTART LICENSE PAR2-USER-GENERIC BALANCE-USER HOTP-2009.pdf

all: $(MAN1S) $(MAN7S) $(HTMLS)

install:
	mkdir -p ${MAN1DIR}
	mkdir -p ${MAN7DIR}
	mkdir -p ${HTMLDIR}
	${INSTALL} ${MAN1S} ${MAN1DIR}
	${INSTALL} ${MAN7S} ${MAN7DIR}
	${INSTALL} ${HTMLS} ${HTMLDIR}
	${INSTALL} ${MISC} ${MISCDIR}

clean:
	/bin/rm -f ${MAN1S} ${MAN7S} ${HTMLS}

