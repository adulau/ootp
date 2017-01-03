# $Id: Makefile 35 2009-11-30 21:49:59Z maf $

what:
	@echo
	@echo "make hardware-systype"
	@echo
	@echo "This Makefile knows about the following"
	@echo
	@echo i386-fbsd i386-linux i386-macosx
	@echo

i386-fbsd:
	@make CC="gcc" CFLAGS="-I../common -g -DOOTP_ENABLE -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" LIBS="-lssl -lcrypt" all

i386-linux:
	@make CC="gcc" CFLAGS="-I../common -g -DOOTP_ENABLE -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -D_BSD_SOURCE -D_XOPEN_SOURCE -Wall -std=c99 -pedantic" LIBS="-lssl -lcrypt" all

i386-macosx:
	@make CC="gcc" CFLAGS="-I../common -g -DOOTP_ENABLE -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" LIBS="-lssl -lcrypto" all

INSTALL=install -c -m0755

.c.o:;  $(CC) $(CFLAGS) -c $*.c -o $*.o

OBJS = pw.o rad.o ../common/xerr.o ../common/str.o ../common/otplib.o ../common/ffdb.o

BINS = urd

BINDIR=/usr/local/ootp/bin

all: pw.c rad.c urd.c ${OBJS} ${BINS}

install:
	mkdir -p ${BINDIR}
	${INSTALL} ${BINS} ${BINDIR}
	@echo files installed in ${BINDIR}

clean:
	/bin/rm -f ${BINS} urd.o pw.o rad.o

urd: ${OBJS} urd.o
	$(CC) $(CFLAGS) $(LFLAGS) $(INC) -o urd ${OBJS} urd.o $(LIBS)

