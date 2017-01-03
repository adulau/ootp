# $Id: Makefile 13 2009-11-26 16:37:03Z maf $

what:
	@echo
	@echo "make hardware-systype"
	@echo
	@echo "This Makefile knows about the following"
	@echo
	@echo i386-fbsd i386-linux i386-yum-linux i386-macosx
	@echo

i386-fbsd:
	@make CC="gcc" CFLAGS="-I../common -I/usr/local/pcsc/include/PCSC -DSCR_PCSC -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" LFLAGS="-L/usr/local/pcsc/lib" LIBS="-lpcsclite" all

i386-linux:
	@make CC="gcc" CFLAGS="-I../common -I/usr/local/include/PCSC -DSCR_PCSC -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -D_BSD_SOURCE -D_XOPEN_SOURCE -std=c99 -pedantic" LFLAGS="-L/usr/local/pcsc/lib" LIBS="/usr/local/lib/libpcsclite.a -lpthread" all

i386-yum-linux:
	@make CC="gcc" CFLAGS="-I../common -I/usr/include/PCSC -DSCR_PCSC -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -D_BSD_SOURCE -D_XOPEN_SOURCE -Wall -std=c99 -pedantic" LIBS="-lpcsclite -lpthread" all

i386-macosx:
	@make CC="gcc" CFLAGS="-I../common -I/System/Library/Frameworks/PCSC.framework/Versions/Current/Headers -DSCR_PCSC -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic " LFLAGS="-framework PCSC" LIBS="-lssl" all

INSTALL=install -c -m0755

.c.o:;  $(CC) $(CFLAGS) -c $*.c -o $*.o

OBJS = ../common/xerr.o ../common/str.o ../common/acr30.o ../common/scr.o ../common/sccmd.o

BINS = otp-sct

BINDIR=/usr/local/ootp/bin

all: otp-sct.c ${OBJS} ${BINS}

install:
	mkdir -p ${BINDIR}
	${INSTALL} ${BINS} ${BINDIR}
	@echo files installed in ${BINDIR}

clean:
	/bin/rm -f ${BINS} otp-sct.o

otp-sct: ${OBJS} otp-sct.o
	$(CC) $(CFLAGS) $(LFLAGS) $(INC) -o otp-sct ${OBJS} otp-sct.o $(LIBS)

