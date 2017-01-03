# $Id: Makefile 13 2009-11-26 16:37:03Z maf $

what:
	@echo
	@echo "make hardware-systype"
	@echo
	@echo "This Makefile knows about the following"
	@echo
	@echo i386-fbsd i386-linux i386-macosx
	@echo

i386-fbsd:
	@make CC="gcc" CFLAGS="-I../common -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" all

i386-linux:
	@make CC="gcc" CFLAGS="-I../common -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -D_BSD_SOURCE -D_XOPEN_SOURCE -Wall -std=c99 -pedantic" all

i386-macosx:
	@make CC="gcc" CFLAGS="-I../common -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" all

INSTALL=install -c -m0755

.c.o:;  $(CC) $(CFLAGS) -c $*.c -o $*.o

OBJS = ../common/xerr.o

BINS = htsoft-downloader

BINDIR=/usr/local/ootp/bin

all: htsoft-downloader.c ${OBJS} ${BINS}

install:
	mkdir -p ${BINDIR}
	${INSTALL} ${BINS} ${BINDIR}
	@echo files installed in ${BINDIR}

clean:
	/bin/rm -f ${BINS} htsoft-downloader.o

htsoft-downloader: ${OBJS} htsoft-downloader.o
	$(CC) $(CFLAGS) $(LFLAGS) $(INC) -o htsoft-downloader ${OBJS} htsoft-downloader.o $(LIBS)

