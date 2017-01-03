# $Id: Makefile 192 2011-06-12 16:33:42Z maf $

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

BIN = htsoft-downloader
COBJS = ../common/xerr.o
OBJS = version.o ${BIN}.o

BINDIR=/usr/local/ootp/bin

all: version ${COBJS} ${OBJS} ${BIN}

version:
	rm -f version.c; ../build/version ../VERSION ${BIN} > version.c

version.c:

install:
	mkdir -p ${BINDIR}
	${INSTALL} ${BIN} ${BINDIR}
	@echo files installed in ${BINDIR}

clean:
	/bin/rm -f ${BINS} ${OBJS} version.c

${BIN}: ${COBJS} ${OBJS}
	$(CC) $(CFLAGS) $(LFLAGS) $(INC) -o ${BIN} ${COBJS} ${OBJS} $(LIBS)

