# $Id: Makefile 134 2010-06-15 14:31:25Z maf $

what:
	@echo
	@echo "make hardware-systype"
	@echo
	@echo "This Makefile knows about the following"
	@echo
	@echo i386-fbsd i386-linux i386-yum-linux i386-macosx
	@echo

i386-fbsd:
	@make CC="gcc" CFLAGS="-g -I/usr/local/pcsc/include/PCSC -DSCR_PCSC -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG  -Wall -std=c99 -pedantic" all

i386-linux:
	@make CC="gcc" CFLAGS="-g -I/usr/local/include/PCSC -D_BSD_SOURCE -D_XOPEN_SOURCE -DSCR_PCSC -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" all

i386-yum-linux:
	@make CC="gcc" CFLAGS="-g -I/usr/include/PCSC -DSCR_PCSC -D_BSD_SOURCE -D_XOPEN_SOURCE -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" all

i386-macosx:
	@make CC="gcc" CFLAGS="-g ../common -I/System/Library/Frameworks/PCSC.framework/Versions/Current/Headers -DSCR_PCSC -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" all

INSTALL=install -c -m0755

.c.o:;  $(CC) $(CFLAGS) -c $*.c

OBJS = xerr.o str.o ffdb.o otplib.o acr30.o scr.o sccmd.o

all: ${OBJS}

clean:
	/bin/rm -f ${OBJS}

