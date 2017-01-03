# $Id: Makefile 41 2009-12-01 22:12:06Z maf $

what:
	@echo
	@echo "make hardware-systype"
	@echo
	@echo "This Makefile knows about the following"
	@echo
	@echo i386-fbsd i386-linux i386-macosx
	@echo

i386-fbsd:
	@make CC="gcc" CFLAGS="-fpic -DPIC -I../common -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" LIBS="-lssl -lpam -lc" SLIB="--shared" all

i386-linux:
	@make CC="gcc" CFLAGS="-fpic -DPIC -I../common -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -D_BSD_SOURCE -D_XOPEN_SOURCE -Wall -std=c99 -pedantic" LIBS="-lssl -lpam -lcrypto -lc" SLIB="--shared" all

i386-macosx:
	@make CC="gcc" CFLAGS="-fpic -DPIC -I../common -g -DHAVE_STRING_H -DHAVE_STRINGS_H -DDEBUG -Wall -std=c99 -pedantic" LIBS="-lssl -lpam -lcrypto -lc" SLIB="-dylib" all

INSTALL=install -c -m0755

.c.o:;  $(CC) $(CFLAGS) -c $*.c -o $*.o

OBJS = xerr.o str.o otplib.o ffdb.o

LIBDIR=/usr/local/ootp/lib/

BLIBS=pam_otp.so

all: pam_otp.so ${OBJS}

install:
	mkdir -p ${LIBDIR}
	${INSTALL} ${BLIBS} ${LIBDIR}
	@echo files installed in ${LIBDIR}

clean:
	/bin/rm -f ${BLIBS} pam_otp.o

pam_otp.so: ${OBJS} pam_otp.o
	ld -x ${SLIB} -o pam_otp.so pam_otp.o ${OBJS} ${LIBS}

