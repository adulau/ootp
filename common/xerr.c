/*
 * Copyright (c) 2005 Mark Fullmer
 * Copyright (c) 2009 Mark Fullmer and the Ohio State University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Based on code from FreeBSD - err.c 8.1 (Berkeley) 6/4/93
 *
 *      $Id: xerr.c 13 2009-11-26 16:37:03Z maf $
 */

#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif


#define XERR_FILE   1
#define XERR_SYSLOG 2

static int xerr_flags = XERR_FILE;
static FILE *xerr_file;
static char *xerr_id = "";
static void (*xerr_exit)(int);

void xerr_setexit(void (*f)(int))
{
        xerr_exit = f;
} /* xerr_set_exit */


void xerr_setid(char *id)
{
  char *c;

  /* skip to end */
  for (c = id; *c; ++c);

  /* skip back to first / or begining */
  for (; (c != id) && (*c != '/'); --c);

  if (c != id)
    xerr_id = c+1;
  else
    xerr_id = c;

}

void xerr_setfile(int enable, void *fp)
{
  if (enable) {
    xerr_flags |= XERR_FILE;
    xerr_file = fp;
  }
  else
    xerr_flags &= ~XERR_FILE;
}

void xerr_setsyslog(int enable, int logopt, int facility)
{
  if (enable) {
    xerr_flags |= XERR_SYSLOG;
    openlog(xerr_id, logopt, facility);
  } else {
    if (xerr_flags & XERR_SYSLOG)
      closelog();
    xerr_flags &= ~XERR_SYSLOG;
  }
}

void xerr_setsyslog2(int enable)
{
  if (enable) {
    xerr_flags |= XERR_SYSLOG;
  } else {
    xerr_flags &= ~XERR_SYSLOG;
  }
}

void xerr_info(const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);

  snprintf(buf2, 1024, "%s: %s", xerr_id, buf);

  if (xerr_flags & XERR_FILE)
    fprintf(((xerr_file) ? xerr_file : stderr), "%s\n", buf2);

  if (xerr_flags & XERR_SYSLOG)
    syslog(LOG_INFO, buf);

} /* xerr_info */

void xerr_err(int code, const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);


  if (xerr_flags & XERR_FILE) {
    snprintf(buf2, 1024, "%s: %s: %s", xerr_id, buf, strerror(errno));
    fprintf(((xerr_file) ? xerr_file : stderr), "%s\n", buf2);
  }

  if (xerr_flags & XERR_SYSLOG) {
    snprintf(buf2, 1024, "%s: %s", buf, strerror(errno));
    syslog(LOG_INFO, buf2);
  }

  if (xerr_exit)
    xerr_exit(code);
  exit (code);

} /* xerr_err */

void xerr_errx(int code, const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);

  if (xerr_flags & XERR_FILE) {
    snprintf(buf2, 1024, "%s: %s", xerr_id, buf);
    fprintf(((xerr_file) ? xerr_file : stderr), "%s\n", buf2);
  }

  if (xerr_flags & XERR_SYSLOG)
    syslog(LOG_INFO, buf);

  if (xerr_exit)
    xerr_exit(code);
  exit (code);

} /* xerr_errx */

void xerr_warnx(const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);

  if (xerr_flags & XERR_FILE) {
    snprintf(buf2, 1024, "%s: %s", xerr_id, buf);
    fprintf(((xerr_file) ? xerr_file : stderr), "%s\n", buf2);
  }

  if (xerr_flags & XERR_SYSLOG)
    syslog(LOG_INFO, buf);

} /* xerr_warnx */

void xerr_warn(const char *fmt, ...)
{
  va_list ap;
  char buf[1025];
  char buf2[1025];
 
  va_start(ap, fmt);
  vsnprintf(buf, (size_t)1024, fmt, ap);
  va_end(ap);


  if (xerr_flags & XERR_FILE) {
    snprintf(buf2, 1024, "%s: %s: %s", xerr_id, buf, strerror(errno));
    fprintf(((xerr_file) ? xerr_file : stderr), "%s\n", buf2);
  }

  if (xerr_flags & XERR_SYSLOG) {
    snprintf(buf2, 1024, "%s: %s", buf, strerror(errno));
    syslog(LOG_INFO, buf2);
  }

} /* xerr_warn */

