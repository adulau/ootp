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
 *      $Id: otp-ov-plugin.c 13 2009-11-26 16:37:03Z maf $
 */

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <stdlib.h>
#include "ffdb.h"
#include "otplib.h"
#include "xerr.h"

void help(void);

int main (int argc, char **argv)
{
  struct otp_ctx *otpctx;
  char *otpdb_fname, *username, *pass;
  int db_flags, i, r, ret;

  /* init xerr */
  xerr_setid(argv[0]);

  otpdb_fname = OTP_DB_FNAME;
  db_flags = 0;
  ret = -1; /* fail */

  while ((i = getopt(argc, argv, "h?o:v")) != -1) {

    switch (i) { 
  
      case 'h':
      case '?':
        help();
        exit(0); /* be careful here... openvpn treats this as accept auth */

      case 'o' :
        otpdb_fname = optarg;
        break;

      case 'v':
        db_flags |= OTP_DB_VERBOSE;
        break;

      default:
        help();
        exit(1);

     } /* switch */

  } /* while */

  if (!(username = getenv("user")))
    xerr_errx(1, "getenv(user): failed.");

  if (!(pass = getenv("pass")))
    xerr_errx(1, "getenv(pass): failed.");

  if (!(otpctx = otp_db_open(otpdb_fname, db_flags)))
    xerr_errx(1, "otp_db_open(): failed.");

  if ((r = otp_user_exists(otpctx, username)) < 0)
    xerr_errx(1, "otp_user_exists(): failed.");

  if (r != 0)
    xerr_errx(1, "User %s does not exist in otp database.", username);
  
  if ((r = otp_user_auth(otpctx, username, pass, OTP_HOTP_WINDOW)) < 0)
    xerr_errx(1, "otp_user_auth(): failed.");

  if (otp_db_close(otpctx) < 0)
    xerr_errx(1, "otp_user_close(): failed.");

  /* convert otp auth status to openvpn auth return code space */
  if (r == OTP_AUTH_PASS) {
    if (db_flags & OTP_DB_VERBOSE)
      xerr_info("OTP_AUTH_PASS");
    ret = 0;
  } else {
    if (db_flags & OTP_DB_VERBOSE)
      xerr_info("OTP_AUTH_FAIL");
    ret = 1;
  }

  return ret;

} /* main.c */

void help()
{
  fprintf(stderr, "otp-ov-plugin [-?hv] [-o otpdb_pathname]\n");
  fprintf(stderr, "              -h : help\n");
  fprintf(stderr, "              -v : enable verbose output\n");
} /* help */
