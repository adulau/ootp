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
 *      $Id: otp-ov-plugin.c 177 2011-05-16 02:37:28Z maf $
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/errno.h>
#include "ffdb.h"
#include "otplib.h"
#include "xerr.h"

void help(void);

int main (int argc, char **argv)
{
  extern char *ootp_version;
  struct otp_ctx *otpctx;
  struct otp_user ou;
  u_long tmpul;
  char *otpdb_fname, *username, *pass, *endptr, *service;
  int db_flags, i, r, ret, otp_window, opt_version, otp_allow_unknown;

  struct option longopts[] = {
    { "otp-allow-unknown-user",     0, (void*)0L, 'u'},
    { "help",                       0, (void*)0L, 'h'},
    { "help",                       0, (void*)0L, '?'},
    { "otp-db",                     1, (void*)0L, 'o'},
    { "verbose",                    0, (void*)0L, 'v'},
    { "service-name",               0, (void*)0L, 'V'},
    { "otp-challenge-window",       1, (void*)0L, 'w'},
    { "version",                    0, &opt_version, 1},
    { 0, 0, 0, 0},
  };

  /* init xerr */
  xerr_setid(argv[0]);

  otpdb_fname = OTP_DB_FNAME;
  db_flags = 0;
  otp_window = OTP_WINDOW_DEFAULT;
  opt_version = 0;
  otp_allow_unknown = 0;
  service = "otp-openvpn";
  bzero(&ou, sizeof(ou));
  ret = -1; /* fail */

  while ((i = getopt_long(argc, argv, "h?o:uvV:w:", longopts,
    (int*)0L)) != -1) {

    switch (i) {

      case 'h':
      case '?':
        help();
        exit(0); /* be careful here... openvpn treats this as accept auth */

      case 'o' :
        otpdb_fname = optarg;
        break;

      case 'u':
        otp_allow_unknown = 1;
        break;

      case 'v':
        db_flags |= OTP_DB_VERBOSE;
        break;

      case 'V':
        service = optarg;
        break;

      case 'w':
        tmpul = strtoul(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "stroul(%s): failed at %c.", optarg, *endptr);
        if (tmpul > OTP_WINDOW_MAX)
          xerr_errx(1, "Challenge window %lu > %lu.", tmpul, OTP_WINDOW_MAX);
        otp_window = tmpul;
        break;

      case 0:
        if (opt_version) {
          printf("%s\n", ootp_version);
          exit(0);
        }
        break;

      default:
        xerr_errx(1, "getopt_long(): fatal.");
        break; /* not reached */

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

  if ((r == 1) && (otp_allow_unknown == 0)) {
       
    xerr_info("OTP_AUTH_FAIL via otp_user_exists() allow_unknown=0");
    ret = 1;
    goto done;

  }

  if ((r == 1) && (otp_allow_unknown == 1)) {

    xerr_info("OTP_AUTH_PASS via unknown user and allow_unknown=1");
    ret = 0;
    goto done;

  }

  if (r != 0)
    xerr_errx(1, "User %s does not exist in otp database.", username);

  if (otp_urec_open(otpctx, username, &ou, O_RDONLY,
    FFDB_OP_LOCK_EX) < 0)
    xerr_errx(1, "otp_urec_open(%s): failed.", username);

  if (otp_urec_get(otpctx, &ou) < 0)
    xerr_errx(1, "otp_urec_get(): failed.");

  if (otp_urec_close(otpctx, &ou) < 0)
    xerr_errx(1, "otp_urec_close(): failed.");

  if (ou.flags & OTP_FLAGS_SEND_TOKEN) {
    if (otp_user_send_token(otpctx, username, service) < 0)
      xerr_warnx("otp_user_send_token(): failed.");
  }
  
  if ((r = otp_user_auth(otpctx, username, pass, otp_window)) < 0)
    xerr_errx(1, "otp_user_auth(): failed.");

  if (otp_db_close(otpctx) < 0)
    xerr_errx(1, "otp_user_close(): failed.");

  /* convert otp auth status to openvpn auth return code space */
  if (r == OTP_AUTH_PASS) {
    xerr_info("OTP_AUTH_PASS");
    ret = 0;
  } else {
    xerr_info("OTP_AUTH_FAIL");
    ret = 1;
  }

done:

  return ret;

} /* main.c */

void help()
{
  fprintf(stderr, "otp-ov-plugin [-?hv] [-o otpdb_pathname] [-w otp_window]\n");
  fprintf(stderr, "              -h : help\n");
  fprintf(stderr, "              -v : enable verbose output\n");
} /* help */
