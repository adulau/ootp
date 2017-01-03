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
 *      $Id: otp-sct.c 13 2009-11-26 16:37:03Z maf $
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include "scr.h"
#include "sccmd.h"
#include "str.h"
#include "xerr.h"
#include "otpsc.h"
#include "otplib.h"

#if defined(__FreeBSD__)
#include <sys/endian.h>
#endif

#if defined(__DARWIN_UNIX03)
#include <sys/_endian.h>
#endif

#define OTP_ERROR          -1      /* library function failure */
#define OTP_SUCCESS        0       /* library function success */
#define OTP_FAIL           1       /* library function failure */

#define BZS(A) bzero(A, sizeof A);

#define SWAP32(x) x = \
         ((((x)&0xff)<<24) |\
         (((x)&0xff00)<<8) |\
         (((x)&0xff0000)>>8) |\
         (((x)>>24)&0xff));

#define SWAP16(x) x = \
    ( (((x)&0xff)<<8) | (((x)&0xff00)>>8) );

static int debug;

void help(void);


int main(int argc, char **argv)
{
  struct scr_ctx *scrctx;
  int i, j, k, r, sc_idx_set, sc_idx_tmp, j_start, j_end;
  int reset_pin, list_readers, list_version, get_hotp_version, list_hostnames;
  uint32_t tmp_count;
  uint64_t tmp64u;
  char sc_hostname[SC_HOSTNAME_LEN+1], sc_pin[SC_PIN_LEN+1];
  char sc_newpin[SC_PIN_LEN+1], sc_newpin2[SC_PIN_LEN+1];
  char fmt_buf[133], fmt_buf2[133];
  u_char sc_hotp[SC_HOTP_LEN+1], sc_idx[SC_INDEX_LEN+1];
  u_char sc_version[SC_VERSION_LEN+1], sc_count32[SC_COUNT32_LEN+1];
  u_char sc_fv;
  char *reader, *endptr, *err_msg;

  /* init xerr */
  xerr_setid(argv[0]);

  sc_fv = 5;
  debug = 0;
  sc_idx_set = 0;
  reset_pin = 0; /* no */
  tmp_count = 0;
  reader = SCR_DEFAULT_READER;
  list_readers = 0; /* no */
  list_version = 0; /* no */
  list_hostnames = 0; /* no */
  scrctx = (struct scr_ctx*)0L;
  get_hotp_version = 3;

  BZS(sc_hotp);
  BZS(sc_idx);
  BZS(sc_version);
  BZS(sc_count32);
  BZS(sc_hostname);
  BZS(sc_pin);
  BZS(sc_newpin);

  bcopy(SC_PIN_DEFAULT, sc_pin, SC_PIN_LEN);
  bcopy(SC_PIN_DEFAULT, sc_newpin, SC_PIN_LEN);

  while ((i = getopt(argc, argv, "1c:d:hi:lLpr:v:V?")) != -1) {

    switch (i) {

      case '1':
        get_hotp_version = 1;
        break;

      case 'c':
        tmp64u = strtoull(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoull(%s): failed at %c.", optarg, *endptr);
        if (tmp64u > SC_COUNT32_MAX)
          xerr_errx(1, "count > SC_COUNT32_MAX.");
        tmp_count = tmp64u;
#if BYTE_ORDER == LITTLE_ENDIAN
        SWAP32(tmp_count);
#endif /* LITTLE_ENDIAN */
        bcopy(&tmp_count, sc_count32, 4);
        tmp_count = 1; /* signal was set */
        break;

      case 'd':
        debug = strtoul(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoul(%s): failed at %c.", optarg, *endptr);
        break;

      case 'h':
      case '?':
        help();
        exit(0);
        break; /* notreached */

      case 'i':
        sc_idx_tmp = strtoul(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoul(%s): failed at %c.", optarg, *endptr);
        if (sc_idx_tmp > SC_INDEX_MAX) {
          xerr_errx(1, "Index out of range 0..%d", SC_INDEX_MAX);
        } else {
          sc_idx[0] = sc_idx_tmp;
          sc_idx_set = 1;
        }
        break;

      case 'l':
        list_readers = 1;
        break;

      case 'L':
        list_hostnames = 1;
        break;

      case 'p':
        reset_pin = 1;
        break;

      case 'r':
        reader = optarg;
        break;

      case 'v':
        sc_fv = strtoul(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoul(%s): failed at %c.", optarg, *endptr);
        get_hotp_version = 1;
        break;

      case 'V':
        list_version = 1;
        break;

    } /* switch */

  } /* while getopt() */

  /* get pin */
  if (!list_readers && !list_version) {

    while (1) {

      if (str_input("Enter PIN: ", sc_pin, SC_PIN_LEN+1,
        STR_FLAGS_ECHO_OFF) < 0)
        xerr_errx(1, "str_input(%d): failed.", SC_PIN_LEN);

      if (strlen((char*)sc_pin) != SC_PIN_LEN) {

        xerr_warnx("PIN Must be %d characters", SC_PIN_LEN);
        continue;

      } else {

        break;

      } /* SC_PIN_LEN */

    } /* valid pin len */

  } /* need PIN */

  if (!(scrctx = scr_ctx_new(SCR_READER_EMBEDDED_ACR30S|SCR_READER_PCSC, debug))) {
    xerr_errx(1, "scr_ctx_new(): failed");
  }

  if (list_readers) {

    for (i = 0; i < scrctx->num_readers; ++i)
      printf("%s\n", scrctx->readers[i]);

    goto main_out;

  }

  /* get new pin? */
  if (reset_pin) {

    while (1) {

      if (str_input("New PIN: ", sc_newpin, SC_PIN_LEN+1,
        STR_FLAGS_ECHO_OFF) < 0)
        xerr_errx(1, "str_input(%d): failed.", SC_PIN_LEN);

      if (strlen((char*)sc_newpin) != SC_PIN_LEN) {
        xerr_warnx("PIN Must be %d characters.", SC_PIN_LEN);
        continue;
      }

      if (str_input("New PIN (again): ", sc_newpin2, SC_PIN_LEN+1,
        STR_FLAGS_ECHO_OFF) < 0)
        xerr_errx(1, "str_input(%d): failed.", SC_PIN_LEN);

      /* identical? then done */
      if (!bcmp(sc_newpin,sc_newpin2, SC_PIN_LEN))
        break;

      printf("New PIN did not match, try again.\n");

    } /* new pin confirm */

  } /* reset_pin */

  if (scr_ctx_connect(scrctx, reader) < 0) {
    xerr_errx(1, "scr_ctx_connect(): failed");
  }

/****************/

  if (list_version) {

    if ((r = sccmd_GetVersion(scrctx, sc_fv, sc_version)) < 0) {
      xerr_errx(1, "sccmd_GetVersion(): failed.");
    }

    if (r == 0) {
      str_hex_dump(fmt_buf, sc_version, 1);
      printf("Version: 0x%s\n", fmt_buf);
    } else if (r == 1) {
      printf("Version: fail\n");
    } else {
      xerr_errx(1, "sccmd_GetVersion(): fatal.");
    }

    goto main_out;

  } /* list_version */

/****************/

  if (reset_pin) {

    if ((r = sccmd_SetPIN(scrctx, sc_fv, sc_pin, sc_newpin)) < 0) {
      xerr_errx(1, "sccmd_SetPIN(): failed.");
    }

    if (r == 0)
      printf("SetPIN Good.\n");
    else if (r == 1)
      printf("SetPIN Bad.\n");
    else
      xerr_errx(1, "sccmd_SetPIN(): fatal.");

    goto main_out;

  } /* reset_pin */

  if (list_hostnames) {

    /* if no index, iterate until empty hostname */
    if (sc_idx_set) {
      j_start = sc_idx[0];
      j_end = sc_idx[0];
    } else {
      j_start = 0, j_end = SC_INDEX_MAX;
    }

    for (j = j_start; j <= j_end; ++j) {

      sc_idx[0] = j;
  
      if ((r = sccmd_GetHostName(scrctx, sc_fv, sc_idx, sc_pin,
        sc_hostname)) < 0)
        xerr_errx(1, "sccmd_GetHostName(): failed.");
  
      if (r == 0) {
  
        /* empty hostname is end of data */
        if (sc_hostname[0] == 0)
          break;
 
        str_hex_dump(fmt_buf, sc_idx, 1); 
        i = (1<<1); fmt_buf[i] = ':'; i += 1;

        /* required reader key then skip */
        if (sc_hostname[HOSTNAME_POS_READERKEY] & HOSTNAME_FLAG_MASK) {

          continue;

        } /* READERKEY flag */


        for (k = 0; k < SC_HOSTNAME_LEN; ++k) {

          fmt_buf[i++] = sc_hostname[k] & ~HOSTNAME_FLAG_MASK;

          if (sc_hostname[k] == 0)
            break;

        } /* hostname chars */
  
        printf("%s\n", fmt_buf);
  
      } else if (r == 1) {
  
        printf("GetHostName reject\n");
        break;
  
      } else {
  
        xerr_errx(1, "sccmd_GetHostName(): fatal.");
  
      }
  
    } /* for host */

    goto main_out;

  } /* list_hostnames */

/****************/  

  if (get_hotp_version == 1) {

    if ((r = sccmd_GetHOTP(scrctx, sc_fv, sc_idx, sc_pin, sc_hotp)) < 0)
      xerr_errx(1, "sccmd_GetHOTP(): failed.");

      err_msg = "sccmd_GetHOTP(): fatal.";

  } /* get_hotp_version == 1 */

  if (get_hotp_version == 3) {

    if ((r = sccmd_GetHOTPHostCount32(scrctx, sc_fv, sc_idx, sc_pin,
      sc_count32, sc_hotp, sc_hostname)) < 0)
      xerr_errx(1, "sccmd_GetHOTPHostCount32(): failed.");
    
    err_msg = "sccmd_GetHOTPHostCount32(): fatal.";

  } /* get_hotp_version == 3 */

  /* successful SC transaction? */
  if (r == 0) {

    for (i = 0, j = 0; i < SC_HOSTNAME_LEN; ++i) {

      /* clear high bit for display */
      sc_hostname[i] &= ~HOSTNAME_FLAG_MASK;

    }

    str_hex_dump(fmt_buf, sc_hotp, 5);

    if (get_hotp_version == 3) {
      str_ftoc(fmt_buf2, sc_hostname, SC_HOSTNAME_LEN);
      printf("HOTP: %s %s\n", fmt_buf2, fmt_buf);
    }

    if (get_hotp_version == 1) {
      printf("HOTP: %s\n", fmt_buf);
    }
      
  } else if (r == 1) {
    printf("HOTP: rejected\n");
  } else {
    xerr_errx(1, err_msg);
  }

main_out:

  scr_ctx_free(scrctx);

  exit (0);

} /* main */

void help(void)
{
  fprintf(stderr, "otp-sct [-1hlpv?] [-c count] [-d debug_level] [-i index]\n");
  fprintf(stderr, "        [-r reader] [-v card_api_version]\n");
  fprintf(stderr, "        -1 : Use version 1 firmware GetHOTP\n");
  fprintf(stderr, "        -h : help\n");
  fprintf(stderr, "        -l : list SC readers\n");
  fprintf(stderr, "        -L : list hostnames\n");
  fprintf(stderr, "        -p : reset PIN\n");
  fprintf(stderr, "        -V : list SC firmware version\n");
} /* help */

