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
 *      $Id: otp-sca.c 144 2010-10-19 02:05:40Z maf $
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <getopt.h>
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

#define KEY_HEX160_LEN        40
#define KEY_HEX40_LEN         10

#define MODE_ADMIN_ENABLE     0x1
#define MODE_ADMIN_DISABLE    0x2
#define MODE_BALANCECARD_SET  0x4
#define MODE_HOST_GET         0x5
#define MODE_HOST_SET         0x6
#define MODE_HOSTNAME_GET     0x7
#define MODE_HOTP_GEN         0x8
#define MODE_PIN_SET          0x9
#define MODE_PIN_TEST         0xA
#define MODE_VERSION          0xB
#define MODE_ADMINKEY_SET     0xC
#define MODE_CAPABILITIES_GET 0xD
#define MODE_SC_CLEAR         0xE
#define MODE_SPYRUS_EE_GET    0xF
#define MODE_SPYRUS_EE_SET    0x10
#define MODE_READERKEY_SET    0x11

/* modifiers */
#define OPT_MOD_HOST        0x1
#define OPT_MOD_HOST_C      'h'
#define OPT_MOD_COUNT       0x2
#define OPT_MOD_COUNT_C     'c'
#define OPT_MOD_DB          0x4
#define OPT_MOD_DB_C        'd'
#define OPT_MOD_READERKEY   0x8
#define OPT_MOD_READERKEY_C 'r'

void help(void);
int parse_sc_hostdump(FILE *FP, uint8_t sc_fv, uint8_t *sc_idx,
  uint8_t *sc_count, uint8_t *sc_count32, char *sc_hostname,
  uint8_t *sc_hotpkey);
int key_hex160_load(char *key_hex160_fname, char *key_hex160);
int key_hex40_load(char *key_hex40_fname, char *key_hex40);

int parse_sc_spyrusEEProm(FILE *FP, uint8_t *sc_spyrusee_idx,
  uint8_t *sc_spyrusee_block);

#define BZS(A) bzero(A, sizeof A);

#define SWAP32(x) x = \
         ((((x)&0xff)<<24) |\
         (((x)&0xff00)<<8) |\
         (((x)&0xff0000)>>8) |\
         (((x)>>24)&0xff));

#define SWAP16(x) x = \
    ( (((x)&0xff)<<8) | (((x)&0xff00)>>8) );

static int debug;

/* XXX many of these +1 LEN's are not necessary */
int main(int argc, char **argv)
{
  extern char *ootp_version;
  struct scr_ctx *scrctx;
  int i, j, k, r, mode, sc_idx_set, j_start, j_end, done, sc_idx_tmp, opt_mod;
  int no_PIN, list_readers, opt_version;
  uint32_t tmp_count, tmp_cap, tmp32u;
  uint64_t tmp64u;
  char sc_hostname[SC_HOSTNAME_LEN+1], sc_PIN[SC_PIN_LEN+1];
  char sc_newPIN[SC_PIN_LEN+1], sc_newPIN2[SC_PIN_LEN+1];
  char fmt_buf[133];
  uint8_t sc_hotp[SC_HOTP_LEN+1], sc_idx[SC_INDEX_LEN+1];
  uint8_t sc_version[SC_VERSION_LEN+1], sc_adminkey[SC_ADMINKEY_LEN+1];
  uint8_t sc_count[SC_COUNT_LEN+1], sc_count32[SC_COUNT32_LEN+1];
  uint8_t sc_hotpkey[SC_HOTPKEY_LEN+1], sc_adminmode[SC_ADMINMODE_LEN+1];
  uint8_t sc_capabilities[SC_CAPABILITIES_LEN+1];
  uint8_t sc_spyrusee_idx[SC_SPYRUSEEIDX_LEN];
  uint8_t sc_spyrusee_block[SC_SPYRUSEEBLOCK_LEN];
  uint8_t sc_fv, sc_count_len, tmp8u;
  uint8_t sc_readerkey[SC_READERKEY_LEN+1];
  char key_hex160[KEY_HEX160_LEN+1], key_hex40[KEY_HEX40_LEN+1];
  char *adminkey_hex160_fname, *endptr, *err_msg, *username, *reader;
  char *readerkey_hex40_fname;

  struct option longopts[] = {
    { "sc-admin-key",               1, (void*)0L, 'a'},
    { "sc-count",                   1, (void*)0L, 'c'},
    { "debug",                      1, (void*)0L, 'd'},
    { "help",                       0, (void*)0L, 'h'},
    { "help",                       0, (void*)0L, '?'},
    { "sc-index",                   1, (void*)0L, 'i'},
    { "list-readers",               0, (void*)0L, 'l'},
    { "sc-command",                 1, (void*)0L, 'm'},
    { "sc-command-modifier",        1, (void*)0L, 'M'},
    { "no-pin",                     0, (void*)0L, 'p'},
    { "reader",                     1, (void*)0L, 'r'},
    { "sc-reader-key",              1, (void*)0L, 'R'},
    { "sc-username",                1, (void*)0L, 'u'},
    { "sc-version",                 1, (void*)0L, 'v'},
    { "version",                    0, &opt_version, 1},
    { 0, 0, 0, 0},
  };

  /* init xerr */
  xerr_setid(argv[0]);

  no_PIN = 0;
  debug = 0;
  mode = 0;
  opt_mod = 0;
  sc_idx_set = 0;
  opt_version = 0;
  adminkey_hex160_fname = (char*)0L;
  readerkey_hex40_fname = (char*)0L;
  sc_fv = 5;
  tmp_count = 0;
  username = "USER";
  list_readers = 0; /* no */
  scrctx = (struct scr_ctx*)0L;
  reader = (char*)0L;

  BZS(sc_hotp);
  BZS(sc_idx);
  BZS(sc_version);
  BZS(sc_adminkey);
  BZS(sc_count);
  BZS(sc_count32);
  BZS(sc_hotpkey);
  BZS(sc_hostname);
  BZS(sc_adminmode);
  BZS(sc_PIN);
  BZS(sc_newPIN);
  BZS(sc_capabilities);
  BZS(key_hex160);
  BZS(key_hex40);

  bcopy(SC_READERKEY_DEFAULT, sc_readerkey, SC_READERKEY_LEN);
  bcopy(SC_PIN_DEFAULT, sc_PIN, SC_PIN_LEN);
  bcopy(SC_PIN_DEFAULT, sc_newPIN, SC_PIN_LEN);
  bcopy(SC_ADMINKEY_DEFAULT, sc_adminkey, SC_ADMINKEY_LEN);

  while ((i = getopt_long(argc, argv, "a:c:d:h?i:lm:M:pr:R:u:v:", longopts,
    (int*)0L)) != -1) {

    switch (i) {

      case 'a':
        adminkey_hex160_fname = optarg;
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

      case 'm':
        if (!strcasecmp(optarg, "version")) {
          mode = MODE_VERSION;
        } else if (!strcasecmp(optarg, "PIN-test")) {
          mode = MODE_PIN_TEST;
        } else if (!strcasecmp(optarg, "PIN-set")) {
          mode = MODE_PIN_SET;
        } else if (!strcasecmp(optarg, "hotp-generate")) {
          mode = MODE_HOTP_GEN;
        } else if (!strcasecmp(optarg, "hotp-gen")) {
          mode = MODE_HOTP_GEN;
        } else if (!strcasecmp(optarg, "hostname-get")) {
          mode = MODE_HOSTNAME_GET;
        } else if (!strcasecmp(optarg, "host-set")) {
          mode = MODE_HOST_SET;
        } else if (!strcasecmp(optarg, "host-get")) {
          mode = MODE_HOST_GET;
        } else if (!strcasecmp(optarg, "balancecard-set")) {
          mode = MODE_BALANCECARD_SET;
        } else if (!strcasecmp(optarg, "admin-disable")) {
          mode = MODE_ADMIN_DISABLE;
        } else if (!strcasecmp(optarg, "admin-enable")) {
          mode = MODE_ADMIN_ENABLE;
        } else if (!strcasecmp(optarg, "adminkey-set")) {
          mode = MODE_ADMINKEY_SET;
        } else if (!strcasecmp(optarg, "capabilities-get")) {
          mode = MODE_CAPABILITIES_GET;
        } else if (!strcasecmp(optarg, "sc-clear")) {
          mode = MODE_SC_CLEAR;
        } else if (!strcasecmp(optarg, "spyrus-ee-get")) {
          mode = MODE_SPYRUS_EE_GET;
        } else if (!strcasecmp(optarg, "spyrus-ee-set")) {
          mode = MODE_SPYRUS_EE_SET;
        } else if (!strcasecmp(optarg, "reader-key-set")) {
          mode = MODE_READERKEY_SET;
        } else {
          fprintf(stderr, "Unknown mode.\n");
          help();
          exit(1);
        }
        break; /* notreached */

      case 'M':
        for (j = 0; j < strlen(optarg); ++j) {
          if (optarg[j] == OPT_MOD_HOST_C)
            opt_mod |= OPT_MOD_HOST;
          else if (optarg[j] == OPT_MOD_COUNT_C)
            opt_mod |= OPT_MOD_COUNT;
          else if (optarg[j] == OPT_MOD_DB_C)
            opt_mod |= OPT_MOD_DB;
          else if (optarg[j] == OPT_MOD_READERKEY_C)
            opt_mod |= OPT_MOD_READERKEY;
          else
            xerr_errx(1, "Unknown modifier %c.", optarg[j]);
        } /* j */
        break;

      case 'p':
        no_PIN = 1;
        break;

      case 'r':
        reader = optarg;
        break;

      case 'R':
        readerkey_hex40_fname = optarg;
        break;

      case 'u':
        username = optarg;
        if (strlen(username) > OTP_USER_NAME_LEN)
          xerr_errx(1, "strlen(username) > OTP_USER_NAME_LEN.");
        break;

      case 'v':
        sc_fv = strtoul(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoul(%s): failed at %c.", optarg, *endptr);
        break;

     case 0:
        if (opt_version) {
          printf("%s\n", ootp_version);
          exit(0);
        }

     default:
        xerr_errx(1, "getopt_long(): fatal.");

    } /* switch */

  } /* while getopt_long() */

  /* work to do? */
  if (!mode && !list_readers) {
    xerr_warnx("Unknown mode.");
    help();
    exit(1);
  }

  /* modifier available for specific modes */
  if ((opt_mod & OPT_MOD_DB) && (mode != MODE_HOST_GET))
    xerr_errx(1, "Mode and Modifier inconsistent.");

  if (((opt_mod & OPT_MOD_COUNT) || (opt_mod & OPT_MOD_HOST) ||
       (opt_mod & OPT_MOD_READERKEY)) &&
       (mode != MODE_HOTP_GEN))
    xerr_errx(1, "Mode and Modifier inconsistent.");

  /* get reader pin? */
  if ((mode == MODE_READERKEY_SET) || (opt_mod & OPT_MOD_READERKEY)) {

    while (1) {

      if (readerkey_hex40_fname) {

        if (key_hex40_load(readerkey_hex40_fname, key_hex40) < 0)
          xerr_errx(1, "key_hex40_load(): failed.");

      } else {

        if (str_input("40 bit Reader Key (hex): ", key_hex40,
          KEY_HEX40_LEN+1, STR_FLAGS_ECHO_OFF) < 0)
          xerr_errx(1, "str_input(40): failed.");

      }

      if (strlen(key_hex40) != KEY_HEX40_LEN) {
        xerr_warnx("40 bits required.");
        continue;
      }

      if (str_hex_decode(key_hex40, KEY_HEX40_LEN, sc_readerkey,
        SC_READERKEY_LEN) == -1) {
        xerr_warnx("str_hex_decode(): failed.");

      } else {

        break;

      } /* str_hex_decode */

    } /* while */

  } /* MODE_READERKEY_SET */

  /* get admin secret? */
  if ((mode == MODE_ADMIN_ENABLE) ||
      (mode == MODE_ADMIN_DISABLE) ||
      (mode == MODE_ADMINKEY_SET)) {

    while (1) {

      if (adminkey_hex160_fname) {

        if (key_hex160_load(adminkey_hex160_fname, key_hex160) < 0) {
          xerr_errx(1, "key_hex160_load(): failed.");
        }

      } else {

        if (str_input("160 bit Admin Key (hex): ", key_hex160,
          KEY_HEX160_LEN+1, STR_FLAGS_ECHO_OFF) < 0)
          xerr_errx(1, "str_input(160): failed.");

      }

      if (strlen(key_hex160) != KEY_HEX160_LEN) {
        xerr_warnx("160 bits required.");
        continue;
      }

      if (str_hex_decode(key_hex160, KEY_HEX160_LEN, sc_adminkey,
        SC_ADMINKEY_LEN) == -1) {
        xerr_warnx("str_hex_decode(): failed.");

      } else {

        break;

      } /* str_hex_decode */

    } /* read admin key */

  } /* need admin key */


  /* get PIN? */
  if ((!no_PIN) &&
      ((mode == MODE_HOSTNAME_GET) ||
      (mode == MODE_HOTP_GEN) ||
      (mode == MODE_PIN_SET) ||
      (mode == MODE_PIN_TEST))) {

    while (1) {

      if (str_input("Enter PIN: ", sc_PIN, SC_PIN_LEN+1,
        STR_FLAGS_ECHO_OFF) < 0)
        xerr_errx(1, "str_input(%d): failed.", SC_PIN_LEN);

      if (strlen((char*)sc_PIN) != SC_PIN_LEN) {

        xerr_warnx("PIN Must be %d characters", SC_PIN_LEN);
        continue;

      } else {

        break;

      } /* SC_PIN_LEN */

    } /* valid PIN len */

  } /* get PIN */

  /* get new PIN? */
  if (mode == MODE_PIN_SET) {

     while (1) {

      if (str_input("New PIN: ", sc_newPIN, SC_PIN_LEN+1,
        STR_FLAGS_ECHO_OFF) < 0)
        xerr_errx(1, "str_input(%d): failed.", SC_PIN_LEN);

      if (strlen((char*)sc_newPIN) != SC_PIN_LEN) {
        xerr_warnx("PIN Must be %d characters.", SC_PIN_LEN);
        continue;
      }

      if (str_input("New PIN (again): ", sc_newPIN2, SC_PIN_LEN+1,
        STR_FLAGS_ECHO_OFF) < 0)
        xerr_errx(1, "str_input(%d): failed.", SC_PIN_LEN);

      /* identical? then done */
      if (!bcmp(sc_newPIN,sc_newPIN2, SC_PIN_LEN))
        break;

      printf("New PIN did not match, try again.\n");

    } /* new PIN confirm */

  } /* MODE_PIN_SET */

  if (!(scrctx = scr_ctx_new(SCR_READER_EMBEDDED_ACR30S|SCR_READER_PCSC,
    debug))) {
    xerr_errx(1, "scr_ctx_new(): failed");
  }

  if (list_readers) {

    for (i = 0; i < scrctx->num_readers; ++i)
      printf("%s\n", scrctx->readers[i]);

    goto main_out;

  }

  if (scr_ctx_connect(scrctx, reader) < 0) {
    xerr_errx(1, "scr_ctx_connect(): failed");
  }

/****************/

  if (mode == MODE_VERSION) {

    if ((r = sccmd_GetVersion(scrctx, sc_fv, sc_version)) < 0)
      xerr_errx(1, "sccmd_GetVersion(): failed.");

    if (r == 0) {
      str_hex_dump(fmt_buf, sc_version, 1);
      printf("Version: 0x%s\n", fmt_buf);
    } else if (r == 1) {
      printf("Version: fail\n");
    } else {
      xerr_errx(1, "sccmd_GetVersion(): fatal.");
    }

  } /* MODE_VERSION */

  if (mode == MODE_SC_CLEAR) {

    if ((r = sccmd_ClearAll(scrctx, sc_fv)) < 0)
      xerr_errx(1, "sccmd_ClearAll(): failed.");

    if (r == 0)
      printf("SC Cleared.\n");
    else if (r == 1)
      printf("SC Clear fail.\n");
    else
      xerr_errx(1, "sccmd_ClearAll(): fatal.");

  } /* MODE_SC_CLEAR */

  if (mode == MODE_CAPABILITIES_GET) {

    if ((r = sccmd_GetCapabilities(scrctx, sc_fv, sc_capabilities)) < 0)
      xerr_errx(1, "sccmd_GetCapabilities(): failed.");

    if (r == 0) {

      str_hex_dump(fmt_buf, sc_capabilities, 4);

      printf("Capabilities: 0x%s:", fmt_buf);

      bcopy(sc_capabilities, &tmp_cap, sizeof tmp_cap);

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP32(tmp_cap);
#endif /* LITTLE_ENDIAN */

      if (tmp_cap & SC_PRDISPLAY_CAP)
        printf(" %s", SC_PRDISPLAY_STR);

      if (tmp_cap & SC_SETHOST_CAP)
        printf(" %s", SC_SETHOST_STR);

      if (tmp_cap & SC_GETHOST_CAP)
        printf(" %s", SC_GETHOST_STR);

      if (tmp_cap & SC_GETHOSTNAME_CAP)
        printf(" %s", SC_GETHOSTNAME_STR);

      if (tmp_cap & SC_GETHOTP_CAP)
        printf(" %s", SC_GETHOTP_STR);

      if (tmp_cap & SC_SETADMINMODE_CAP)
        printf(" %s", SC_SETADMINMODE_STR);

      if (tmp_cap & SC_SETBALANCECARDINDEX_CAP)
        printf(" %s", SC_SETBALANCECARDINDEX_STR);

      if (tmp_cap & SC_SETPIN_CAP)
        printf(" %s", SC_SETPIN_STR);

      if (tmp_cap & SC_TESTPIN_CAP)
        printf(" %s", SC_TESTPIN_STR);

      if (tmp_cap & SC_GETVERSION_CAP)
        printf(" %s", SC_GETVERSION_STR);

      if (tmp_cap & SC_SETADMINKEY_CAP)
        printf(" %s", SC_SETADMINKEY_STR);

      if (tmp_cap & SC_SETHOST32_CAP)
        printf(" %s", SC_SETHOST32_STR);

      if (tmp_cap & SC_GETHOST32_CAP)
        printf(" %s", SC_GETHOST32_STR);

      if (tmp_cap & SC_GETHOTPCOUNT32_CAP)
        printf(" %s", SC_GETHOTPCOUNT32_STR);

      if (tmp_cap & SC_GETHOTPHOST_CAP)
        printf(" %s", SC_GETHOTPHOST_STR);

      if (tmp_cap & SC_GETHOTPHOSTCOUNT32_CAP)
        printf(" %s", SC_GETHOTPHOSTCOUNT32_STR);

      if (tmp_cap & SC_GETCAPABILITIES_CAP)
        printf(" %s", SC_GETCAPABILITIES_STR);

      if (tmp_cap & SC_CLEARALL_CAP)
        printf(" %s", SC_CLEARALL_STR);

      if (tmp_cap & SC_SETREADERKEY_CAP)
        printf(" %s", SC_GETCAPABILITIES_STR);

      printf("\n");

    } else if (r == 1) {
      printf("GetCapabilities: fail\n");
    } else {
      xerr_errx(1, "sccmd_GetCapabilities(): fatal.");
    }

  } /* MODE_CAPABILITIES_GET */

/****************/

  if (mode == MODE_PIN_TEST) {

    if ((r = sccmd_TestPIN(scrctx, sc_fv, sc_PIN)) < 0)
      xerr_errx(1, "sccmd_TestPIN(): failed.");

    if (r == 0)
      printf("PIN Good.\n");
    else if (r == 1)
      printf("PIN Bad.\n");
    else
      xerr_errx(1, "sccmd_TestPIN(): fatal.");

  } /* MODE_PIN_TEST */

/****************/

  if (mode == MODE_PIN_SET) {

    if ((r = sccmd_SetPIN(scrctx, sc_fv, sc_PIN, sc_newPIN)) < 0)
      xerr_errx(1, "sccmd_SetPIN(): failed.");

    if (r == 0)
      printf("SetPIN Good.\n");
    else if (r == 1)
      printf("SetPIN Bad.\n");
    else
      xerr_errx(1, "sccmd_SetPIN(): fatal.");

  } /* MODE_PIN_SET */

  if (mode == MODE_HOTP_GEN) {

    /*
     * too many versions of generate HOTP
     */

    /* copy in reader key? */
    if (opt_mod & OPT_MOD_READERKEY)
      bcopy(sc_readerkey, sc_hotp, SC_READERKEY_LEN);

    if ((opt_mod & OPT_MOD_COUNT) && (tmp_count == 0))
      xerr_warnx("count modifier set, no count input.  Using count=0.");

    /* 00 */
    if ((!(opt_mod & OPT_MOD_HOST)) && (!(opt_mod & OPT_MOD_COUNT))) {

      if ((r = sccmd_GetHOTP(scrctx, sc_fv, sc_idx, sc_PIN, sc_hotp)) < 0)
        xerr_errx(1, "sccmd_GetHOTP(): failed.");
      
      err_msg = "sccmd_GetHOTP(): fatal.";

    /* 01 */
    } else if ((!(opt_mod & OPT_MOD_HOST)) && (opt_mod & OPT_MOD_COUNT)) {

      if ((r = sccmd_GetHOTPCount32(scrctx, sc_fv, sc_idx, sc_PIN, sc_count32,
        sc_hotp)) < 0)
        xerr_errx(1, "sccmd_GetHOTPCount32(): failed.");
      
      err_msg = "sccmd_GetHOTPCount32(): fatal.";

    /* 10 */
    } else if ((opt_mod & OPT_MOD_HOST) && (!(opt_mod & OPT_MOD_COUNT))) {

      if ((r = sccmd_GetHOTPHost(scrctx, sc_fv, sc_idx, sc_PIN, sc_hotp,
        sc_hostname)) < 0)
        xerr_errx(1, "sccmd_GetHOTPHost(): failed.");
     
      err_msg = "sccmd_GetHOTPHost(): fatal.";

    /* 11 */
    } else if ((opt_mod & OPT_MOD_HOST) && (opt_mod & OPT_MOD_COUNT)) {

      if ((r = sccmd_GetHOTPHostCount32(scrctx, sc_fv, sc_idx, sc_PIN,
        sc_count32, sc_hotp, sc_hostname)) < 0)
        xerr_errx(1, "sccmd_GetHOTPHostCount32(): failed.");
      
      err_msg = "sccmd_GetHOTPHostCount32(): fatal.";
    }

    /* successful SC transaction? */
    if (r == 0) {

      if (sc_hostname[HOSTNAME_POS_FMT] & HOSTNAME_FLAG_MASK) {

        tmp32u = (sc_hotp[0] << 24) | (sc_hotp[1] << 16) |
                 (sc_hotp[2] << 8) | sc_hotp[3];

        k = str_uint32toa(fmt_buf, tmp32u);

      } else {

        k = str_hex_dump(fmt_buf, sc_hotp, 5);

      }

      for (i = 0, j = 0; i < SC_HOSTNAME_LEN; ++i) {

        /* high bit flag set? */
        if (sc_hostname[i] & HOSTNAME_FLAG_MASK) {

          if ((i == HOSTNAME_POS_CHALLENGE) && (!(opt_mod & OPT_MOD_COUNT))) {
            xerr_warnx("need_count flag set and count not in SC transaction.");

          } else if ((i == HOSTNAME_POS_READERKEY) &&
                    (!(opt_mod & OPT_MOD_READERKEY))) {
            xerr_warnx("readerkey flag set and key not in SC transaction.");

          } else if ((i != HOSTNAME_POS_CHALLENGE) &&
                     (i != HOSTNAME_POS_READERKEY) &&
                     (i != HOSTNAME_POS_FMT) &&
                     (i != HOSTNAME_POS_FMT3) &&
                     (i != HOSTNAME_POS_FMT2) &&
                     (i != HOSTNAME_POS_FMT1) &&
                     (i != HOSTNAME_POS_FMT0)) {
            xerr_warnx("sc_hostname high bit set on byte %d.", i);
          }
        }

        /* clear high bit for display */
        sc_hostname[i] &= ~HOSTNAME_FLAG_MASK;

      }

      if (opt_mod & OPT_MOD_HOST) {
        strcpy(fmt_buf+k, " -- ");
        str_ftoc(fmt_buf+k+4, sc_hostname, SC_HOSTNAME_LEN);
      }

      printf("HOTP: %s\n", fmt_buf);
      
    } else if (r == 1) {

      printf("HOTP: rejected\n");

    } else {

      xerr_errx(1, err_msg);

   }

  } /* MODE_HOTP_GEN */

/****************/

  if (mode == MODE_HOSTNAME_GET) {

    /* if no index, iterate until empty hostname */
    if (sc_idx_set) {
      j_start = sc_idx[0];
      j_end = sc_idx[0];
    } else {
      j_start = 0, j_end = SC_INDEX_MAX;
    }

    for (j = j_start; j <= j_end; ++j) {

      sc_idx[0] = j;
  
      if ((r = sccmd_GetHostName(scrctx, sc_fv, sc_idx, sc_PIN,
        sc_hostname)) < 0)
        xerr_errx(1, "sccmd_GetHostName(): failed.");
  
      if (r == 0) {
  
        /* empty hostname is end of data */
        if (sc_hostname[0] == 0)
          break;
 
        str_hex_dump(fmt_buf, sc_idx, 1); 
        i = (1<<1); fmt_buf[i] = ','; i += 1;

        /* required reader key? */
        if (sc_hostname[HOSTNAME_POS_READERKEY] & HOSTNAME_FLAG_MASK) {

          fmt_buf[i++] = '*';
          fmt_buf[i++] = '*';

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

  } /* MODE_HOSTNAME_GET */
  
/****************/

  if (mode == MODE_ADMIN_ENABLE) {

    sc_adminmode[0] = SC_ADMIN_ENABLE;

    if ((r = sccmd_SetAdminMode(scrctx, sc_fv, sc_adminmode, sc_adminkey)) < 0)
      xerr_errx(1, "sccmd_SetAdminMode(): failed.");

    if (r == 0)
      printf("AdminMode: enabled.\n");
    else if (r == 1)
      printf("Set AdminMode: Fail\n");
    else
      xerr_errx(1, "sccmd_SetAdminMode(): fatal.");

  } /* MODE_ADMIN_ENABLE */

  if (mode == MODE_ADMIN_DISABLE) {

    sc_adminmode[0] = SC_ADMIN_DISABLE;

    if ((r = sccmd_SetAdminMode(scrctx, sc_fv, sc_adminmode, sc_adminkey)) < 0)
      xerr_errx(1, "sccmd_SetAdminMode(): failed.");

    if (r == 0)
      printf("AdminMode: disabled.\n");
    else if (r == 1)
      printf("Set AdminMode: Fail\n");
    else
      xerr_errx(1, "sccmd_SetAdminMode(): fatal.");

  } /* MODE_ADMIN_DISABLE */

/****************/


  if (mode == MODE_ADMINKEY_SET) {

    if ((r = sccmd_SetAdminKey(scrctx, sc_fv, sc_adminkey)) < 0)
      xerr_errx(1, "sccmd_SetAdminKey(): failed.");

    if (r == 0)
      printf("Set AdminKey: Done.\n");
    else if (r == 1)
      printf("Set AdminKey: Fail.\n");
    else
      xerr_errx(1, "sccmd_SetAdminKey(): fatal.");

  } /* MODE_ADMINKEY_SET */

/****************/

  if (mode == MODE_BALANCECARD_SET) {

    if (!sc_idx_set)
      sc_idx[0] = SC_BALANCECARD_DISABLE;

    if ((r = sccmd_SetBalanceCardIndex(scrctx, sc_fv, sc_idx)) < 0)
      xerr_errx(1, "sccmd_SetBalanceCardIndex(): failed.");

    if (r == 0) {

      if (sc_idx[0] == SC_BALANCECARD_DISABLE)
        printf("Disable BalanceCard: Done.\n");
      else
        printf("Set BalanceCardIndex: Done.\n");

    } else if (r == 1) {

      printf("Set BalanceCardIndex: Fail.\n");

    } else {

      xerr_errx(1, "sccmd_SetBalanceCardIndex(): fatal.");

    }

  } /* MODE_BALANCECARD_SET */

/****************/

  if (mode == MODE_HOST_GET) {

    if (opt_mod & OPT_MOD_DB)
      printf(
        "#version:user:key:status:format:type:flags:count_cur:count_ceil:last\n");
    else
      printf("#index:count:hostname:key\n");

    /* if no index, iterate until empty hostname */
    if (sc_idx_set) {
      j_start = sc_idx[0];
      j_end = sc_idx[0];
    } else {
      j_start = 0, j_end = SC_INDEX_MAX;
    }

    for (j = j_start; j <= j_end; ++j) {

      sc_idx[0] = j;

      if (sc_fv >= 3) {

        if ((r = sccmd_GetHost32(scrctx, sc_fv, sc_idx, sc_count32,
          sc_hostname, sc_hotpkey)) < 0)
          xerr_errx(1, "sccmd_GetHost32(): failed.");

        sc_count_len = SC_COUNT32_LEN;
        err_msg = "sccmd_GetHost32(): fatal.";

      } else if (sc_fv >= 1) {

        if ((r = sccmd_GetHost(scrctx, sc_fv, sc_idx, sc_count32, sc_hostname,
          sc_hotpkey)) < 0)
          xerr_errx(1, "sccmd_GetHost(): failed.");

        sc_count_len = SC_COUNT_LEN;
        err_msg = "sccmd_GetHost(): fatal.";

      }

      if (r == 0) {

        /* empty hostname is end of data */
        if (sc_hostname[0] == 0)
          break;

        /* output in otpd friendly db load format? */
        if (opt_mod & OPT_MOD_DB) {

          tmp8u = 0x01;

          /* version */
          str_hex_dump(fmt_buf, (uint8_t*)&tmp8u, 1);
          i = (1<<1); fmt_buf[i] = ':'; i += 1;

          /* username */
          for (k = 0; k < strlen(username); ++k)
            fmt_buf[i++] = username[k];
          fmt_buf[i++] = ':';

          /* key */
          str_hex_dump(fmt_buf+i, sc_hotpkey, SC_HOTPKEY_LEN);
          i += (SC_HOTPKEY_LEN<<1); fmt_buf[i++] = ':';

          /* status */
          tmp8u = OTP_STATUS_ACTIVE;
          str_hex_dump(fmt_buf+i, (uint8_t*)&tmp8u, 1);
          i += (1<<1); fmt_buf[i++] = ':';

          /* format */
          tmp8u = OTP_FORMAT_HEX40;
          str_hex_dump(fmt_buf+i, (uint8_t*)&tmp8u, 1);
          i += (1<<1); fmt_buf[i++] = ':';

          /* type */
          tmp8u = OTP_TYPE_HOTP;
          str_hex_dump(fmt_buf+i, (uint8_t*)&tmp8u, 1);
          i += (1<<1); fmt_buf[i++] = ':';

          /* flags */
          /*  OTP_USER_FLAGS_DSPCNT is set if CHALLENGE flag is set in SC */
          tmp8u = (sc_hostname[HOSTNAME_POS_CHALLENGE] & HOSTNAME_FLAG_MASK);
          str_hex_dump(fmt_buf+i, (uint8_t*)&tmp8u, 1);
          i += (1<<1); fmt_buf[i++] = ':';

          /* count */
          /* pad to 64 bits */
          for (k = 0; k < (8-sc_count_len)<<1; ++k)
            fmt_buf[i++] = '0';
          str_hex_dump(fmt_buf+i, sc_count32, sc_count_len);
          i += (sc_count_len<<1); fmt_buf[i++] = ':';

          /* count_ceil */
          tmp64u = 0xFFFFFFFFFFFFFFFFLL;
          str_hex_dump(fmt_buf+i, (uint8_t*)&tmp64u, 8);
          i += (8<<1); fmt_buf[i++] = ':';

          /* last login */
          tmp64u = 0x0LL;
          str_hex_dump(fmt_buf+i, (uint8_t*)&tmp64u, 8);

          printf("%s\n", fmt_buf);

        /* sc load format */
        } else {

          /* index */
          str_hex_dump(fmt_buf, sc_idx, SC_INDEX_LEN);
          i = (SC_INDEX_LEN<<1); fmt_buf[i] = ':'; i += 1;

          /* count */
          /* pad to 32 bits */
          for (k = 0; k < (4-sc_count_len)<<1; ++k)
            fmt_buf[i++] = '0';
          str_hex_dump(fmt_buf+i, sc_count32, sc_count_len);
          i += (sc_count_len<<1); fmt_buf[i] = ':'; i += 1;

          /* hostname */
          str_hex_dump(fmt_buf+i, (uint8_t*)sc_hostname, SC_HOSTNAME_LEN);
          i += (SC_HOSTNAME_LEN<<1); fmt_buf[i] = ':'; i += 1;

          /* key */
          str_hex_dump(fmt_buf+i, sc_hotpkey, SC_HOTPKEY_LEN);

          printf("%s\n", fmt_buf);

        } /* OPT_MOD_DB */

      } else if (r == 1) {

        printf("GetHost: reject.\n");
        break;

      } else {

        xerr_errx(1, err_msg);

      } /* r */

    } /* for host */

  } /* MODE_HOST_GET */

/****************/

  if (mode == MODE_HOST_SET) {

    done = 0;

    while (!done) {

      if ((done = parse_sc_hostdump(stdin, sc_fv, sc_idx, sc_count,
        sc_count32, sc_hostname, sc_hotpkey)) < 0) {
        xerr_errx(1, "parse_sc_hostdump(): failed.");
      }

      /* empty input? */
      if (done == 1)
        break;

      if (sc_fv >= 3) {

        if ((r = sccmd_SetHost32(scrctx, sc_fv, sc_idx, sc_count32,
          sc_hostname, sc_hotpkey)) < 0)
          xerr_errx(1, "sccmd_SetHost32(): failed.");

        err_msg = "sccmd_SetHost32(): fail.";

      } else if (sc_fv >= 1) {

        if ((r = sccmd_SetHost(scrctx, sc_fv, sc_idx, sc_count, sc_hostname,
          sc_hotpkey)) < 0)
          xerr_errx(1, "sccmd_SetHost(): failed.");

        err_msg = "sccmd_SetHost(): fail.";

      }

      if (r == 0)
        printf("SetHost (%d): Done.\n", (int)sc_idx[0]);
      else if (r == 1)
        printf("SetHost (%d): Fail.\n", (int)sc_idx[0]);
      else
        xerr_errx(1, err_msg);

    } /* more input lines */

  } /* MODE_HOST_SET */

  if (mode == MODE_SPYRUS_EE_SET) {

    done = 0;

    while (!done) {

      if ((done = parse_sc_spyrusEEProm(stdin, sc_spyrusee_idx,
        sc_spyrusee_block)) < 0) {
        xerr_errx(1, "parse_sc_spyrusEEProm(): failed.");
      }

      /* empty input? */
      if (done == 1)
        break;

      if ((r = sccmd_SetSpyrusEEBlock(scrctx, sc_spyrusee_idx,
        sc_spyrusee_block)) < 0)
        xerr_errx(1, "sccmd_SetSpyrusEEBlock(): failed.");

      err_msg = "sccmd_SetHost(): fail.";


      if (r == 0)
        printf("SetSpyrusEEBlock (%d): Done.\n",
          (int)sc_spyrusee_idx[0] & ~HOSTNAME_FLAG_MASK);
      else if (r == 1)
        printf("SetSpyrusEEBlock (%d): Fail.\n",
          (int)sc_spyrusee_idx[0] & ~HOSTNAME_FLAG_MASK);
      else
        xerr_errx(1, err_msg);

    } /* more input lines */

  } /* MODE_SPYRUS_EE_SET */

  if (mode == MODE_SPYRUS_EE_GET) {

    printf("#index:block_data\n");

    /* foreach EE Block */
    for (j = 0; j < 16; ++j) {

      sc_spyrusee_idx[0] = j;

      if ((r = sccmd_GetSpyrusEEBlock(scrctx, sc_spyrusee_idx,
        sc_spyrusee_block)) < 0)
        xerr_errx(1, "sccmd_GetSpyrusEEBlock(): failed.");

      /* fail? */
       if (r)
         xerr_errx(1, "sccmd_GetSpyrusEEBlock(): fail.");

      str_hex_dump(fmt_buf, sc_spyrusee_idx, SC_SPYRUSEEIDX_LEN);
      i = (SC_INDEX_LEN<<1); fmt_buf[i] = ':'; i += 1;

      str_hex_dump(fmt_buf+i, sc_spyrusee_block, SC_SPYRUSEEBLOCK_LEN);

      printf("%s\n", fmt_buf);

      /* last? */
      if (sc_spyrusee_idx[0] & 0x80)
        break;

    }

  } /* MODE_SPYRUS_EE_GET */

  if (mode == MODE_READERKEY_SET) {

    if ((r = sccmd_SetReaderKey(scrctx, sc_readerkey)) < 0)
      xerr_errx(1, "sccmd_SetReaderKey(): failed.");

    if (r == 0)
      printf("Reader Key Set.\n");
    else if (r == 1)
      printf("Reader Key not Set.\n");
    else
      xerr_errx(1, "sccmd_SetReaderKey(): fatal.");

  } /* MODE_READERKEY_SET */

main_out:

  scr_ctx_free(scrctx);

  exit (0);

} /* main */

int key_hex160_load(char *key_hex160_fname, char *key_hex160)
{
  int fd, n;

  if ((fd = open(key_hex160_fname, O_RDONLY)) < 0) {
    xerr_err(1, "open(%s):", key_hex160_fname);
  }

  if ((n = read(fd, key_hex160, KEY_HEX160_LEN)) < 0) {
    xerr_err(1, "read(%s):", key_hex160_fname);
  }

  if (n != KEY_HEX160_LEN) {
    xerr_errx(1, "Short read, expecting %d bytes in %s.", KEY_HEX160_LEN,
      key_hex160_fname);
  }

  close (fd);

  return 0;

} /* key_hex160_load */

int key_hex40_load(char *key_hex40_fname, char *key_hex40)
{
  int fd, n;

  if ((fd = open(key_hex40_fname, O_RDONLY)) < 0) {
    xerr_err(1, "open(%s):", key_hex40_fname);
  }

  if ((n = read(fd, key_hex40, KEY_HEX40_LEN)) < 0) {
    xerr_err(1, "read(%s):", key_hex40_fname);
  }

  if (n != KEY_HEX40_LEN) {
    xerr_errx(1, "Short read, expecting %d bytes in %s.", KEY_HEX40_LEN,
      key_hex40_fname);
  }

  close (fd);

  return 0;

} /* key_hex40_load */

#define CHK_STRLEN(N,L,G)\
  n = strlen(f);\
  if (n != L) {\
    if (debug)\
      xerr_warnx("parse_sc_hostdump(): %s length expecting %d, got %d.", N, L, n);\
    goto G;\
  }

#define HEX_DECODE(N,V,E,G)\
  if (str_hex_decode(f, E, (uint8_t*)V, E>>1) < 0) {\
    if (debug)\
      xerr_warnx("parse_sc_hostdump(): str_hex_decode(%s): failed.", N);\
    goto G;\
  }

#define NXT_FIELD(N,G)\
  f = strsep(&bufp, ":");\
  if (!f) {\
    xerr_warnx("parse_sc_hostdump(): expecting %s", N);\
    goto G;\
  }\

int parse_sc_hostdump(FILE *FP, uint8_t sc_fv, uint8_t *sc_idx,
  uint8_t *sc_count, uint8_t *sc_count32, char *sc_hostname,
  uint8_t *sc_hotpkey)
{
  char buf[1024], *f, *c, *bufp;
  int nl, sc_count_max, n, ret;
  uint32_t tmp_count32;

  ret = -1; /* fail */

  if (sc_fv >= 3)
    sc_count_max = SC_COUNT32_MAX;
  else if (sc_fv >= 1)
    sc_count_max = SC_COUNT_MAX;
  else
    xerr_errx(1, "sc_fv failed assertion.");

  while (1) {

    /* grab a line */
    if (!fgets(buf, 1024, FP))
      return 1;

    /* got \n? */
    nl = 0;

    /* \n is end of string */
    for (f = buf; *f; ++f) {
      if (*f == '\n') {
        *f = 0;
        nl = 1;
        break;
      }
    }

    if (nl == 0) {
      xerr_warnx("fgets(): no \\n.");
      return -1;
    }

    if (debug)
      printf("line: %s\n", buf);

    /* skip leading whitespace */
    for (c = buf; *c && isspace(*c); ++c);

    /* comment lines */
    if (*c == '#')
      continue;

    break;

  } /* get a non comment line */

  /* work with pointer to buf */
  bufp = buf;

  NXT_FIELD("idx", parse_sc_hostdump_out);
  CHK_STRLEN("idx", SC_INDEX_LEN<<1, parse_sc_hostdump_out);
  HEX_DECODE("idx", sc_idx, SC_INDEX_LEN<<1, parse_sc_hostdump_out);

  if (sc_idx[0] > SC_INDEX_MAX) {
    xerr_warnx("parse_sc_hostdump(): fail idx > SC_INDEX_MAX.");
    goto parse_sc_hostdump_out;
  }

  NXT_FIELD("count", parse_sc_hostdump_out);
  CHK_STRLEN("count", SC_COUNT32_LEN<<1, parse_sc_hostdump_out);
  HEX_DECODE("count", sc_count32, SC_COUNT32_LEN<<1, parse_sc_hostdump_out);

  bcopy(sc_count32, &tmp_count32, sizeof tmp_count32);
  bcopy(sc_count32+2, sc_count, SC_COUNT_LEN);

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP32(tmp_count32);
#endif /* LITTLE_ENDIAN */

  if (tmp_count32 > sc_count_max) {
    xerr_warnx("parse_sc_hostdump(): count > count_max (%d>%d).",
      tmp_count32, sc_count_max);
      goto parse_sc_hostdump_out;
  }

  NXT_FIELD("hostname", parse_sc_hostdump_out);
  CHK_STRLEN("hostname", SC_HOSTNAME_LEN<<1, parse_sc_hostdump_out);
  HEX_DECODE("hostname", sc_hostname, SC_HOSTNAME_LEN<<1,
    parse_sc_hostdump_out);

  NXT_FIELD("key", parse_sc_hostdump_out);
  CHK_STRLEN("key", SC_HOTPKEY_LEN<<1, parse_sc_hostdump_out);
  HEX_DECODE("key", sc_hotpkey, SC_HOTPKEY_LEN<<1, parse_sc_hostdump_out);

  /* no more */
  f = strsep(&bufp, ":");

  if (!f)
    ret = 0;
  else
    xerr_warnx("parse_sc_hostdump(): trailing input.");

parse_sc_hostdump_out:

  return ret;

} /* parse_sc_hostdump */

int parse_sc_spyrusEEProm(FILE *FP, uint8_t *sc_spyrusee_idx,
  uint8_t *sc_spyrusee_block)
{
  char buf[1024], *f, *c, *bufp;
  int nl, n, ret;

  ret = -1; /* fail */

  while (1) {

    /* grab a line */
    if (!fgets(buf, 1024, FP))
      return 1;

    /* got \n? */
    nl = 0;

    /* \n is end of string */
    for (f = buf; *f; ++f) {
      if (*f == '\n') {
        *f = 0;
        nl = 1;
        break;
      }
    }

    if (nl == 0) {
      xerr_warnx("fgets(): no \\n.");
      return -1;
    }

    if (debug)
      printf("line: %s\n", buf);

    /* skip leading whitespace */
    for (c = buf; *c && isspace(*c); ++c);

    /* comment lines */
    if (*c == '#')
      continue;

    break;

  } /* get a non comment line */

  /* work with pointer to buf */
  bufp = buf;

  NXT_FIELD("spyrusee_idx", parse_sc_spyrusEEProm_out);
  CHK_STRLEN("spyrusee_idx", SC_SPYRUSEEIDX_LEN<<1, parse_sc_spyrusEEProm_out);
  HEX_DECODE("spyrusee_idx", sc_spyrusee_idx, SC_SPYRUSEEIDX_LEN<<1,
    parse_sc_spyrusEEProm_out);

  NXT_FIELD("spyrusee_block", parse_sc_spyrusEEProm_out);
  CHK_STRLEN("spyrusee_block", SC_SPYRUSEEBLOCK_LEN<<1,
    parse_sc_spyrusEEProm_out);
  HEX_DECODE("spyrusee_block", sc_spyrusee_block, SC_SPYRUSEEBLOCK_LEN<<1,
    parse_sc_spyrusEEProm_out);

  /* no more */
  f = strsep(&bufp, ":");

  if (!f)
    ret = 0;
  else
    xerr_warnx("parse_sc_hostdump(): trailing input.");

parse_sc_spyrusEEProm_out:

  return ret;

} /* parse_sc_spyrusEEProm */

void help(void)
{
  fprintf(stderr, "otp-sca [-hlp?] [-a admin_keyfile] [-c count] [-d debug_level]\n");
  fprintf(stderr, "        [-i index] [-m command_mode] [-M modifiers] [-r reader]\n");
  fprintf(stderr, "        [-R reader_keyfile] [-u username] [-v card_api_version]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "        -h : help\n");
  fprintf(stderr, "        -l : list SC readers\n");
  fprintf(stderr, "        -p : no PIN required\n\n");

  fprintf(stderr, "         Command Mode       Description                Notes    Modifiers\n");
  fprintf(stderr, "         ---------------------------------------------------------------\n");
  fprintf(stderr, "         admin-enable     - Enable Admin Mode          1\n");
  fprintf(stderr, "         admin-disable    - Disable Admin Mode\n");
  fprintf(stderr, "         adminkey-set     - Set Admin Key              1\n");
  fprintf(stderr, "         balancecard-set  - Set Balance Card Index     1\n");
  fprintf(stderr, "         capabilities-get - Get Capabilities\n");
  fprintf(stderr, "         host-get         - Get host entry             1,2,4    d\n");
  fprintf(stderr, "         host-set         - Set host entry             1,4\n");
  fprintf(stderr, "         hostname-get     - Get Hostname for Index     2,3\n");
  fprintf(stderr, "         hotp-gen         - Generate HOTP for Index    3        chr\n");
  fprintf(stderr, "         pin-set          - Set PIN                    3\n");
  fprintf(stderr, "         pin-test         - Test/Verify PIN            3\n");
  fprintf(stderr, "         reader-key-set   - Set Reader Key             1\n");
  fprintf(stderr, "         sc-clear         - Clear all SC data          1\n");
  fprintf(stderr, "         spyrus-ee-get    - Spyrus EEProm read         5\n");
  fprintf(stderr, "         spyrus-ee-set    - Spyrus EEProm write        5\n");
  fprintf(stderr, "         version          - Firmware version\n");
  fprintf(stderr, "\n");
  fprintf(stderr, " Notes (*):\n");
  fprintf(stderr, "   1 Admin Enable required.\n");
  fprintf(stderr, "   2 Iterate over all if no index specified.\n");
  fprintf(stderr, "   3 PIN or Admin Enable required.\n");
  fprintf(stderr, "   4 version 3 firmware supports 32 bit count, version 2 16 bit count.\n");
  fprintf(stderr, "   5 Spyrus customization SC firmware");
  fprintf(stderr, "\n");
  fprintf(stderr, " Modifiers: (version 3+ SC firmware)\n");
  fprintf(stderr, "   c pass count to SC.\n");
  fprintf(stderr, "   h return hostname from SC.\n");
  fprintf(stderr, "   d output in otpdb load friendly format.\n");
  fprintf(stderr, "   r include reader key in request.\n");
} /* help */
