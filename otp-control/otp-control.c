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
 *      $Id: otp-control.c 55 2009-12-17 01:59:35Z maf $
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include "otplib.h"
#include "otpsc.h"
#include "xerr.h"
#include "ffdb.h"
#include "str.h"

#define MODE_ADD                1
#define MODE_DUMP               5
#define MODE_GENERATE           6
#define MODE_LIST               7
#define MODE_LOAD               8
#define MODE_REMOVE             9
#define MODE_SET_COUNT          10
#define MODE_SET_COUNT_CEIL     11
#define MODE_TEST               12
#define MODE_CREATE             13
#define MODE_LIST_SC            18
#define MODE_SET_STATUS         19
#define MODE_SET_TYPE           20
#define MODE_SET_FORMAT         21
#define MODE_SET_FLAGS          22

#define KEY_HEX160_LEN          40

#define DEV_RANDOM "/dev/urandom"

int get_random(char *dev, unsigned char *entropy, int bits);

void help(void);

int main (int argc, char **argv)
{
  struct otp_ctx *otpctx;
  struct otp_user ou;
  int i, j, r, mode, window, db_flags, open_mode, open_op, verbose;
  char *otpdb_fname;
  uint64_t u_count, u_count_ceil, count_offset, tmp64u;
  uint8_t u_version, u_status, u_format, u_type, u_flags, sc_index;
  uint8_t sc_flags[SC_HOSTNAME_LEN];
  unsigned char u_key160[20];
  char key_hex160[KEY_HEX160_LEN+1];
  char crsp_tmp[11];
  char *u_username, *u_key_ascii, *sc_hostname;
  char *endptr, *i_status, *i_format, *i_type, *i_flags;

  otpdb_fname = OTP_DB_FNAME;
  sc_index = 0;
  mode = 0;
  window = 1;
  verbose = 0;
  db_flags = 0;
  /* user defaults */
  u_count = 0;
  u_count_ceil = 0xFFFFFFFFFFFFFFFFLL;
  u_version = OTP_VERSION;
  u_format = OTP_FORMAT_HEX40;
  u_type = OTP_TYPE_HOTP;
  u_status = OTP_STATUS_ACTIVE;
  u_flags = 0;
  u_username = (char*)0L;
  u_key_ascii = (char*)0L;
  endptr = (char*)0L;
  sc_hostname = (char*)0L;
  bzero(sc_flags, SC_HOSTNAME_LEN);
  i_status = i_type = i_format = i_flags = (char*)0L;

  /* init xerr */
  xerr_setid(argv[0]);

  while ((i = getopt(argc, argv, "c:C:hf:F:H:I:?k:m:no:s:S:t:u:w:v")) != -1) {

    switch (i) {

      case 'c':
        u_count = strtoull(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoull(%s): failed at %c.", optarg, *endptr);
        break;

      case 'C':
        u_count_ceil = strtoull(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoull(%s): failed at %c.", optarg, *endptr);
        break;

      case 'f':
        i_format = optarg;
        break;

      case 'F':
        if (str_setflag8(otp_flags_l, &u_flags, optarg, 0, OTP_FLAGS_BITS) < 0)
          xerr_errx(1, "Invalid flag %s.", optarg);
        break;

      case 'H':
        sc_hostname = optarg;
        if (strlen(sc_hostname) > SC_HOSTNAME_LEN)
          xerr_errx(1, "strlen(sc_hostname) > SC_HOSTNAME_LEN");
        break;

      case 'I':
        tmp64u = strtoull(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoull(%s): failed at %c.", optarg, *endptr);
        if (tmp64u > SC_INDEX_MAX)
          xerr_errx(1, "sc_index > SC_INDEX_MAX.");
        sc_index = tmp64u;
        break;

      case 'k':
        u_key_ascii = optarg;
        break;

      case 'm':
        if (mode)
          xerr_errx(1, "mode previously set.");

        if (!strcasecmp(optarg, "add")) {
          mode = MODE_ADD;
        } else if (!strcasecmp(optarg, "create")) {
          mode = MODE_CREATE;
        } else if (!strcasecmp(optarg, "dump")) {
          mode = MODE_DUMP;
        } else if (!strcasecmp(optarg, "generate")) {
          mode = MODE_GENERATE;
        } else if (!strcasecmp(optarg, "list")) {
          mode = MODE_LIST;
        } else if (!strcasecmp(optarg, "list-sc")) {
          mode = MODE_LIST_SC;
        } else if (!strcasecmp(optarg, "load")) {
          mode = MODE_LOAD;
        } else if (!strcasecmp(optarg, "remove")) {
          mode = MODE_REMOVE;
        } else if (!strcasecmp(optarg, "set-count")) {
          mode = MODE_SET_COUNT;
        } else if (!strcasecmp(optarg, "set-count-ceil")) {
          mode = MODE_SET_COUNT_CEIL;
        } else if (!strcasecmp(optarg, "set-flags")) {
          mode = MODE_SET_FLAGS;
        } else if (!strcasecmp(optarg, "set-format")) {
          mode = MODE_SET_FORMAT;
        } else if (!strcasecmp(optarg, "set-status")) {
          mode = MODE_SET_STATUS;
        } else if (!strcasecmp(optarg, "set-type")) {
          mode = MODE_SET_TYPE;
        } else if (!strcasecmp(optarg, "test")) {
          mode = MODE_TEST;
        } else {
          xerr_errx(1, "Unknown mode %s.", optarg);
        }
        break;

      case 's':
        i_status = optarg;
        break;

      case 'S' :
        for (j = 0; j < strlen(optarg); ++j) {
          if (optarg[j] == '0')
            sc_flags[HOSTNAME_POS_CHALLENGE] = HOSTNAME_FLAG_MASK;
          else if (optarg[j] == '1')
            sc_flags[HOSTNAME_POS_READERKEY] = HOSTNAME_FLAG_MASK;
          else
            xerr_errx(1, "Unknown sc_flag %c.", optarg[j]);
        } /* j */
        break;

      case 't':
        i_type = optarg;
        break;

      case 'n':
        db_flags |= OTP_DB_CREATE_SOFT;
        break;

      case 'o':
        otpdb_fname = optarg;
        break;

      case 'u':
        u_username = optarg;
        break;

      case 'v':
        db_flags |= OTP_DB_VERBOSE;
        verbose = 1;
        break;

      case 'h':
      case '?':
        help();
        exit(0);

      case 'w':
        window = atoi(optarg);
        break;

    } /* switch */

  } /* while */

  if (!mode)
    xerr_errx(1, "No mode set.");

  /* username required for most modes */
  if ((mode != MODE_DUMP) && (mode != MODE_LOAD) && (mode != MODE_CREATE)) {
    if ((!u_username) || (!u_username[0])) {
      xerr_errx(1, "Username required.");
    }
  }

  /* smart card hostname field required for MODE_LIST_SC */
  if ((mode == MODE_LIST_SC) && (!sc_hostname))
    xerr_errx(1, "Hostname required.");

  /* check username length */
  if (u_username && (strlen(u_username) > OTP_USER_NAME_LEN))
    xerr_errx(1, "Username > OTP_USER_NAME_LEN.");

  /* input key */
  if (u_key_ascii && u_key_ascii[0] != '-')
    xerr_errx(1, "Key not accepted on command line, use - for stdin");

  /* format */
  if (i_format)
    if (str_find8(otp_format_l, &u_format, i_format, 1, OTP_FORMAT_MAX))
      xerr_errx(1, "Invalid format %s.", i_format);

  if ((mode == MODE_SET_FORMAT) && (!i_format))
    xerr_errx(1, "Format value not specified.");

  /* status */
  if (i_status)
    if (str_find8(otp_status_l, &u_status, i_status, 1, OTP_STATUS_MAX))
      xerr_errx(1, "Invalid status %s.", i_status);

  if ((mode == MODE_SET_STATUS) && (!i_status))
    xerr_errx(1, "Status value not specified.");

  /* type */
  if (i_type)
    if (str_find8(otp_type_l, &u_type, i_type, 1, OTP_TYPE_MAX))
      xerr_errx(1, "Invalid type %s.", i_type);

  if ((mode == MODE_SET_TYPE) && (!i_type))
    xerr_errx(1, "Type value not specified.");

  /* user specified key? need key material? */
  if (mode == MODE_ADD) {

    /* key not on command line (safe) */
    if (u_key_ascii && (u_key_ascii[0] == '-') && (u_key_ascii[1] == 0)) {

      if (str_input("160 bit shared key (hex): ", key_hex160,
        KEY_HEX160_LEN+1, STR_FLAGS_ECHO_OFF) < 0)
        xerr_errx(1, "str_input(160): failed.");
      
      if (strlen(key_hex160) != 40)
        xerr_errx(1, "Key failure, expecting 40 hex digits.");

      if (str_hex_decode(key_hex160, 40, u_key160, 20) == -1)
        xerr_errx(1, "str_hex_decode(%s): failed.", key_hex160);

    } else {

      if (verbose)
        printf("Generating random 160 bit key.\n");
      if (get_random(DEV_RANDOM, u_key160, 160) < 0)
        xerr_errx(1, "get_random(): failed.");

    }

  } /* MODE_ADD */

  if (mode == MODE_CREATE) {
    db_flags |= OTP_DB_CREATE;
  }

  if (!(otpctx = otp_db_open(otpdb_fname, db_flags))) {
    xerr_errx(1, "otp_db_open(): failed.");
  }

  if (mode == MODE_CREATE) {
    printf("Created db %s.\n", otpdb_fname);
    goto mode_done;
  }

  if (mode == MODE_DUMP) {
    if (otp_db_dump(otpctx, u_username) < 0)
      xerr_errx(1, "otp_db_dump(): failed.");
    goto mode_done;
  } /* MODE_DUMP */

  if (mode == MODE_LOAD) {
    if (otp_db_load(otpctx, u_username) < 0)
      xerr_errx(1, "otp_db_load(): failed.");
    goto mode_done;
  } /* MODE_LOAD */

  if (mode == MODE_ADD) {
    printf("Adding user %s.\n", u_username);
    if (otp_user_add(otpctx, u_username, u_key160, OTP_HOTP_KEY_SIZE,
      u_count, u_count_ceil, u_status, u_type, u_format, u_version))
      xerr_errx(1, "otp_user_add(): failed.");
    goto mode_done;
  } /* MODE_ADD */

  if (mode == MODE_REMOVE) {
    printf("Removing user %s.\n", u_username);
    if (otp_user_rm(otpctx, u_username) < 0)
      xerr_errx(1, "ot_user_rm(): failed.");
    goto mode_done;
  } /* MODE_REMOVE */

  /*
   * modes requiring open and get of user record:
   */
  if ((mode == MODE_GENERATE) ||
      (mode == MODE_LIST) ||
      (mode == MODE_LIST_SC) ||
      (mode == MODE_SET_COUNT) ||
      (mode == MODE_SET_COUNT_CEIL) ||
      (mode == MODE_SET_FLAGS) ||
      (mode == MODE_SET_FORMAT) ||
      (mode == MODE_SET_STATUS) ||
      (mode == MODE_SET_TYPE) ||
      (mode == MODE_TEST)) {

    /* rw or ro? */
    if ((mode == MODE_LIST) || (mode==MODE_LIST_SC)) {
      open_mode = O_RDONLY;
      open_op = FFDB_OP_LOCK_SH;
    } else {
      open_mode = O_RDWR;
      open_op = FFDB_OP_LOCK_EX;
    }

    if (otp_urec_open(otpctx, u_username, &ou, open_mode, open_op) < 0)
      xerr_errx(1, "otp_urec_open(%s): failed.", u_username);

    if (otp_urec_get(otpctx, &ou) < 0)
      xerr_errx(1, "otp_urec_open(%s): failed.", u_username);

  } /* open & get urec */

  if (mode == MODE_TEST) {

    if (otp_urec_close(otpctx, &ou) < 0)
      xerr_errx(1, "otp_urec_close(): failed.");

    printf("Testing authentication for user %s.\n", u_username);
    printf("OTP challenge for user %s (%" PRIu64 "): ", u_username, ou.count);
    fflush(stdout);
    scanf("%10s", crsp_tmp);

    r = otp_user_auth(otpctx, u_username, crsp_tmp, window);

    if (r < 0)
      xerr_errx(1, "otp_user_auth(): failed.");

    if (r == OTP_AUTH_PASS)
      printf("Success.\n");
    else if (r == OTP_AUTH_FAIL)
      printf("Fail.\n");
    else
      xerr_errx(1, "otp_user_auth(): unknown response.");

    goto mode_done;

  } /* MODE_TEST */

  if (mode == MODE_GENERATE) {

    for (count_offset = 0; count_offset < window; ++count_offset) {

      if (otp_urec_crsp(otpctx, &ou, count_offset, crsp_tmp, 11) < 0)
        xerr_errx(1, "otp_urec_crsp(): failed.");

      printf("count=%" PRIu64 " crsp=%s\n", ou.count+count_offset, crsp_tmp);

    }

    goto mode_close;

  } /* MODE_GENERATE */

  if ((mode == MODE_SET_COUNT) ||
      (mode == MODE_SET_COUNT_CEIL) ||
      (mode == MODE_SET_FLAGS) ||
      (mode == MODE_SET_FORMAT) ||
      (mode == MODE_SET_STATUS) ||
      (mode == MODE_SET_TYPE)) {

    if (mode == MODE_SET_COUNT)
      ou.count = u_count;
    else if (mode == MODE_SET_COUNT_CEIL)
      ou.count_ceil = u_count_ceil;
    else if (mode == MODE_SET_FLAGS)
      ou.flags = u_flags;
    else if (mode == MODE_SET_FORMAT)
      ou.format = u_format;
    else if (mode == MODE_SET_STATUS)
      ou.status = u_status;
    else if (mode == MODE_SET_TYPE)
      ou.type = u_type;

    if (otp_urec_put(otpctx, &ou) < 0)
      xerr_errx(1, "otp_urec_put(): failed.");

    goto mode_close;

  } /* update user record mode */

  if (mode == MODE_LIST) {

    otp_urec_disp(otpctx, &ou);
    goto mode_close;

  } /* MODE_LIST */

  if (mode == MODE_LIST_SC) {

    printf("#index:count:hostname:key\n");
    otp_urec_dispsc(otpctx, &ou, sc_index, sc_hostname, sc_flags);
    goto mode_close;

  } /* MODE_LIST_SC */

mode_close:
  if (otp_urec_close(otpctx, &ou) < 0)
    xerr_errx(1, "otp_urec_close(): failed.");

mode_done:

  return 0;

} /* main */

void help(void)
{
  int i;

  fprintf(stderr, "otp-control [-?hnv] [-c count] [-C count_ceil] [-f format] [-F flags]\n");
  fprintf(stderr, "            [-H sc_hostname] [-I sc_index] [-k key] [-m command_mode]\n");
  fprintf(stderr, "            [-o otbdb_pathname] [-s status] [-S sc_flags] [ -t type]\n");
  fprintf(stderr, "            [-u username] [-w window]\n");
  fprintf(stderr, "            -h : help\n");
  fprintf(stderr, "            -n : create database\n");
  fprintf(stderr, "            -v : enable verbose output\n\n");
  fprintf(stderr, "            sc_flags    : 0=CHALLENGE 1=READERKEY\n");

  fprintf(stderr, "            flags       : ");
  for (i = 0; i < OTP_FLAGS_BITS; ++i)
    fprintf(stderr, "%s ", otp_flags_l[i]);
  fprintf(stderr, "\n");

  fprintf(stderr, "            format list : ");
  for (i = 1; i <= OTP_FORMAT_MAX; ++i)
    fprintf(stderr, "%s ", otp_format_l[i]);
  fprintf(stderr, "\n");

  fprintf(stderr, "            type list   : ");
  for (i = 1; i <= OTP_TYPE_MAX; ++i)
    fprintf(stderr, "%s ", otp_type_l[i]);
  fprintf(stderr, "\n");

  fprintf(stderr, "            status list : ");
  for (i = 1; i <= OTP_STATUS_MAX; ++i)
    fprintf(stderr, "%s ", otp_status_l[i]);
  fprintf(stderr, "\n");

  fprintf(stderr, "\n");
  fprintf(stderr, "            Mode                Description\n");
  fprintf(stderr, "            -------------------------------------------------\n");
  fprintf(stderr, "            add                - Add user\n");
  fprintf(stderr, "            create             - Create database\n");
  fprintf(stderr, "            dump               - ASCII dump user record(s)\n");
  fprintf(stderr, "            generate           - Generate HOTP for user\n");
  fprintf(stderr, "            list               - List user record (printable)\n");
  fprintf(stderr, "            list-sc            - List user record (SC friendly)\n");
  fprintf(stderr, "            load               - ASCII load user record(s)\n");
  fprintf(stderr, "            remove             - Remove user\n");
  fprintf(stderr, "            set-count          - Set user count\n");
  fprintf(stderr, "            set-count-ceil     - Set user count ceiling\n");
  fprintf(stderr, "            set-flags          - Set user flags\n");
  fprintf(stderr, "            set-format         - Set user format\n");
  fprintf(stderr, "            set-status         - Set user status\n");
  fprintf(stderr, "            set-type           - Set user OTP type\n");
  fprintf(stderr, "            test               - Test user\n");
}

int get_random(char *dev, unsigned char *entropy, int bits)
{
  int fd;
  int bytes;

  bytes = bits / 8;

  if ((fd = open(dev, O_RDONLY, 0)) < 0) {
    fprintf(stderr, "open(%s): %s\n", dev, strerror(errno));
    return -1;
  }

  if (read(fd, entropy, bytes) != bytes) {
    fprintf(stderr, "read(%s): failed to gather %d bytes of entropy.\n",
      dev, bytes);
    close(fd);
    return -1;
  }

  close(fd);

  return 0;

} /* get_random */
