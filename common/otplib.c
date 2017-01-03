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
 *      $Id: otplib.c 18 2009-11-26 19:40:06Z maf $
 */

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <sys/errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "otplib.h"
#include "xerr.h"
#include "ffdb.h"
#include "str.h"
#include "otpsc.h"

char *otp_l_status[] = {"error", "active", "inactive", "disabled"};
char *otp_l_format[] = {"error", "hex40"};
char *otp_l_type[] = {"error", "HOTP"};

/*
 * One Time Password library with HOTP implementation.
 *
 *
 ****
 *
 * otp_ou_toascii()      struct otp_user to ASCII
 * otp_ou_fromascii      ASCII to struct otp_user
 *
 ****
 *
 * otp_hotp_hex40_auth() HOTP 40 bit hex key authentication
 * otp_hotp_hex40_crsp() HOTP 40 bit hex key challenge response generator
 *
 ****
 *
 * otp_db_open()         open OTP db
 * otp_db_close()        close OTP db
 * otp_db_valid()        OTP db pointer valid?
 * otp_db_dump()         dump OTP db to ASCII
 * otp_db_load()         load OTP db from ASCII
 *
 ****
 *
 * otp_user_add()        add user to OTP db
 * otp_user_exists()     user exists in OTP db?
 * otp_user_rm()         remove user from OTP db
 * otp_user_auth()       authenticate user from OTP db
 *
 ****
 *
 * otp_urec_open()       open OTP db user record
 * otp_urec_close()      close OTP db user record
 * otp_urec_get()        get/read OTP db user record (after open)
 * otp_urec_put()        put/write OTP db user record (after open)
 * otp_urec_sanity()     check sanity of OTP user db record
 * otp_urec_crsp()       generate challenge response for OTP user db record
 * otp_urec_disp()       display/printable output of OTP user db record
 * otp_urec_dispsc()     smart card friendly output of user db record
 *
 */


/*
 * function: otp_ou_toascii()
 *
 * convert binary ou struct to : separated ASCII string.  ASCII
 * string is stored in the context.
 *
 * arguments:
 *  otpctx   - otp context from otp_db_open()
 *  ou       - otp_user struct source
 *
 * returns: <0 : fail
 *           0 : success
 *
 */
int otp_ou_toascii(struct otp_ctx *otpctx, struct otp_user *ou)
{
  char *c;
  int n;

  if (otp_db_valid(otpctx, "otp_ou_toascii") < 0)
    return -1;

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP64(ou->last)
  SWAP64(ou->count)
  SWAP64(ou->count_ceil)
#endif /* BYTE_ORDER */

  /*
   * encode to:
   *  version:name:key:status:format:type:count:count_ceil:last
   */

  c = ou->ascii_encoded;

  str_hex_dump(c, (void*)&ou->version, 1);
  c += 2;

  if ((n = strlen(ou->username)) > OTP_USER_NAME_LEN) {
    xerr_warnx("otp_ou_toascii(): username length invalid.");
    return -1;
  }
 
  *c++ = ':';
  strcpy(c, ou->username);
  c += n;

  *c++ = ':';
  str_hex_dump(c, ou->key, 20);
  c += 40;

  *c++ = ':';
  str_hex_dump(c, (void*)&ou->status, 1);
  c += 2;

  *c++ = ':';
  str_hex_dump(c, (void*)&ou->format, 1);
  c += 2;

  *c++ = ':';
  str_hex_dump(c, (void*)&ou->type, 1);
  c += 2;

  *c++ = ':';
  str_hex_dump(c, (void*)&ou->flags, 1);
  c += 2;

  *c++ = ':';
  str_hex_dump(c, (void*)&ou->count, 8);
  c += 16;

  *c++ = ':';
  str_hex_dump(c, (void*)&ou->count_ceil, 8);
  c += 16;

  *c++ = ':';
  str_hex_dump(c, (void*)&ou->last, 8);
  c += 16;

  *c++ = 0;

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP64(ou->last)
  SWAP64(ou->count)
  SWAP64(ou->count_ceil)
#endif /* BYTE_ORDER */

  ou->db_val.val = &ou->ascii_encoded;
  ou->db_val.size = strlen(ou->ascii_encoded);

  return 0;

} /* otp_ou_toascii */

/*
 * function: otp_ou_fromascii()
 *
 * convert ASCII : separated user record in otpctx to binary ou
 *
 * arguments:
 *  otpctx    - otp context from otp_db_open()
 *  ou        - otp_user struct filled in
 *
 * returns: <0 : fail
 *           0 : success
 *
 *
 */
int otp_ou_fromascii(struct otp_ctx *otpctx, struct otp_user *ou)
{
  int field, ret, n, i;
  char *c;

  if (otp_db_valid(otpctx, "otp_ou_fromascii") < 0)
    return -1;

  /* strip \n */
  for (i = 0; i < OTP_USER_ASCII_LEN; ++i) {
    if (ou->ascii_encoded[i] == '\n') {
      ou->ascii_encoded[i] = 0;
      break;
    } /* if */
    if (ou->ascii_encoded[i] == 0)
      break;
  } /* for */

  ret = OTP_ERROR;

  /* first pass, sanity check : verify n fields, replace : with 0 */
  field = 0;
  c = ou->ascii_encoded;
  for (;;) {
    if (*c == ':') {
      *c = 0;
      ++c;
      ++field;
      if (field > (OTP_USER_N_FIELDS-1)) /* too many fields */
        break;
    } else if (*c == 0) {
      break;
    } else {
      ++c;
    }
  }

  if (field != (OTP_USER_N_FIELDS-1)) {
    if (otpctx->verbose)
      xerr_warnx("expecting %d fields, got %d.", OTP_USER_N_FIELDS, field+1);
    return -1;
  }

#define CHK_STRLEN(N,L)\
  n = strlen(c);\
  if (n != L) {\
    if (otpctx->verbose)\
      xerr_warnx("%s: %s length expecting %d, got %d.", __func__, N, L, n);\
    goto otp_ou_fromascii_out;\
  }\

#define CHK_STRRANGE(N,L,H)\
  n = strlen(c);\
  if ((n > H) || (n < L)) {\
    if (otpctx->verbose)\
      xerr_warnx("%s: %s length range (%d,%d), got %d.", __func__, N, L, H, n);\
    goto otp_ou_fromascii_out;\
  }\

#define HEX_DECODE(N,V,E)\
  if (str_hex_decode(c, E, (u_char*)&ou->V, E>>1) < 0) {\
    if (otpctx->verbose)\
      xerr_warnx("%s: str_hex_decode(%s): failed.", __func__, N);\
    goto otp_ou_fromascii_out;\
  }\
    
  for (field = 0, c = ou->ascii_encoded; field < OTP_USER_N_FIELDS; ++field) {
   
    if (field == 0) { /* version */
      CHK_STRLEN("version", 2)
      HEX_DECODE("version", version, 2)
      if ((ou->version < OTP_VERSION_MIN) ||
          (ou->version > OTP_VERSION_MAX)) {
        if (otpctx->verbose)
          xerr_warnx("version not in range (%d,%d).", OTP_VERSION_MIN,
            OTP_VERSION_MAX);
        return -1;
      }
    } else if (field == 1) { /* username */
      CHK_STRRANGE("username", 1, 32)
      strcpy(ou->username, c);
    } else if (field == 2) { /* key */
      CHK_STRRANGE("key", 1, 40);
      HEX_DECODE("key", key, 40)
    } else if (field == 3) { /* status */
      CHK_STRLEN("status", 2);
      HEX_DECODE("status", status, 2)
    } else if (field == 4) { /* format */
      CHK_STRLEN("format", 2);
      HEX_DECODE("format", format, 2)
    } else if (field == 5) { /* type */
      CHK_STRLEN("type", 2);
      HEX_DECODE("type", type, 2)
    } else if (field == 6) { /* flags */
      CHK_STRLEN("flags", 2);
      HEX_DECODE("flags", flags, 2)
    } else if (field == 7) { /* count */
      CHK_STRLEN("count", 16);
      HEX_DECODE("count", count, 16)
    } else if (field == 8) { /* count_ceil */
      CHK_STRLEN("count_ceil", 16);
      HEX_DECODE("count_ceil", count_ceil, 16)
    } else if (field == 9) { /* last */
      CHK_STRLEN("last", 16);
      HEX_DECODE("last", last, 16)
    }

    /* skip to next field */
    for (; *c; ++c);
    ++c;

  } /* foreach field */

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP64(ou->last)
  SWAP64(ou->count)
  SWAP64(ou->count_ceil)
#endif /* BYTE_ORDER */

  ou->key_size = OTP_HOTP_KEY_SIZE;

  ou->db_key.key = &ou->username;
  ou->db_key.size = strlen(ou->username);

  ret = OTP_SUCCESS;

otp_ou_fromascii_out:

  return ret;

} /* otp_ou_fromascii */

/*
 * function: otp_hotp_hex40_auth()
 *
 * validate challenge HOTP 40 bit hex format challenge response
 * for user ou with window.
 *
 * arguments:
 *  ou             - otp user struct
 *  crsp           - user response
 *  window         - window of challenge responses to attempt
 *
 * return: OTP_ERROR       - error
 *         OTP_AUTH_PASS   - user authenticated
 *         OTP_AUTH_FAIL   - user not authenticated
 *
 */
int otp_hotp_hex40_auth(struct otp_ctx *otpctx, struct otp_user *ou,
  char *crsp, int window)
{
  uint64_t tmp_count;
  u_int rlen;
  int i;
  u_char result[EVP_MAX_MD_SIZE], decoded[5];

  if (otp_db_valid(otpctx, "otp_hotp_hex40_auth") < 0)
    return -1;

  if (strlen(crsp) != 10) {
    if (otpctx->verbose)
      xerr_warnx("strlen(crsp) != 10.");
    return OTP_AUTH_FAIL;
  }

  /* expecting at most 10 hex digits 5*8=40 bits */
  if (str_hex_decode(crsp, 10, decoded, 5) < 0) {
    if (otpctx->verbose)
      xerr_warnx("str_hex_decode(): failed.");
    return OTP_AUTH_FAIL;
  }

  tmp_count = ou->count;

  /* try to authenticate with count, incrementing count up to count+window */
  for (i = 0; i < window; ++i, ++tmp_count) {

  /* HOTP is big endian */
#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP64(tmp_count)
#endif /* BYTE_ORDER */

    /* compute expected response to challenge */
    if (!HMAC(EVP_sha1(), ou->key, 20, (void*)&tmp_count, 8,
      result, &rlen)) {
      if (otpctx->verbose)
        xerr_warnx("HMAC(): failed.");
      return OTP_ERROR;
    }

  /* restore from HOTP standard byte order */
#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP64(tmp_count)
#endif /* BYTE_ORDER */

    /* compare the top 40 bits to authenticate user, match then return good */
    if (!bcmp(decoded, &result, 5)) {
      ou->count = tmp_count+1;
      return OTP_AUTH_PASS;
    }

  }

  return OTP_AUTH_FAIL;

} /* otp_hotp_hex40_auth */

/*
 * function: otp_hotp_hex40_crsp()
 *
 * generate HOTP challenge response in hex40 format from data in ou
 * with optional * count_offset applied.  Store results in buf as
 * null terminated ASCII string.
 *
 * arguments:
 *  otpctx       - otp context from otp_db_open()
 *  ou           - otp_user struct source
 *  count_offset - offset of count from current count in ou
 *  buf          - buffer with ASCII result.  Min 11 bytes.
 *
 * returns: <0 : fail
 *           0 : success
 *
 */
int otp_hotp_hex40_crsp(struct otp_ctx *otpctx, struct otp_user *ou,
  int64_t count_offset, char *buf, size_t buf_size)
{
  uint64_t tmp_count;
  u_char result[EVP_MAX_MD_SIZE];
  u_int rlen;

  if (otp_db_valid(otpctx, "otp_hotp_hex40_crsp") < 0)
    return -1;

  /* HOTP is big endian */
  tmp_count = ou->count;
  tmp_count += count_offset;

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP64(tmp_count)
#endif /* BYTE_ORDER */
  
  /* compute expected response to challenge */
  if (!HMAC(EVP_sha1(), ou->key, 20, (void*)&tmp_count, 8,
    result, &rlen)) {
    if (otpctx->verbose)
      xerr_warnx("HMAC(): failed.");
    return OTP_ERROR;
  }

  /* two bytes for each digit + null terminator */
  if (buf_size < 11) {
    xerr_warnx("buf_size < 11");
    return OTP_ERROR;
  }
 
  str_hex_dump(buf, result, 5);
  
  return 0;

} /* otp_hotp_hex40_crsp */

/*
 * function: otp_db_open()
 *
 * open OTP user database, return db context
 * otp_db_close() must be called to resources by open db context
 *
 * arguments:
 *  dbname - pathname to db
 *  flags  - OTP_DB_*
 *    OTP_DB_VERBOSE     - enable verbose warnings and errors
 *    OTP_DB_CREATE      - create db if it does not exist
 *    OTP_DB_CREATE_SOFT - fail quiet if db exists and OTP_DB_CREATE set
 *
 * returns: 0L             failure
 *          struct otp_ctx success
 *
 */
struct otp_ctx *otp_db_open(char *dbname, int flags)
{
  struct otp_ctx *otpctx;
  int ret, verbose, ffdb_flags;

  ffdb_flags = 0;
  otpctx = (void*)0L;
  ret = -1;

  if (flags & OTP_DB_VERBOSE) {
    verbose = 1;
    ffdb_flags |= FFDB_DB_VERBOSE;
  } else {
    verbose = 0;
  }

  if (flags & OTP_DB_CREATE)
    ffdb_flags |= FFDB_DB_CREATE;

  if (flags & OTP_DB_CREATE_SOFT)
    ffdb_flags |= FFDB_DB_CREATE_SOFT;

  if (!(otpctx = (struct otp_ctx*)malloc(sizeof *otpctx))) {
    if (verbose)
      xerr_warn("malloc(otpctx): failed.");
    goto otp_db_open_out;
  }

  bzero(otpctx, sizeof *otpctx);
  otpctx->verbose = verbose;

  if (!(otpctx->ffdbctx = ffdb_db_open(dbname, OTP_USER_NAME_LEN, 
    OTP_USER_ASCII_LEN, ffdb_flags, S_IRUSR|S_IWUSR, S_IRWXU))) {
    if (verbose)
      xerr_warnx("ffdb_db_open(): failed.");
    goto otp_db_open_out;
  }

  otpctx->valid = 1;

  ret = 0; /* success */
    
otp_db_open_out:

  if ((ret == -1) && (otpctx) && (otpctx->ffdbctx))
    ffdb_db_close(otpctx->ffdbctx);

  if ((ret == -1) && (otpctx)) {
    bzero(otpctx, sizeof *otpctx);
    free(otpctx);
    otpctx = (void*)0L;
  }

  return otpctx;

} /* otp_db_open */

/*
 * function: otp_db_close()
 *
 * close db context created by otp_db_open()
 *
 * arguments:
 *  otpctx - otp db context returned by otp_db_open()
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_db_close(struct otp_ctx *otpctx)
{
  if (otp_db_valid(otpctx, "otp_db_close") == -1)
    return -1;

  if (ffdb_db_close(otpctx->ffdbctx) == -1)
    return -1;

  bzero(otpctx, sizeof *otpctx);
  free (otpctx);

  return 0;

} /* otp_db_close */

/*
 * function: otp_db_valid()
 *
 * simple validation of otpctx
 *
 * arguments:
 *  otpctx - otp db context returned by otp_db_open()
 *
 * returns: <0 failure
 *           0 success
 */
int otp_db_valid(struct otp_ctx *otpctx, char *who)
{

  if (!otpctx) {
    xerr_warnx("%s(): fatal, no context.", who);
    return -1;
  }

  if (!otpctx->valid) {
    if (otpctx->verbose)
      xerr_warnx("%s(): fatal, invalid context.", who);
      return -1;
  }

  return 0;

} /* otp_db_valid */

/*
 * function otp_db_dump()
 *
 * Dump database in ASCII to stdout
 *
 * arguments:
 *  otpctx     - otp db context returned by otp_db_open()
 *  u_username - optional username.  null to dump all users
 *
 * returns: <0 failure
 *           0 success
 */
int otp_db_dump(struct otp_ctx *otpctx, char *u_username)
{
  struct ffdb_key db_key;
  struct ffdb_val db_val;
  int r, ret, ul;
  char buf[OTP_USER_ASCII_LEN+1];

  if (otp_db_valid(otpctx, "otp_db_dump") < 0)
    return -1;

  ret = -1;

  if (u_username)
    ul = strlen(u_username);
  else
    ul = 0;

  printf("#version:user:key:status:format:type:flags:count_cur:count_ceil:last\n");

  /* first record */
  r = ffdb_rec_iter(otpctx->ffdbctx, &db_key, &db_val,
    FFDB_ITER_FIRST|FFDB_ITER_GET);

  while (1) {

    if (r < 0) {
      if (otpctx->verbose)
        xerr_warnx("ffdb_rec_iter(): failed.");
      goto otp_db_dump_out;
    }

    /* last? */
    if (r == 1) {
      ret = 0;
      break;
    }

    /* match on single username? */
    if (ul) {
      /* not same strlen? */
      if (db_key.size != ul)
        goto otp_db_dump_skip1;

      /* not same string? */
      if (bcmp(db_key.key, u_username, ul))
        goto otp_db_dump_skip1;
    }

    if (db_val.size > OTP_USER_ASCII_LEN) {
      if (otpctx->verbose)
        xerr_warnx("db_val.size > OTP_USER_ASCII_LEN.");
      goto otp_db_dump_out;
    }

    bcopy(db_val.val, buf, db_val.size);
    buf[db_val.size] = 0;

    printf("%s\n", buf);

otp_db_dump_skip1:

    /* next record */
    r = ffdb_rec_iter(otpctx->ffdbctx, &db_key, &db_val, FFDB_ITER_GET);

  }

  ret = 0; /* success */

otp_db_dump_out:

  return ret;

} /* otp_db_dump */

/*
 * function: otp_db_load()
 *
 * load otp db from stdin.
 *
 * arguments:
 *  otpctx     - otp db context returned by otp_db_open()
 *  u_username - optional username.  null to load all users
 *
 * returns: <0 failure
 *           0 success
 */
int otp_db_load(struct otp_ctx *otpctx, char *u_username)
{
  struct otp_user ou;
  int ret, l, i;
  char buf[OTP_USER_ASCII_LEN<<2];
  char *c;

  if (otp_db_valid(otpctx, "otp_db_load") < 0)
    return -1;

  ret = -1; /* fail */

  while (!feof(stdin)) {

    /* get line or EOF */
    if (!fgets(buf, (OTP_USER_ASCII_LEN<<2), stdin))
      break;

    /* skip whitespace */
    for (c = buf; *c && ((*c == ' ') || (*c == '\t')); ++c);

    /* skip # comment lines */
    if (*c == '#')
      continue;

    l = strlen(c);

    /* sanity check line length */
    if (l > OTP_USER_ASCII_LEN) {
      if (otpctx->verbose)
        xerr_warnx("line buf > OTP_USER_ASCII_LEN.");
      goto otp_db_load_out;

    }

    /* copy line into user data struct */
    bcopy(c, &ou.ascii_encoded, l);

    /* ASCII to binary / sanity checking */
    if (otp_ou_fromascii(otpctx, &ou) < 0) {
      if (otpctx->verbose)
        xerr_warnx("otp_ou_fromascii(): failed.");
      goto otp_db_load_out;
    }

    /* limit to single username load? */
    if (u_username && (strcmp(u_username, ou.username))) {
      if (otpctx->verbose)
        printf("skip %s\n", ou.username);
      continue;
    }

    /* strip \n on input */
    for (i = 0; i < l; ++i) {
      if (buf[i] == '\n') {
        buf[i] = 0;
        break;
      }
    }
    if (otpctx->verbose)
      printf("load %s\n", buf);

    /* binary to ASCII / sanity checking */
    if (otp_ou_toascii(otpctx, &ou) < 0) {
      if (otpctx->verbose)
        xerr_warnx("otp_ou_toascii(): failed.");
      goto otp_db_load_out;
    }

    /* open/create user record */
    if (ffdb_rec_open(otpctx->ffdbctx, &ou.db_key, O_RDWR|O_CREAT,
      FFDB_OP_LOCK_EX) < 0) {
      if (otpctx->verbose)
        xerr_warnx("ffdb_rec_open(): failed.");
      goto otp_db_load_out;
    }

    /* store record */
    if (ffdb_rec_put(otpctx->ffdbctx, &ou.db_key, &ou.db_val, 0) < 0) {
      if (otpctx->verbose)
        xerr_warnx("ffdb_rec_put(): failed.");
      goto otp_db_load_out;
    }

    /* close record */
    if (ffdb_rec_close(otpctx->ffdbctx, &ou.db_key) < 0) {
      if (otpctx->verbose)
        xerr_warnx("ffdb_rec_close(): failed.");
      goto otp_db_load_out;
    }

  } /* while */

  ret = 0; /* success */

otp_db_load_out:

  return ret;

} /* otp_db_load */


/*
 * function: otp_user_add()
 *
 * add user u_username to otpdb
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  u_username   - username
 *  u_key_val    - key value
 *  u_key_size   - length of key in bytes
 *  u_count      - initial count
 *  u_count_ceil - count ceiling
 *  u_status     - status OTP_STATUS_*
 *  u_type       - type OTP_TYPE_HOTP (HOTP implemented)
 *  u_format     - format OTP_FORMAT_HEX40 (HEX40 implemented)
 *  u_version    - version OTP_VERSION (version 1 implemented)
 *  
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_user_add(struct otp_ctx *otpctx, char *u_username,
  uint8_t *u_key_val, uint16_t u_key_size, uint64_t u_count,
  uint64_t u_count_ceil, uint8_t u_status, uint8_t u_type,
  uint8_t u_format, uint8_t u_version)
{
  struct otp_user ou;
  int ret, r;

  if (otp_db_valid(otpctx, "otp_user_add") < 0)
    return -1;

  ret = -1; /* fail */
  bzero(&ou, sizeof ou);
  ou.db_key.key = u_username;
  ou.db_key.size = strlen(u_username);

  /*
   * sanity checks
   */
  if (ou.db_key.size > OTP_USER_NAME_LEN) {
    if (otpctx->verbose)
      xerr_warnx("strlen(u_username) > OTP_USER_NAME_LEN.");
    goto otp_user_add_out;
  }

  if (u_key_size > OTP_USER_KEY_LEN) {
    if (otpctx->verbose)
      xerr_warnx("key_size > OTP_USER_KEY_LEN.");
    goto otp_user_add_out;
  }

  /*
   * copy in user fields to ou
   */

  strcpy(ou.username, u_username);
  bcopy(u_key_val, &ou.key, u_key_size);
  ou.key_size = u_key_size;
  ou.count = u_count;
  ou.count_ceil = u_count_ceil;
  ou.last = 0;
  ou.version = u_version;
  ou.status = u_status;
  ou.format = u_format;
  ou.type = u_type;

  if (otp_urec_sanity(otpctx, &ou) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_urec_sanity(): failed.");
    goto otp_user_add_out;
  }

  /* does user exist? */
  r = ffdb_rec_exists(otpctx->ffdbctx, &ou.db_key);

  /* yes */
  if (r == 0) {
    if (otpctx->verbose)
      xerr_warnx("user %s exists in otp db, fail.", u_username);
    goto otp_user_add_out;
  }

  /* ffdb_rec_exists failure */
  if (r < 0) {
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_exists(): failed.");
    goto otp_user_add_out;
  }

  /* user struct binary to ASCII */
  if (otp_ou_toascii(otpctx, &ou) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_ou_toascii(): failed.");
    goto otp_user_add_out;
  }

  /* open/create user record */
  if (ffdb_rec_open(otpctx->ffdbctx, &ou.db_key, O_RDWR|O_CREAT,
    FFDB_OP_LOCK_EX) < 0) {
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_open(): failed.");
    goto otp_user_add_out;
  }

  /* store user record */
  if (ffdb_rec_put(otpctx->ffdbctx, &ou.db_key, &ou.db_val, 0) < 0) {
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_put(): failed.");
    goto otp_user_add_out;
  }

  /* close user record */
  if (ffdb_rec_close(otpctx->ffdbctx, &ou.db_key) < 0) {
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_close(): failed.");
    goto otp_user_add_out;
  }

  ret = 0; /* success */

otp_user_add_out:

  return ret;
    
} /* otp_user_add */

/*
 * function: otp_user_exists()
 *
 * test if user exists in otp db
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  u_username   - username
 *
 * returns: <0 failure
 *           0 success
 *           1 key does not exist
 */
int otp_user_exists(struct otp_ctx *otpctx, char *u_username)
{
  struct ffdb_key db_key;
  int ret;

  if (otp_db_valid(otpctx, "otp_user_exists") < 0)
    return -1;

  /* paranoia */
  str_safe(u_username, OTP_USER_NAME_LEN);

  ret = OTP_ERROR; /* fail */
  db_key.key = u_username;
  db_key.size = strlen(u_username);

  /*
   * sanity checks
   */
  if (db_key.size > OTP_USER_NAME_LEN) {
    if (otpctx->verbose)
      xerr_warnx("strlen(u_username) > OTP_USER_NAME_LEN.");
    goto otp_user_exists_out;
  }

  /* does user exist? */
  ret = ffdb_rec_exists(otpctx->ffdbctx, &db_key);

  /* ffdb_rec_exists failure */
  if (ret < 0)
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_exists(): failed.");

otp_user_exists_out:

  return ret;

} /* otp_user_exists */

/*
 * function: otp_user_rm()
 *
 * remove user from otp database
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  u_username   - username
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_user_rm(struct otp_ctx *otpctx, char *u_username)
{
  struct ffdb_key db_key;
  int ret;

  if (otp_db_valid(otpctx, "otp_user_rm") < 0)
    return -1;

  /* paranoia */
  str_safe(u_username, OTP_USER_NAME_LEN);

  ret = -1; /* fail */

  db_key.key = u_username;
  db_key.size = strlen(u_username);

  /*
   * sanity checks
   */
  if (db_key.size > OTP_USER_NAME_LEN) {
    if (otpctx->verbose)
      xerr_warnx("strlen(u_username) > OTP_USER_NAME_LEN.");
    goto otp_user_rm_out;
  }

  /* remove user */
  ret = ffdb_rec_rm(otpctx->ffdbctx, &db_key);

  /* ffdb_rec_rm failure */
  if (ret < 0)
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_rm(): failed.");

otp_user_rm_out:

  return ret;

} /* otp_user_rm */

/*
 * otp_user_auth()
 *
 * returns: <0 failure
 *          OTP_AUTH_FAIL  - user not authenticated
 *                           database update
 *                             authenticate attempt time
 *          OTP_AUTH_PASS  - user authenticated, database updated with
 *                           database update
 *                             authenticate attempt time
 *                             new count
 */
int otp_user_auth(struct otp_ctx *otpctx, char *u_username, 
  char *u_crsp, int u_window)
{
  time_t now;
  struct otp_user ou;
  int ret, r, auth_status;

  if (otp_db_valid(otpctx, "otp_user_auth") < 0)
    return -1;

  /* paranoia */
  str_safe(u_username, OTP_USER_NAME_LEN);

  ret = -1; /* fail */
  bzero(&ou, sizeof ou);
  auth_status = OTP_AUTH_FAIL;

  /* paranoia */
  str_safe(u_username, OTP_USER_NAME_LEN);
  str_safe(u_crsp, OTP_HOTP_HEX40_LEN<<1);

  /* open user record */
  if (otp_urec_open(otpctx, u_username, &ou, O_RDWR, FFDB_OP_LOCK_EX) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_urec_open(%s): failed.", u_username);
    goto otp_user_auth_out;
  }

  /* get user record */
  if (otp_urec_get(otpctx, &ou) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_urec_get(%s): failed.", u_username);
    goto otp_user_auth_out;
  }

  now = time((time_t)0L);

  /* only allow 1 try per second for this user */
  if (now == ou.last) {
    ret = OTP_AUTH_FAIL; /* soft fail */
    if (otpctx->verbose)
      xerr_warnx("User %s exceeded otp auth policer.", u_username);
    goto otp_user_auth_out;
  }

  if (otp_urec_sanity(otpctx, &ou) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_urec_sanity(): failed.");
    goto otp_user_auth_out;
  }

  /* set for next time */
  ou.last = now;

  /* try to authenticate user */
  if (ou.status != OTP_STATUS_ACTIVE)
    auth_status = OTP_AUTH_FAIL;
  else if (ou.count >= ou.count_ceil)
    auth_status = OTP_AUTH_FAIL;
  else
    auth_status = otp_hotp_hex40_auth(otpctx, &ou, u_crsp, u_window);

  /*
   * regardless of authentication status update the db to reflect last access
   */

  if (otp_urec_put(otpctx, &ou) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_urec_put(): failed.");
    goto otp_user_auth_out;
  }

  /* set return code to auth status */
  ret = auth_status;

otp_user_auth_out:

  /* close record */
  if (ou.db_key.fd && (ou.db_key.fd != -1)) {
    if ((r = otp_urec_close(otpctx, &ou)) < 0) {
      if (otpctx->verbose)
        xerr_warnx("otp_urec_close(): failed.");
      ret = r;
    }
  }

  return ret;

} /* otp_user_auth */

/*
 * function: otp_urec_open()
 *
 * open an otp user record in otp database.  A user record must
 * be closed with otp_urec_close() to release resources allocated
 * during the otp_urec_open().  A user can be created with
 * open_flags = O_RDWR|OCREAT.  For read only records use O_RDONLY.
 * The record can be locked by setting appropriate flags in op_flags
 *
 * examples:
 *
 *   ;;;; create new user test, hold exclusive lock on record
 *   otp_urec_open(otpctx, "test", &ou, O_RDWR|O_CREAT, FFDB_OP_LOCK_EX)
 *   ; fill in ou
 *   otp_urec_put(otpctx, &ou)
 *   otp_urec_close(otpctx, &ou)
 *
 *   ;;;; read/modify/write user test, hold exclusive lock on record
 *   otp_urec_open(otpctx, "test", &ou, O_RDWR, FFDB_OP_LOCK_EX)
 *   otp_urec_get(otpctx, &ou)
 *   ; modify ou fields
 *   otp_urec_put(otpctx, &ou)
 *   otp_urec_close(otpctx, &ou)
 *
 *   ;;;; display a user record, get shared lock
 *   otp_urec_open(otpctx, "test", &ou, O_RDONLY, FFDB_OP_LOCK_SH)
 *   otp_urec_get(otpctx, &ou)
 *   otp_urec_disp(otpctx, &ou)
 *   otp_urec_close(otpctx, &ou)
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  u_username   - username
 *  ou           - otp_user record
 *  open_flags   - flags passed to open(2)
 *  op_flags     - flags FFDB_OP_*
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_urec_open(struct otp_ctx *otpctx, char *u_username,
   struct otp_user *ou, int open_flags, int op_flags)
{
  int ret;

  if (otp_db_valid(otpctx, "otp_urec_open") < 0)
    return -1;

  /* paranoia */
  str_safe(u_username, OTP_USER_NAME_LEN);

  ret = -1; /* fail */
  bzero(ou, sizeof *ou);
  ou->db_key.fd = -1; /* invalid */

  ou->db_key.key = u_username;
  ou->db_key.size = strlen(u_username);

  /*
   * sanity checks
   */

  if (ou->db_key.size > OTP_USER_NAME_LEN) {
    if (otpctx->verbose)
      xerr_warnx("strlen(u_username) > OTP_USER_NAME_LEN.");
    goto otp_urec_open_out;
  }

  /* open user record */
  if (ffdb_rec_open(otpctx->ffdbctx, &ou->db_key, open_flags, op_flags) < 0) {
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_open(): failed.");
    goto otp_urec_open_out;
  }

  ret = 0; /* success */
  
otp_urec_open_out:

  return ret;

} /* otp_urec_open */

/*
 * otp_urec_close()
 *
 * close user record opened with otp_urec_open()
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  ou           - otp_user record opened with otp_urec_open()
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_urec_close(struct otp_ctx *otpctx, struct otp_user *ou)
{
  if (otp_db_valid(otpctx, "otp_urec_close") < 0)
    return -1;

  if (ffdb_rec_close(otpctx->ffdbctx, &ou->db_key) < 0) {
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_close(): failed.");
    return -1;
  }

  return 0; /* success */
} /* otp_urec_close */


/*
 * function: otp_urec_get()
 *
 * read otp user db record opened with otp_urec_open()
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  ou           - otp_user record opened with otp_urec_open()
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_urec_get(struct otp_ctx *otpctx, struct otp_user *ou)
{
  int ret;

  if (otp_db_valid(otpctx, "otp_urec_get") < 0)
    return -1;

  ret = -1; /* fail */

  /* get user record */
  if (ffdb_rec_get(otpctx->ffdbctx, &ou->db_key, &ou->db_val, 0) < 0) {
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_get(%s): failed.", ou->username);
      goto otp_urec_get_out;
  }

  /* sanity check size */
  if (ou->db_val.size > OTP_USER_ASCII_LEN) {
    if (otpctx->verbose)
      xerr_warnx("db_val.size > OTP_USER_ASCII_LEN.");
    goto otp_urec_get_out;
  }

  /* copy out */
  bcopy(ou->db_val.val, ou->ascii_encoded, ou->db_val.size);

  /* null terminate */
  ou->ascii_encoded[ou->db_val.size] = 0;

  /* ASCII to binary */
  if (otp_ou_fromascii(otpctx, ou) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_ou_fromascii(): failed.");
    goto otp_urec_get_out;
  }

  ret = 0; /* success */

otp_urec_get_out:

  return ret;

} /* otp_urec_get */

/*
 * function: otp_urec_put()
 *
 * write otp user db record opened with otp_urec_open()
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  ou           - otp_user record opened with otp_urec_open()
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_urec_put(struct otp_ctx *otpctx, struct otp_user *ou)
{
  int ret;

  if (otp_db_valid(otpctx, "otp_urec_put") < 0)
    return -1;

  ret = -1; /* fail */

  /* convert binary struct to ASCII for db */
  if (otp_ou_toascii(otpctx, ou) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_ou_toascii(): failed.");
    goto otp_urec_put_out;
  }

  /* update db */
  if (ffdb_rec_put(otpctx->ffdbctx, &ou->db_key, &ou->db_val, 0) < 0) {
    if (otpctx->verbose)
      xerr_warnx("ffdb_rec_put(%s): failed.", ou->username);
    goto otp_urec_put_out;
  }

  ret = 0; /* success */

otp_urec_put_out:

  return ret;

} /* otp_urec_put */

/*
 * function: otp_urec_sanity()
 *
 * perform sanity checks on otp_user structure.  Used internally
 * with otp_urec_*() functions before performing operations on
 * structure.
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  ou           - otp_user record opened with otp_urec_open()
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_urec_sanity(struct otp_ctx *otpctx, struct otp_user *ou)
{

  if (otp_db_valid(otpctx, "otp_urec_sanity") < 0)
    return -1;

  if (ou->type != OTP_TYPE_HOTP) {
    if (otpctx->verbose)
      xerr_warnx("type != OTP_TYPE_HOTP.");
    return -1;
  }
 
  if (ou->format != OTP_FORMAT_HEX40) {
    if (otpctx->verbose)
      xerr_warnx("format != OTP_FORMAT_HEX40.");
    return -1;
  }

  if (ou->version != OTP_VERSION) {
    if (otpctx->verbose)
      xerr_warnx("version != OTP_VERSION.");
    return -1;
  }

  if (ou->key_size != OTP_HOTP_KEY_SIZE) {
    if (otpctx->verbose)
      xerr_warnx("key_size != OTP_HOTP_KEY_SIZE.");
    return -1;
  }

  return 0; /* success */

} /* otp_urec_sanity */

/*
 * function: otp_urec_crsp()
 *
 * generate challenge response for ou
 * HOTP HEX40 implemented.
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  ou           - otp_user record opened with otp_urec_open()
 *
 * returns: <0 failure
 *           0 success
 *
 */
int otp_urec_crsp(struct otp_ctx *otpctx, struct otp_user *ou,
  int64_t count_offset, char *buf, size_t buf_size)
{

  if (otp_db_valid(otpctx, "otp_urec_crsp") < 0)
    return -1;

  if (buf_size < 5) {
    if (otpctx->verbose)
      xerr_warnx("buf_size < 5.");
    goto otp_urec_crsp_out;
  }

  if (otp_urec_sanity(otpctx, ou) < 0) {
    if (otpctx->verbose)
      xerr_warnx("otp_urec_sanity(): failed.");
    goto otp_urec_crsp_out;
  }

  return (otp_hotp_hex40_crsp(otpctx, ou, count_offset, buf, buf_size));

otp_urec_crsp_out:

  return -1;

} /* otp_urec_crsp */


/*
 * function: otp_urec_disp()
 *
 * format and display ou to stdout
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  ou           - otp_user record opened with otp_urec_open()
 *
 * returns: <0 failure
 *           0 success
 *
 */
void otp_urec_disp(struct otp_ctx *otpctx, struct otp_user *ou)
{
  char tmp[41];

  if (otp_db_valid(otpctx, "otp_urec_disp") < 0)
    return;

  str_hex_dump(tmp, ou->key, 20);

  printf("Username.......%s\n", ou->username);
  printf("Key............%s\n", tmp);
  printf("Count..........%" PRIu64 " (0x%" PRIx64 ")\n", ou->count, ou->count);
  printf("Count Ceiling..%" PRIu64 " (0x%" PRIx64 ")\n", ou->count_ceil,
    ou->count_ceil);
  printf("Version........%u\n", (u_int)ou->version);
  printf("Status.........%s (%u)\n",
    otp_l_status[ou->status], (u_int)ou->status);
  printf("Format.........%s (%u)\n",
    otp_l_format[ou->format], (u_int)ou->format);
  printf("Type...........%s (%u)\n", otp_l_type[ou->type], (u_int)ou->type);
  printf("Flags..........%2.2x", (u_int)ou->flags);
  if (ou->flags)
    printf(" [");
  if (ou->flags & OTP_USER_FLAGS_DSPCNT)
    printf(" display-count");
  if (ou->flags)
    printf(" ]");
  printf("\n");

} /* otp_urec_disp */

/*
 * function: otp_urec_dispsc()
 *
 * format and display ou to stdout in SC friendly format
 *
 * arguments:
 *  otpctx       - otp db context returned by otp_db_open()
 *  ou           - otp_user record opened with otp_urec_open()
 *  sc_index     - SC index
 *  sc_hostname  - SC hostname
 *  sc_flags     - SC flag bits (OR'd to hostname in output)
 *
 * returns: <0 failure
 *           0 success
 *
 */
void otp_urec_dispsc(struct otp_ctx *otpctx, struct otp_user *ou,
uint8_t sc_index, char *sc_hostname, uint8_t *sc_flags)
{
  char fmt_buf[1024], tmp_sc_hostname[SC_HOSTNAME_LEN];
  uint32_t tmpc32;
  int l;

  if (otp_db_valid(otpctx, "otp_urec_dispsc") < 0)
    return;

  l = strlen(sc_hostname);
  if (l > SC_HOSTNAME_LEN)
    l = SC_HOSTNAME_LEN;

  bzero(tmp_sc_hostname, SC_HOSTNAME_LEN);
  bcopy(sc_hostname, tmp_sc_hostname, l);

  /* set flag bits */
  for (l = 0; l < SC_HOSTNAME_LEN; ++l)
    tmp_sc_hostname[l] |= sc_flags[l];

  tmpc32 = ou->count;

#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP32(tmpc32)
#endif /* BYTE_ORDER */

  str_hex_dump(fmt_buf, (u_char*)&sc_index, SC_INDEX_LEN);
  printf("%s:", fmt_buf);

  str_hex_dump(fmt_buf, (u_char*)&tmpc32, SC_COUNT32_LEN);
  printf("%s:", fmt_buf);

  str_hex_dump(fmt_buf, (u_char*)tmp_sc_hostname, SC_HOSTNAME_LEN);
  printf("%s:", fmt_buf);

  str_hex_dump(fmt_buf, ou->key, SC_HOTPKEY_LEN);
  printf("%s\n", fmt_buf);

} /* otp_urec_dispsc */

#ifdef OTPLIB_EXAMPLE

#include <stdio.h>
#include "otplib.h"
#include "ffdb.h"


int main(int argc, char **argv)
{
  struct otp_ctx *otpctx, *otpctx2;
  struct otp_user ou;
  uint8_t key160[OTP_HOTP_KEY_LEN];
  uint8_t key40[OTP_HOTP_HEX40_LEN];
  uint8_t crsp[20];
  int i, ret;

  xerr_setid(argv[0]);

  otpctx = otp_db_open("/tmp/otpdb", OTP_DB_VERBOSE|OTP_DB_CREATE);
  ret = (otpctx == 0L);
  printf("otp_db_open(): %d\n", ret);

  otpctx2 = otp_db_open("/tmp/otpdb2", OTP_DB_VERBOSE|OTP_DB_CREATE);
  ret = (otpctx == 0L);
  printf("otp_db_open2(): %d\n", ret);

  for (i = 0; i < OTP_HOTP_KEY_LEN; ++i)
    key160[i] = i;

  for (i = 0; i < OTP_HOTP_HEX40_LEN; ++i)
    key40[i] = i;

  ret = otp_user_add(otpctx, "maf3", key160, OTP_HOTP_KEY_LEN, 0LL,
    0xFFFFFFFFFFFFFFFFLL, OTP_STATUS_ACTIVE, OTP_TYPE_HOTP,
    OTP_FORMAT_HEX40, OTP_VERSION);

  printf("otp_user_add(): %d\n", ret);

  ret = otp_user_exists(otpctx, "maf");
  printf("otp_user_exists(): %d\n", ret);

  ret = otp_urec_open(otpctx, "maf", &ou, O_RDWR, FFDB_OP_LOCK_EX);
  printf("otp_urec_open(): %d\n", ret);

  ret = otp_urec_get(otpctx,  &ou);
  printf("otp_urec_get(): %d\n", ret);

  ret = otp_urec_put(otpctx,  &ou);
  printf("otp_urec_put(): %d\n", ret);

  ret = otp_urec_crsp(otpctx,  &ou, 0LL, crsp, 20);
  printf("otp_urec_crsp(): %d %s\n", ret, crsp);

  ret = otp_urec_close(otpctx,  &ou);
  printf("otp_urec_close(): %d\n", ret);

/*  crsp[0] = 'F'; */

  ret = otp_user_auth(otpctx, "maf", crsp, OTP_HOTP_WINDOW);
  printf("otp_user_auth(): %d\n", ret);

/*
  ret = otp_user_rm(otpctx, "maf");
  printf("otp_user_rm(): %d\n", ret);
*/

/*
  ret = otp_db_dump(otpctx);
  printf("otp_db_dump(): %d\n", ret);
*/

  ret = otp_db_load(otpctx2, (char*)0L);
  printf("otp_db_load(): %d\n", ret);

  ret = otp_db_close(otpctx);
  printf("otp_db_close(): %d\n", ret);


} /* main */

#endif /* OTPLIB_EXAMPLE */
