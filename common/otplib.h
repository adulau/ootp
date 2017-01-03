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
 *      $Id: otplib.h 61 2009-12-17 03:57:22Z maf $
 */

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif
#include "ffdb.h"

#ifndef OTP_H
#define OTP_H

#define u_int unsigned int
#define u_char unsigned char

#define SWAP64(x) x = \
      ((((x) & 0xff00000000000000ull) >> 56)|\
      (((x) & 0x00ff000000000000ull)>>40)|\
      (((x) & 0x0000ff0000000000ull)>>24)|\
      (((x) & 0x000000ff00000000ull)>>8)|\
      (((x) & 0x00000000ff000000ull)<<8)|\
      (((x) & 0x0000000000ff0000ull)<<24)|\
      (((x) & 0x000000000000ff00ull)<<40)|\
      (((x) & 0x00000000000000ffull)<<56));

#define SWAP32(x) x = \
         ((((x)&0xff)<<24) |\
         (((x)&0xff00)<<8) |\
         (((x)&0xff0000)>>8) |\
         (((x)>>24)&0xff));

#define SWAP16(x) x = \
    ( (((x)&0xff)<<8) | (((x)&0xff00)>>8) );



#define OTP_DB_FNAME        "/etc/otpdb" /* location of user database */
#define OTP_VERSION         1            /* version of library */

#define OTP_FORMAT_HEX40    1            /* 40 bits in hex */
#define OTP_FORMAT_DHEX40   2            /* 40 bits in hex w. RFC 4226 DT */
#define OTP_FORMAT_DEC31_6  3            /* 31 bits 6 digits in decimal RFC */
#define OTP_FORMAT_DEC31_7  4            /* 31 bits 7 digits in decimal */
#define OTP_FORMAT_DEC31_8  5            /* 31 bits 8 digits in decimal */
#define OTP_FORMAT_DEC31_9  6            /* 31 bits 9 digits in decimal */
#define OTP_FORMAT_DEC31_10 7            /* 31 bits 10 digits in decimal */
#define OTP_FORMAT_MAX      7            /* highest valid format enum */

#define OTP_TYPE_HOTP       1            /* protocol type */
#define OTP_TYPE_MAX        1            /* highest valid type enum */

#define OTP_WINDOW_DEFAULT  10           /* default challenge window */
#define OTP_WINDOW_MAX      255          /* max challenge window */

#define OTP_VERSION_MIN 1          /* min version for this code */
#define OTP_VERSION_MAX 1          /* max version for this code */

#define OTP_HOTP_KEY_SIZE 20       /* HMAC SHA160 key length */
#define OTP_HOTP_HEX40_LEN 5       /* HOTP challenge hex 40 bits */
#define OTP_HOTP_DEC31_LEN 10      /* max 10 digits */

#define OTP_AUTH_PASS      0       /* authenticated */
#define OTP_AUTH_FAIL      1       /* not authenticated */
#define OTP_ERROR          -1      /* library function failure */
#define OTP_SUCCESS        0       /* library function success */
#define OTP_FAIL           1       /* library function failure */

#define OTP_STATUS_ACTIVE   1       /* user is active */
#define OTP_STATUS_INACTIVE 2       /* user is not active */
#define OTP_STATUS_DISABLED 3       /* user is locked (disabled) */
#define OTP_STATUS_MAX      3       /* highest valid status enum */


#define OTP_USER_N_FIELDS 10       /* n fields in ASCII encoding */
#define OTP_USER_ASCII_LEN 139     /* max ASCII encoded length (w/o null) */

#define OTP_FLAGS_DSPCNT           0x1 /* force display count */
#define OTP_FLAGS_BITS             1   /* bits used */

#define OTP_USER_NAME_LEN 32       /* max length of username (w/o null)*/
#define OTP_USER_KEY_LEN 64        /* key length */

#define OTP_DB_VERBOSE      0x01      /* verbose error messages */
#define OTP_DB_CREATE       0x02      /* create database? */
#define OTP_DB_CREATE_SOFT  0x04      /* create database, soft fail on exist */

struct otp_user {
  struct ffdb_key db_key;        /* database key */
  struct ffdb_val db_val;        /* database value (this struct in ASCII) */
  uint64_t count;                /* count */
  uint64_t count_ceil;           /* count ceiling */
  uint64_t last;                 /* last access */
  uint8_t version;               /* version */
  uint8_t status;                /* status */
  uint8_t format;                /* format */
  uint8_t type;                  /* type */
  uint8_t flags;                 /* type */
  uint8_t res1;                  /* reserved */
  uint8_t res2;                  /* reserved */
  uint8_t res3;                  /* reserved */
  uint16_t key_size;             /* bytes used in key */
  unsigned char key[OTP_USER_KEY_LEN]; /* shared key (may not all be used */
  char username[OTP_USER_NAME_LEN+1];  /* name, null terminated */
  char ascii_encoded[OTP_USER_ASCII_LEN+1];  /* null terminated */

/*
 * ASCII encoding:
 *  version:name:key:status:format:type:count_cur:count_ceil:last
 *                  n encoding decoded size  encoded size
 *                  --------------------------------------
 *  version         1 ASCII HEX 8 bits       2  bytes + 1
 *  username        2 ASCII 32 bytes         1..32 bytes + 1
 *  key             3 ASCII HEX 20 bytes     40 bytes + 1
 *  status          4 ASCII HEX 8 bits       2  bytes + 1
 *  format          5 ASCII HEX 8 bits       2  bytes + 1
 *  type            6 ASCII HEX 8 bits       2  bytes + 1
 *  flags           7 ASCII HEX 8 bits       2  bytes + 1
 *  count_cur       8 ASCII HEX 64 bits      16 bytes + 1
 *  count_ceil      9 ASCII HEX 64 bits      16 bytes + 1
 *  last           10 ASCII HEX 64 bits      16 bytes + 1 null
 *    total bytes = 2+32+40+2+2+2+2_16+16+16+10 = 140
 */

};


struct otp_ctx {
  struct ffdb_ctx *ffdbctx;
  int valid;
  int verbose;
};

int otp_hotp_hex40_auth(struct otp_ctx *otpctx, struct otp_user *ou,
  char *crsp, int window);
int otp_hotp_hex40_crsp(struct otp_ctx *otpctx, struct otp_user *ou,
  int64_t count_offset, char *buf, size_t buf_size);
int otp_hotp_dec31_auth(struct otp_ctx *otpctx, struct otp_user *ou,
  char *crsp, int window);
int otp_hotp_dec31_crsp(struct otp_ctx *otpctx, struct otp_user *ou,
  int64_t count_offset, char *buf, size_t buf_size);

struct otp_ctx *otp_db_open(char *dbname, int flags);
int otp_db_close(struct otp_ctx *otpctx);
int otp_db_valid(struct otp_ctx *otpctx, char *who);
int otp_db_dump(struct otp_ctx *otpctx, char *u_username);
int otp_db_load(struct otp_ctx *otpctx, char *u_username);

int otp_user_add(struct otp_ctx *otpctx, char *u_username,
  uint8_t *u_key_val, uint16_t u_key_size, uint64_t u_count,
  uint64_t u_count_ceil, uint8_t u_status, uint8_t u_type,
  uint8_t u_format, uint8_t u_version);
int otp_user_exists(struct otp_ctx *otpctx, char *u_username);
int otp_user_rm(struct otp_ctx *otpctx, char *u_username);
int otp_user_auth(struct otp_ctx *otpctx, char *u_username,
  char *u_crsp, int u_window);

int otp_urec_open(struct otp_ctx *otpctx, char *u_username,
   struct otp_user *ou, int open_flags, int op_flags);
int otp_urec_crsp(struct otp_ctx *otpctx, struct otp_user *ou,
  int64_t count_offset, char *buf, size_t buf_size);
int otp_urec_get(struct otp_ctx *otpctx, struct otp_user *ou);
int otp_urec_put(struct otp_ctx *otpctx, struct otp_user *ou);
int otp_urec_close(struct otp_ctx *otpctx, struct otp_user *ou);
int otp_urec_sanity(struct otp_ctx *otpctx, struct otp_user *ou);
void otp_urec_disp(struct otp_ctx *otpctx, struct otp_user *ou);
void otp_urec_dispsc(struct otp_ctx *otpctx, struct otp_user *ou,
  uint8_t sc_index, char *sc_hostname, uint8_t *sc_flags);

int otp_user_to_ascii(struct otp_ctx *otpctx, struct otp_user *ou);
int otp_user_from_ascii(struct otp_ctx *otpctx, struct otp_user *ou);

char *otp_uflags_str(uint8_t flags, char *tmpbuf, size_t tmpbuf_size);

extern char *otp_status_l[];
extern char *otp_format_l[];
extern char *otp_type_l[];
extern char *otp_flags_l[];


#endif /* OTP_H */
