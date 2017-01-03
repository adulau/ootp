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
 *      $Id: ffdb.h 13 2009-11-26 16:37:03Z maf $
 */

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <stdint.h>
#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#ifndef FFDB_H
#define FFDB_H

/* max path name element */
#ifndef MAXNAMLEN
#define MAXNAMLEN 255
#endif 

#include "xerr.h"

struct ffdb_key {
  void *key;
  size_t size;
  int fd;
};

struct ffdb_val {
  void *val;
  size_t size;
};

struct ffdb_info {

  size_t min_key_size;
  size_t max_key_size;

  size_t min_val_size;
  size_t max_val_size;

  uint32_t num_keys;

};

struct ffdb_ctx {
  DIR  *iter_DIR;
  char *base_dir_pn;        /* base directory pathname (null terminated) */
  char *key_pn;             /* key file name (encoded) (null terminated) */
  int verbose;              /* verbose? */
  mode_t file_mode;         /* file mode when creating new files */
  struct ffdb_val val;
  size_t key_pn_size;        /* encoded (null terminated) */
  size_t max_key_size;      /* raw */
  size_t max_val_size;      /* maximum bytes in value */
  size_t base_dir_pn_size;  /* strlen(base_dir_pn)+1 */
  uint32_t flags;
  int valid;                /* valid context? */
  int rec_open_ref_count;   /* open records reference count */
};

#define FFDB_DB_KEY_HEX        0x01  /* encode keys as ASCII HEX */
#define FFDB_DB_CREATE         0x02  /* create db */
#define FFDB_DB_SYNC_WRITES    0x04  /* enable synchronous writes */
#define FFDB_DB_STAT_READ      0x08  /* verify read size == stat size */
#define FFDB_DB_CREATE_SOFT    0x20  /* create db if it does not exist */
#define FFDB_DB_VERBOSE        0x40  /* verbose error messages */

#define FFDB_OP_LOCK_NONE         0x0000
#define FFDB_OP_LOCK_SH           0x0001
#define FFDB_OP_LOCK_EX           0x0002
#define FFDB_OP_LOCK_NB           0x0004
#define FFDB_OP_LOCK_UN           0x0008
#define FFDB_OP_REWIND_NO         0x0020
#define FFDB_OP_TRUNCATE_NO       0x0040
#define FFDB_OP_VAL_ALLOC         0x1000

#define FFDB_ITER_FIRST        0x1 /* set on first call */
#define FFDB_ITER_NEXT         0x2 /* set after first call */
#define FFDB_ITER_GET          0x4 /* do ffdb_rec_get() */
#define FFDB_ITER_DONE         0x8 /* clear resources allocated by FIRST */

int ffdb_db_info(char *base_dir_pn, struct ffdb_info *info);
struct ffdb_ctx *ffdb_db_open(char *base_dir_pn, size_t max_key_size,
  size_t max_val_size, uint32_t flags, mode_t file_mode, mode_t dir_mode);
int ffdb_db_close(struct ffdb_ctx *ffdbctx);
void ffdb_db_verbose(struct ffdb_ctx *ffdbctx, int verbose);

int ffdb_rec_exists(struct ffdb_ctx *ffdbctx, struct ffdb_key *key);
int ffdb_rec_rm(struct ffdb_ctx *ffdbctx, struct ffdb_key *key);
int ffdb_rec_iter(struct ffdb_ctx *ffdbctx, struct ffdb_key *key,
  struct ffdb_val *val, int iter_flags);

int ffdb_rec_open(struct ffdb_ctx *ffdbctx, struct ffdb_key *key,
  int open_flags, int op_flags);
int ffdb_rec_close(struct ffdb_ctx *ffdbctx, struct ffdb_key *key);
int ffdb_rec_get(struct ffdb_ctx *ffdbctx, struct ffdb_key *key,
  struct ffdb_val *val, int op_flags);
int ffdb_rec_put(struct ffdb_ctx *ffdbctx, struct ffdb_key *key,
  struct ffdb_val *val, int op_flags);
int ffdb_rec_lock(struct ffdb_ctx *ffdbctx, struct ffdb_key *key,
  int op_flags);


#endif /* FFDB_H */
