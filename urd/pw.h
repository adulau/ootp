/*
 * Copyright (c) 2009 Mark Fullmer
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
 *      $Id: pw.h 13 2009-11-26 16:37:03Z maf $
 */


#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include "queue.h"

#define PASS_DB_STATE_NONE   0
#define PASS_DB_STATE_RELOAD 1
#define PASS_DB_STATE_LOADED 2

#define PASS_DB_ENTRY_INACTIVE 0
#define PASS_DB_ENTRY_ACTIVE 1


#define PASS_DB_AUTH_SUCCESS 0
#define PASS_DB_AUTH_FAIL    1
#define PASS_DB_AUTH_ERROR   -1

#define PASS_DB_USER_NAME_LEN   32   /* max length of user_name */
#define PASS_DB_USER_HASH_LEN   32   /* max length of user_pass */

#define PASS_DB_HASH_BUCKET_BITS 16  /* number of hash buckets */

struct pass_db_ctx {
  struct stat pw_sb;
  struct stat au_sb;
  int state;
  char *pw_fname;
  char *au_fname;
  uint num_entries;
  struct pass_db_entry *pw_entries;
  SLIST_HEAD(pass_db_head, pass_db_entry) bucket[1<<PASS_DB_HASH_BUCKET_BITS];
  int debug;
};

struct pass_db_entry {
  SLIST_ENTRY(pass_db_entry) chain;
  int status;
  uint u_name_len;
  uint u_hash_len;
  char u_name[PASS_DB_USER_NAME_LEN+1];
  char u_hash[PASS_DB_USER_HASH_LEN+1];
};

struct pass_db_ctx *pass_db_ctx_new(char *pw_fname, char *au_fname);
void pass_db_ctx_free(struct pass_db_ctx *pdbctx);
int pass_db_auth(struct pass_db_ctx *pdbctx, char *user_name, char *user_pass);
int pass_db_load(struct pass_db_ctx *pdbctx);
void pass_db_reload(struct pass_db_ctx *pdbctx);
void pass_db_debug(struct pass_db_ctx *pdbctx, int debug);
struct pass_db_entry *pass_db_u_name_lookup(struct pass_db_ctx *pdbctx, 
  char *u_name, int u_name_len);
void pass_db_stats(struct pass_db_ctx *pdbctx);

