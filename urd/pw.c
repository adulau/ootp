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
 *      $Id: pw.c 13 2009-11-26 16:37:03Z maf $
 */


#include <sys/fcntl.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

#include "pw.h"
#include "xerr.h"

/*
 * Simple user authentication based on passwd file flat db with optional
 * authorized users file.  Database is cached in memory.  stat(pw_fname)
 * is performed in pass_db_auth() to trigger a pass_db_load() when the
 * filesystem database is newer than the memory cache.  If this file
 * does not exist the existing in memory database is used.
 *
 * Password file format:
 *
 *   user_name:user_hash\n
 *       or optionally
 *   user_name:user_hash:optional:fields:to:ignore\n
 *
 * Authorized Users file format:
 *
 *    user_name1\n
 *    user_name2\n
 *
 * Hashed lookup is done for speed.  When the authorized_users file is
 * specified a user must also be listed in this file.
 *
 * Usage:
 *   pass_db_ctx_new()       : initialize context
 *   pass_db_ctx_free()      : free resources associated with context
 *   pass_db_load()          : load and parse password file to memory
 *   pass_db_auth()          : authenticate user_name/u_password pair.
 *                             may call pass_db_load()
 *   pass_db_reload()        : trigger manual password file reload.
 *   pass_db_u_name_lookup() : lookup username in hash table
 *   pass_db_debug()         : enable/disable debugging
 *   pass_db_stats()         : dump hash table stats
 * 
 */

/*
 * function: pass_db_ctx_new()
 *
 * Create a pass_db_ctx struct.  Allocate and initialize storage.
 *
 * pass_db_ctx_free() will release resources.
 *
 * If au_fname is NULL this will disable the authorized_users
 * functionality (all users in the password file are valid).
 *
 * returns < 0 : fail
 *           0 : success
 */
struct pass_db_ctx *pass_db_ctx_new(char *pw_fname, char *au_fname)
{
  struct pass_db_ctx *pdbctx;
  int i, ret;

  ret = -1; /* fail */

  if (!(pdbctx = (struct pass_db_ctx*)malloc(sizeof *pdbctx))) {
    xerr_warn("malloc(pdbctx)");
    goto pass_db_ctx_new_out;
  }

  bzero(pdbctx, sizeof *pdbctx);

  if (!(pdbctx->pw_fname = (char*)malloc(strlen(pw_fname)+1))) {
    xerr_warn("malloc(%d)", strlen(pw_fname));
    goto pass_db_ctx_new_out;
  }

  strcpy(pdbctx->pw_fname, pw_fname);

  if (au_fname) {

    if (!(pdbctx->au_fname = (char*)malloc(strlen(au_fname)+1))) {
      xerr_warn("malloc(%d)", strlen(au_fname));
      goto pass_db_ctx_new_out;
    }

    strcpy(pdbctx->au_fname, au_fname);

  } /* au_fname */

  for (i = 0; i < 1<<PASS_DB_HASH_BUCKET_BITS; ++i) {
    SLIST_INIT(&pdbctx->bucket[i]);
  }

  ret = 0; /* pass */

pass_db_ctx_new_out:

  if (ret == -1) {
    pass_db_ctx_free(pdbctx);
    pdbctx = (struct pass_db_ctx*)0L;
  }

  return pdbctx;

} /* pass_db_ctx_new() */

/*
 * function: pass_db_ctx_free()
 *
 * Release resources in pass_db allocated by pass_db_init().  Must
 * be called for each invocation of pass_db_init() to prevent resource
 * leak.
 *
 */
void pass_db_ctx_free(struct pass_db_ctx *pdbctx)
{
  if (pdbctx) {
    if (pdbctx->pw_fname);
      free(pdbctx->pw_fname);
    if (pdbctx->au_fname)
      free(pdbctx->au_fname);
    if (pdbctx->pw_entries);
      free(pdbctx->pw_entries);
    bzero(pdbctx, sizeof (*pdbctx));
    free(pdbctx);
  }
} /* pass_db_ctx_free */

/*
 * function: pass_db_auth()
 *
 * Authenticate user_name and u_pass in pass_db.
 *
 * If au_fname was set in pass_db_ctx_new() the user must first exist
 * in the authorized_users file else authentication will fail.
 *
 * Unix crypt() is used to compute a hash of u_pass for u_name
 * in pass_db.  If the hash matches the stored hash the user is
 * authenticated.
 *
 * reload pw_fname if the file is newer.  If pw_fname does not
 * exist, then ignore.  This allows an updated password file to
 * be linked into place avoiding race conditions of writing directly
 * to the active file.
 *
 * returns PASS_DB_AUTH_FAIL    : user not authenticated
 *         PASS_DB_AUTH_SUCCESS : user authenticated
 *         PASS_DB_AUTH_ERROR   : system error, user not authenticated
 */
int pass_db_auth(struct pass_db_ctx *pdbctx, char *u_name, char *u_pass)
{
  struct pass_db_entry *pwe;
  struct stat cur_sb;
  char *crypt_result;
  int ret;

  ret = PASS_DB_AUTH_FAIL;

  /* load current passwd file metadata */
  if (stat(pdbctx->pw_fname, &cur_sb) < 0) {
    goto skip_reload;
  }

  /* passwd file updated? */
  if (cur_sb.st_mtime != pdbctx->pw_sb.st_mtime) {
    pdbctx->state = PASS_DB_STATE_RELOAD;
  }

  /* reload? then dispose of old state */
  if (pdbctx->state == PASS_DB_STATE_RELOAD) {
    pass_db_ctx_free(pdbctx);
  }

  /* reload passwd database? */
  if (pdbctx->state != PASS_DB_STATE_LOADED) {
    if (pass_db_load(pdbctx) < 0) {
      xerr_warnx("pass_db_load(): failed");
      ret = PASS_DB_AUTH_ERROR;
      goto pass_db_auth_out;
    }
  }

skip_reload:

  /* hash lookup of user name */
  if (!(pwe = pass_db_u_name_lookup(pdbctx, u_name, strlen(u_name)))) {
    if (pdbctx->debug)
      xerr_info("pass_db_auth(%s): no such user");
    goto pass_db_auth_out;
  }

  if (pwe->status != PASS_DB_ENTRY_ACTIVE) {
    if (pdbctx->debug)
      xerr_info("pass_db_auth(%s): not active");
    goto pass_db_auth_out;
  }

  crypt_result = crypt(u_pass, pwe->u_hash);

  if (crypt_result) {
    if (!strcmp(pwe->u_hash, crypt_result)) {
      ret = PASS_DB_AUTH_SUCCESS;
      if (pdbctx->debug)
        xerr_info("pass_db_auth(%s): pass authentication");
      goto pass_db_auth_out;
    }
  }

  if (pdbctx->debug)
    xerr_info("pass_db_auth(%s): fail authentication");

pass_db_auth_out:

  return ret;

} /* pass_db_auth() */

/*
 * function: pass_db_load()
 *
 * Load and parse a unix password database into memory for later use
 * in pass_db_auth().  Optionally load and parse into memory an
 * authorized users file.  Free any previously allocated resources
 * before reloading.  Create hash table for fast lookups.
 *
 * returns < 0 : fail
 *           0 : success
 */
int pass_db_load(struct pass_db_ctx *pdbctx)
{
  struct pass_db_entry *pwe;
  uint16_t u_hash, u_hash_mask;
  int au_fd, pw_fd, ret, len, i;
  char *pw_buf, *au_buf;
  char *p, *pwdb_u_name, *pwdb_u_hash, *au_name;
  uint pw_entry, lineno;
  uint pwdb_u_name_len, pwdb_u_hash_len, au_name_len;
  int status_default;

  ret = -1;

  pw_fd = -1;
  au_fd = -1;

  pw_buf = (char*)0L;
  au_buf = (char*)0L;

  /* username hash mask */
  u_hash_mask = (uint16_t)((1<<PASS_DB_HASH_BUCKET_BITS)-1);

  /* if no authorized users file then status defaults to active */
  if (pdbctx->au_fname)
    status_default = PASS_DB_ENTRY_INACTIVE;
  else
    status_default = PASS_DB_ENTRY_ACTIVE;

  /* load password database into memory */

  /* open pw database */
  if ((pw_fd = open(pdbctx->pw_fname, O_RDONLY, 0)) < 0) {
    xerr_warn("open(%s)", pdbctx->pw_fname);
    goto pass_db_load_out;
  }

  /* load metadata */
  if (fstat(pw_fd, &pdbctx->pw_sb) < 0) {
    xerr_warn("stat(%s)", pdbctx->pw_fname);
    goto pass_db_load_out;
  }

  /* allocate storage for pw database */
  if (!(pw_buf = malloc(pdbctx->pw_sb.st_size+1))) {
    xerr_warn("malloc(%d)", (int)pdbctx->pw_sb.st_size+1);
    goto pass_db_load_out;
  }

  /* read in pw database */
  if ((len = read(pw_fd, pw_buf, pdbctx->pw_sb.st_size)) < 0) {
    xerr_warn("read(%s)", pdbctx->pw_fname);
    goto pass_db_load_out;
  }

  if (len != pdbctx->pw_sb.st_size) {
    xerr_warnx("short read(%s)", pdbctx->pw_fname);
    goto pass_db_load_out;
  }

  /* load authorized_users file if configured into memory */

  if (pdbctx->au_fname) {

    /* open au database */
    if ((au_fd = open(pdbctx->au_fname, O_RDONLY, 0)) < 0) {
      xerr_warn("open(%s)", pdbctx->au_fname);
      goto pass_db_load_out;
    }

    /* load metadata */
    if (fstat(au_fd, &pdbctx->au_sb) < 0) {
      xerr_warn("stat(%s)", pdbctx->au_fname);
      goto pass_db_load_out;
    }

    /* allocate storage for au database */
    if (!(au_buf = malloc(pdbctx->au_sb.st_size+1))) {
      xerr_warn("malloc(%d)", (int)pdbctx->au_sb.st_size+1);
      goto pass_db_load_out;
    }

    /* read in au database */
    if ((len = read(au_fd, au_buf, pdbctx->au_sb.st_size)) < 0) {
      xerr_warn("read(%s)", pdbctx->au_fname);
      goto pass_db_load_out;
    }

    if (len != pdbctx->au_sb.st_size) {
      xerr_warnx("short read(%s)", pdbctx->au_fname);
      goto pass_db_load_out;
    }

  } /* pdbctx->au_fname */

/****/

  /* count number of lines in the passwd file to predict malloc size */
  for (pdbctx->num_entries = 0, p = pw_buf; *p; ++p) {
    if (*p == '\n')
      ++pdbctx->num_entries;
  }

  if (!(pdbctx->pw_entries = (struct pass_db_entry*)malloc(
    pdbctx->num_entries * sizeof (struct pass_db_entry)))) {
    xerr_warn("malloc(pw_entries)");
    goto pass_db_load_out;
  } /* allocate entries */

  bzero(pdbctx->pw_entries,
    pdbctx->num_entries * sizeof (struct pass_db_entry));

  /* while more lines */
  for (p = pw_buf, lineno = 1, pw_entry = 0; *p; ++lineno, ++pw_entry) {

    /* maf:$1$<hash>::::: */
    /* note only u_name:<hash> is required */

    /* u_name is first */
    pwdb_u_name = p;

    for (pwdb_u_name_len = 0;;pwdb_u_name_len++) {

      /* end of u_name field */
      if (*p == ':') {
        ++p;
        break;
      }
      /* require minimum of u_name and password field */
      if ((*p == 0) || (*p == '\n')) {
        *p = 0; /* null terminate */
        xerr_warnx("pass_db_auth(%s): lineno=%d, parse error at %s",
          pdbctx->pw_fname, lineno, pwdb_u_name);
        ret = PASS_DB_AUTH_ERROR;
        goto pass_db_load_out;
      }

      ++p;

    } /* extract u_name */

    /* hash of u_pass is next */
    pwdb_u_hash = p;

    for (pwdb_u_hash_len = 0;;pwdb_u_hash_len++) {

      /* end of u_pass hash field (possibly EOL or EOF */
      if ((*p == 0) || (*p == '\n') || (*p == ':'))
        break;

      ++p;

    } /* extract u_pass hash */

    /* skip to next line */
    for (; *p && *p != '\n'; ++p);

    if (*p == '\n');
      ++p;

    /* u_name len 0 is illegal */
    if (pwdb_u_name_len == 0) {
      xerr_warnx("pass_db_auth(%s): lineno=%d, pwdb_u_name_len=0",
        pdbctx->pw_fname, lineno);
      ret = PASS_DB_AUTH_ERROR;
      goto pass_db_load_out;
    }

    /* user_hash len 0 is illegel */
    if (pwdb_u_hash_len == 0) {
      xerr_warnx("pass_db_auth(%s): lineno=%d, pwdb_u_hash_len=0",
        pdbctx->pw_fname, lineno);
      ret = PASS_DB_AUTH_ERROR;
      goto pass_db_load_out;
    }

    /* bounds check pwdb length */
    if (pwdb_u_hash_len > PASS_DB_USER_HASH_LEN) {
      xerr_warnx("pass_db_auth(%s): lineno=%d, pwdb_u_hash_len=%d >%d ",
        pdbctx->pw_fname, lineno, pwdb_u_hash_len, PASS_DB_USER_HASH_LEN);
      ret = PASS_DB_AUTH_ERROR;
      goto pass_db_load_out;
    }

    /* bounds check pwdb len */
    if (pwdb_u_name_len > PASS_DB_USER_NAME_LEN) {
      xerr_warnx("pass_db_auth(%s): lineno=%d, pwdb_u_name=%d >%d ",
        pdbctx->pw_fname, lineno, pwdb_u_name_len, PASS_DB_USER_NAME_LEN);
      ret = PASS_DB_AUTH_ERROR;
      goto pass_db_load_out;
    }

    pwe = &pdbctx->pw_entries[pw_entry];

    /* store as C string (null termination is handled above in bzero() ) */
    bcopy(pwdb_u_name, &pwe->u_name, pwdb_u_name_len);
    bcopy(pwdb_u_hash, &pwe->u_hash, pwdb_u_hash_len);
    pwe->status = status_default;
    pwe->u_name_len = pwdb_u_name_len;
    pwe->u_hash_len = pwdb_u_hash_len;

    /* populate hash lookup table */
    u_hash = 0;
    for (i = 0; i < pwdb_u_name_len; ++i) {
      if (i & 0x1) {
        u_hash ^= pwdb_u_name[i];
        u_hash ^= pwdb_u_name[i]<<3;
      } else {
        u_hash ^= ((uint16_t)pwdb_u_name[i]<<8);
        u_hash ^= ((uint16_t)pwdb_u_name[i]<<11);
      }
    }

    u_hash &= u_hash_mask;

    SLIST_INSERT_HEAD(&pdbctx->bucket[u_hash], pwe, chain);

  } /* while more lines */

  /*
   * if using authorized_users mark pdbctx entries with an active
   *  user as active
   */
  if (pdbctx->au_fname) {

    /* while more lines */
    for (p = au_buf, lineno = 1; *p; ++lineno) {

      /*
       * format:
       *  username\n
       *  username_2\n
       *   ...
       *  username_n\n
       */

       /* start username */
       for (au_name_len = 0, au_name = p;*p;au_name_len++, ++p) {

         /* EOL */
         if (*p == '\n') {
           ++p;
           break;
         }

       } /* extract username */

       if (au_name_len == 0) {
         xerr_warnx("pass_db_load(%s): lineno=%d, au_name_len=0",
           pdbctx->au_fname, lineno);
         ret = PASS_DB_AUTH_ERROR;
         goto pass_db_load_out;
       }

       /* hash lookup of user name */
       if (!(pwe = pass_db_u_name_lookup(pdbctx, au_name, au_name_len))) {
         xerr_warnx("pass_db_load(%s): lineno=%d, no match in pass_db",
           pdbctx->au_fname, lineno);
       } else {
         pwe->status = PASS_DB_ENTRY_ACTIVE;
       }

    } /* more lines */

  } /* au_fname */

  pdbctx->state = PASS_DB_STATE_LOADED;

  ret = 0; /* good */

pass_db_load_out:

  if (pw_fd != -1)
    close (pw_fd);

  if (au_fd != -1)
    close (au_fd);

  if (pw_buf)
    free(pw_buf);

  if (au_buf)
    free(au_buf);

  return ret;

} /* pass_db_load */

/*
 * function: pass_db_reload()
 *
 * Flag the password database as stale and requiring refresh/reload
 * on the next pass_db_auth()
 *
 */
void pass_db_reload(struct pass_db_ctx *pdbctx)
{
  pdbctx->state = PASS_DB_STATE_RELOAD;
} /* pass_db_reload */

/*
 * function: pass_db_debug()
 *
 * set/clear pass_db context debug
 *
 */
void pass_db_debug(struct pass_db_ctx *pdbctx, int debug)
{
  pdbctx->debug = debug;
} /* pass_db_debug() */

/*
 * function: pass_db_u_name_lookup()
 *
 * Perform a hased lookup of u_name in the password database context.
 *
 * Returns a pointer to a pass_db_entry or 0L on failure.
 *
 */
struct pass_db_entry *pass_db_u_name_lookup(struct pass_db_ctx *pdbctx, 
  char *u_name, int u_name_len)
{
  struct pass_db_entry *pwe;
  uint16_t u_hash, u_hash_mask;
  int i, match;

  /* username hash mask */
  u_hash_mask = (uint16_t)((1<<PASS_DB_HASH_BUCKET_BITS)-1);

  /* not found yet */
  match = 0;

  u_hash = 0;
  for (i = 0; i < u_name_len; ++i) {
    if (i & 0x1) {
      u_hash ^= u_name[i];
      u_hash ^= u_name[i]<<3;
    } else {
      u_hash ^= ((uint16_t)u_name[i]<<8);
      u_hash ^= ((uint16_t)u_name[i]<<11);
    }
  }

  u_hash &= u_hash_mask;

  SLIST_FOREACH(pwe, &pdbctx->bucket[u_hash], chain) {

    if (!strncmp(u_name, pwe->u_name, u_name_len))
      return pwe;

  } /* SLIST_FOREACH */

  return (struct pass_db_entry*)0L;

} /* pass_db_u_name_lookup() */

/*
 * function: pass_db_stats()
 *
 * Dump hash table chain depths.
 *
 */
void pass_db_stats(struct pass_db_ctx *pdbctx)
{
  struct pass_db_entry *pwe;
  int depth, i;

  xerr_info("pass_db_stats:");

  for (i = 0; i < 1<<PASS_DB_HASH_BUCKET_BITS; ++i) {

    if (SLIST_EMPTY(&pdbctx->bucket[i]))
      continue;

   depth = 0;
   SLIST_FOREACH(pwe, &pdbctx->bucket[i], chain)
     ++depth;

   xerr_info(" bucket=%d,depth=%d", i, depth);

  } /* hash_bucket */

} /* pass_db_stat() */
