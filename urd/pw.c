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
 *      $Id: pw.c 155 2011-04-06 02:25:43Z maf $
 */


#include <sys/fcntl.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <security/pam_appl.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

#include "pw.h"
#include "str.h"
#include "xerr.h"
#include "fileio.h"

/*
 * Simple user authentication based on passwd file flat db with optional
 * authorized users file.  Database is cached in memory.  stat(loc)
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
 *   pass_db_ctx_free()      : free all resources associated with context
 *   pass_db_ctx_reset()     : free username/password resources
 *   pass_db_load()          : load and parse password file to memory
 *   pass_db_auth()          : authenticate user_name/u_password pair.
 *                             may call pass_db_load()
 *   pass_db_reload()        : trigger manual password file reload.
 *   pass_db_u_name_lookup() : lookup username in hash table
 *   pass_db_debug()         : enable/disable debugging
 *   pass_db_stats()         : dump hash table stats
 * 
 */

int pam_mem_conv (int pam_nmsg, const struct pam_message **pam_msgh,
  struct pam_response **pam_resph, void *pam_app_data);

static int pam_auth(char *user_name, char *user_pass, char *svc_name);

static char *global_user_pass;

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
struct pass_db_ctx *pass_db_ctx_new(char *loc, char *au_fname, int type)
{
  struct pass_db_ctx *pdbctx;
  int i, ret;

  ret = -1; /* fail */

  if (!(pdbctx = (struct pass_db_ctx*)malloc(sizeof *pdbctx))) {
    xerr_warn("malloc(pdbctx)");
    goto pass_db_ctx_new_out;
  }

  bzero(pdbctx, sizeof *pdbctx);

  pdbctx->type = type;

  if (!(pdbctx->loc = (char*)malloc(strlen(loc)+1))) {
    xerr_warn("malloc(%d)", strlen(loc));
    goto pass_db_ctx_new_out;
  }

  strcpy(pdbctx->loc, loc);

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
 * Release resources in pass_db allocated by pass_db_ctx_new().  Must
 * be called for each invocation of pass_db_ctx_new() to prevent resource
 * leak.
 *
 */
void pass_db_ctx_free(struct pass_db_ctx *pdbctx)
{
  if (pdbctx) {
    if (pdbctx->loc)
      free(pdbctx->loc);
    if (pdbctx->au_fname)
      free(pdbctx->au_fname);
    if (pdbctx->pw_entries)
      free(pdbctx->pw_entries);
    bzero(pdbctx, sizeof (*pdbctx));
    free(pdbctx);
  }
} /* pass_db_ctx_free */

/*
 * function: pass_db_ctx_reset()
 *
 * Release username/password resources from pass_db_ctx
 *
 */
void pass_db_ctx_reset(struct pass_db_ctx *pdbctx)
{
  int i;

  if (pdbctx) {
    if (pdbctx->debug)
      xerr_info("pass_db_ctx_reset()");
    if (pdbctx->pw_entries) {
      bzero(pdbctx->pw_entries,
        pdbctx->num_entries * sizeof (struct pass_db_entry));
      pdbctx->num_entries = 0;
      free(pdbctx->pw_entries);
    }

    for (i = 0; i < 1<<PASS_DB_HASH_BUCKET_BITS; ++i) {
      SLIST_INIT(&pdbctx->bucket[i]);
    }

  }
} /* pass_db_ctx_reset */

/*
 * function: pass_db_auth()
 *
 * Authenticate user_name and u_pass in pass_db.
 *
 * If au_fname was set in pass_db_ctx_new() the user must first exist
 * in the authorized_users file else authentication will fail.
 *
 * type=LOCAL
 *   Unix crypt() is used to compute a hash of u_pass for u_name
 *   in pass_db.  If the hash matches the stored hash the user is
 *   authenticated.
 * type=EX_LOCAL
 *   same as LOCAL, do not consult authorized_users
 * type=PAM
 *   user must exist in local database, PAM is used for authentication
 * type=EX_PAM
 *   PAM is used for authentication.  Local password and authorized_users
 *   file is not consulted.
 *
 * reload loc if the file is newer.  If loc does not
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
  int ret, need_reload;

  ret = PASS_DB_AUTH_FAIL;

  /* optimization when local database is not used */
  if (pdbctx->type == PASS_DB_TYPE_EX_PAM)
    goto skip_exists;

  need_reload = 0;

  /* check authorized users for update */
  if ((pdbctx->type == PASS_DB_TYPE_LOCAL) ||
      (pdbctx->type == PASS_DB_TYPE_PAM)) {

    /* load current passwd file metadata */
    if (stat(pdbctx->au_fname, &cur_sb) < 0) {
      xerr_info("skipping reload, no %s", pdbctx->au_fname);
      goto skip_reload;
    }

    /* passwd file updated? */
    if (cur_sb.st_mtime != pdbctx->au_sb.st_mtime) {
      xerr_info("reload on %s time", pdbctx->au_fname);
      need_reload = 1;
    }

  } /* check for reload of au_fname */

  /* check passwd file for updates */
  if ((pdbctx->type == PASS_DB_TYPE_LOCAL) ||
      (pdbctx->type == PASS_DB_TYPE_EX_LOCAL)) {

    /* load current passwd file metadata */
    if (stat(pdbctx->loc, &cur_sb) < 0) {
      need_reload = 0;
      xerr_info("skipping reload, no %s", pdbctx->loc);
      goto skip_reload;
    }

    /* passwd file updated? */
    if (cur_sb.st_mtime != pdbctx->pw_sb.st_mtime) {
      xerr_info("reload on %s time", pdbctx->loc);
      need_reload = 1;
    }

  }

  if (need_reload)
    pdbctx->state = PASS_DB_STATE_RELOAD;

  /* reload? then dispose of old state */
  if (pdbctx->state == PASS_DB_STATE_RELOAD) {
    pass_db_ctx_reset(pdbctx);
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
      xerr_info("pass_db_auth(%s): no such user", u_name);
    goto pass_db_auth_out;
  }

  if (pwe->status != PASS_DB_ENTRY_ACTIVE) {
    if (pdbctx->debug)
      xerr_info("pass_db_auth(%s): not active", u_name);
    goto pass_db_auth_out;
  }

skip_exists:

  if ((pdbctx->type == PASS_DB_TYPE_LOCAL) ||
      (pdbctx->type == PASS_DB_TYPE_EX_LOCAL)) {

    /* authenticate with local crypt() */
    crypt_result = crypt(u_pass, pwe->u_hash);

    if (crypt_result) {
      if (!strcmp(pwe->u_hash, crypt_result)) {
        ret = PASS_DB_AUTH_SUCCESS;
        if (pdbctx->debug)
          xerr_info("pass_db_auth(%s): pass LOCAL authentication", u_name);
        goto pass_db_auth_out;
      }
    }

  } else if ((pdbctx->type == PASS_DB_TYPE_PAM) ||
             (pdbctx->type == PASS_DB_TYPE_EX_PAM)) {

    /* authenticate with PAM */
    ret = pam_auth(u_name, u_pass, pdbctx->loc);

    if (ret == PASS_DB_AUTH_SUCCESS) {
      if (pdbctx->debug)
        xerr_info("pass_db_auth(%s): pass PAM authentication", u_name);
        goto pass_db_auth_out;
    }

  } /* _PAM */

  if (pdbctx->debug)
    xerr_info("pass_db_auth(%s): fail authentication", u_name);

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
  struct stat cur_sb;
  uint16_t u_hash, u_hash_mask;
  int ret, i;
  char *pw_buf, *au_buf, *p_buf;
  char *p, *pwdb_u_name, *pwdb_u_hash, *au_name;
  uint pw_entry, lineno;
  uint pwdb_u_name_len, pwdb_u_hash_len, au_name_len;
  int local_status_default, au_only, au_active;

  ret = -1;

  pw_buf = (char*)0L;
  au_buf = (char*)0L;

  au_only = 0;   /* authorized users without passwd */
  au_active = 0; /* load and process authorized_users */

  /* optimization, PASS_DB_TYPE_EX_PAM does not require local resources */
  if (pdbctx->type == PASS_DB_TYPE_EX_PAM)
    return 0;

  /* using authorized_users? */
  if ((pdbctx->type ==  PASS_DB_TYPE_PAM) ||
    (pdbctx->type ==  PASS_DB_TYPE_LOCAL)) {

    au_active = 1;

    if (!pdbctx->au_fname) {
      xerr_warnx("Authorized users file not defined");
      goto pass_db_load_out;
    }
  }

  /* username hash mask */
  u_hash_mask = (uint16_t)((1<<PASS_DB_HASH_BUCKET_BITS)-1);

  /*
   * status default is used when the password and authorized_users are
   * both active
   */

  /* if using authorized users, then default to inactive */
  if (pdbctx->type == PASS_DB_TYPE_LOCAL)
    local_status_default = PASS_DB_ENTRY_INACTIVE;
  else if (pdbctx->type == PASS_DB_TYPE_EX_LOCAL)
    local_status_default = PASS_DB_ENTRY_ACTIVE;


  /*
   * special case, PAM + authorized users: do not load passwd database,
   * only authorized_users.  
   */
  if (pdbctx->type == PASS_DB_TYPE_PAM) {

    au_only = 1;
    if (pdbctx->debug)
      xerr_info("pass_db_load(): PAM, loading authorized users only");

  } else {

    /* load current passwd file metadata */
    if (stat(pdbctx->loc, &cur_sb) < 0) {
      xerr_warnx("stat(%s)", pdbctx->loc);
      goto pass_db_load_out;
    }

  
    pdbctx->pw_sb = cur_sb;


    /* load password database into memory */
    if (!(pw_buf = file_load(pdbctx->loc))) {
      xerr_warnx("file_load(%s): failed", pdbctx->loc);
      goto pass_db_load_out;
    }

  }

  /* load authorized_users file if configured */
  if (au_active == 1) {

    /* load current authorized_users file metadata */
    if (stat(pdbctx->au_fname, &cur_sb) < 0) {
      xerr_warnx("stat(%s)", pdbctx->au_fname);
      goto pass_db_load_out;
    }

  
    pdbctx->au_sb = cur_sb;

    if (!(au_buf = file_load(pdbctx->au_fname))) {
      xerr_warnx("file_load(%s): failed", pdbctx->au_fname);
      goto pass_db_load_out;
    }

  } /* au_active */

  if (au_only) {

    /* count number of lines in authorized_users to predict malloc size */
    for (pdbctx->num_entries = 0, p = au_buf; *p; ++p) {
      if (*p == '\n')
        ++pdbctx->num_entries;
    }

   } else {

    /* count number of lines in passwd file to predict malloc size */
    for (pdbctx->num_entries = 0, p = pw_buf; *p; ++p) {
      if (*p == '\n')
        ++pdbctx->num_entries;
    }

  }

  if (pdbctx->debug)
    xerr_info("pass_db_load(): loading %d users", pdbctx->num_entries);

  if (!(pdbctx->pw_entries = (struct pass_db_entry*)malloc(
    pdbctx->num_entries * sizeof (struct pass_db_entry)))) {
    xerr_warn("malloc(pw_entries)");
    goto pass_db_load_out;
  } /* allocate entries */

  bzero(pdbctx->pw_entries,
    pdbctx->num_entries * sizeof (struct pass_db_entry));

  /* if only using authorized users passwd file parsing is skipped */
  if (au_only)
    p_buf = au_buf;
  else
    p_buf = pw_buf;

  /* while more lines */
  for (p = p_buf, lineno = 1, pw_entry = 0; *p; ++lineno, ++pw_entry) {

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

      /* only username if au_only */
      if (au_only)
        if ((*p == 0) || (*p == '\n'))
          break;

      /* require minimum of u_name and password field */
      if ((*p == 0) || (*p == '\n')) {
        *p = 0; /* null terminate */
        xerr_warnx("pass_db_auth(%s): lineno=%d, parse error at %s",
          pdbctx->loc, lineno, pwdb_u_name);
        ret = PASS_DB_AUTH_ERROR;
        goto pass_db_load_out;
      }

      ++p;

    } /* extract u_name */

    /* password hash is next if not au_only */
    if (!au_only) {

      /* hash of u_pass is next */
      pwdb_u_hash = p;

      for (pwdb_u_hash_len = 0;;pwdb_u_hash_len++) {

        /* end of u_pass hash field (possibly EOL or EOF */
        if ((*p == 0) || (*p == '\n') || (*p == ':'))
          break;

        ++p;

      } /* extract u_pass hash */

    }

    /* skip to next line */
    for (; *p && *p != '\n'; ++p);

    if (*p == '\n');
      ++p;

    /* u_name len 0 is illegal */
    if (pwdb_u_name_len == 0) {
      xerr_warnx("pass_db_auth(%s): lineno=%d, pwdb_u_name_len=0",
        pdbctx->loc, lineno);
      ret = PASS_DB_AUTH_ERROR;
      goto pass_db_load_out;
    }

    /* u_hash only if parsing passwd */
    if (!au_only) {

      /* u_hash len 0 is illegel */
      if (pwdb_u_hash_len == 0) {
        xerr_warnx("pass_db_auth(%s): lineno=%d, pwdb_u_hash_len=0",
          pdbctx->loc, lineno);
        ret = PASS_DB_AUTH_ERROR;
        goto pass_db_load_out;
      }


      /* bounds check u_hash_len */
      if (pwdb_u_hash_len > PASS_DB_USER_HASH_LEN) {
        xerr_warnx("pass_db_auth(%s): lineno=%d, pwdb_u_hash_len=%d >%d ",
          pdbctx->loc, lineno, pwdb_u_hash_len, PASS_DB_USER_HASH_LEN);
        ret = PASS_DB_AUTH_ERROR;
        goto pass_db_load_out;
      }

    }

    /* bounds check u_name_len */
    if (pwdb_u_name_len > PASS_DB_USER_NAME_LEN) {
      xerr_warnx("pass_db_auth(%s): lineno=%d, pwdb_u_name=%d >%d ",
        pdbctx->loc, lineno, pwdb_u_name_len, PASS_DB_USER_NAME_LEN);
      ret = PASS_DB_AUTH_ERROR;
      goto pass_db_load_out;
    }

    pwe = &pdbctx->pw_entries[pw_entry];

    /* store as C string (null termination is handled above in bzero() ) */
    bcopy(pwdb_u_name, &pwe->u_name, pwdb_u_name_len);
    pwe->u_name_len = pwdb_u_name_len;

    if (!au_only) {
      bcopy(pwdb_u_hash, &pwe->u_hash, pwdb_u_hash_len);
      pwe->u_hash_len = pwdb_u_hash_len;
      pwe->status = local_status_default;
    } else {
      pwe->u_hash_len = 0;
      pwe->status = PASS_DB_ENTRY_ACTIVE;
    }
 
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
  if (au_active && (!au_only)) {

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

  } /* au_active && !au_only */

  pdbctx->state = PASS_DB_STATE_LOADED;

  ret = 0; /* good */

pass_db_load_out:

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

static int pam_auth(char *user_name, char *user_pass, char *svc_name)
{
  struct pam_conv pam_conv;
  pam_handle_t *pam_h;
  int pam_err, pass_db_ret;

  bzero(&pam_conv, sizeof pam_conv);
  pam_h = (pam_handle_t*)0L;

  pam_conv.conv = &pam_mem_conv;
  pam_conv.appdata_ptr = (void*)0L;

  pass_db_ret = PASS_DB_AUTH_ERROR;

  global_user_pass = user_pass;

  /* PAM must run as root */
  if (getuid() != 0) {
    xerr_warnx("pam_db_auth(): getuid() != 0");
    goto pam_auth_out;
  }

  /* startup PAM */
  if ((pam_err = pam_start (svc_name, user_name, &pam_conv,
    &pam_h)) != PAM_SUCCESS) {
    xerr_warnx("pam_start(): %s", pam_strerror(pam_h, pam_err));
    goto pam_auth_out;
  }

  pam_err = pam_authenticate(pam_h, 0);

  if (pam_err == PAM_SUCCESS) {
    pass_db_ret = PASS_DB_AUTH_SUCCESS;
  } else {
    pass_db_ret = PASS_DB_AUTH_FAIL;
  }

pam_auth_out:

  /* shutdown PAM */
  if (pam_h)
    pam_end(pam_h, 0);

  return pass_db_ret;

} /* pam_db_auth */

int pam_mem_conv (int pam_nmsg, const struct pam_message **pam_msgh,
  struct pam_response **pam_resph, void *pam_app_data)
{
  int i, pam_err, pass_len;

  *pam_resph = (void*)0L;

  pass_len = strlen(global_user_pass);

  if ((pam_nmsg <= 0) || (pam_nmsg >= PAM_MAX_NUM_MSG)) {
    xerr_warnx("check_conv(): invalid pam_nmsg=%d", pam_nmsg);
    pam_err = PAM_CONV_ERR;
    goto pam_mem_conv_out;
  }

  /* allocate storage for responses, to be free()'d by caller or us on err */
  if (!(*pam_resph = (struct pam_response*)malloc(pam_nmsg *
    sizeof (struct pam_response) ))) {
    xerr_warn("malloc(pam_nmsg=%d)", pam_nmsg);
    pam_err = PAM_BUF_ERR;
    goto pam_mem_conv_out;
  }

  bzero(*pam_resph, pam_nmsg*sizeof (struct pam_response));

  for (i = 0; i < pam_nmsg; ++i) {

    switch (pam_msgh[i]->msg_style) {

      case PAM_PROMPT_ECHO_OFF:
      case PAM_PROMPT_ECHO_ON:

        /* allocate space for password */
        if (!((*pam_resph)[i].resp = (char*)malloc(pass_len+1))) {
          xerr_warn("malloc(l_passwd):");
          pam_err = PAM_BUF_ERR;
          goto pam_mem_conv_out;
        }

        bcopy(global_user_pass, (*pam_resph)[i].resp, pass_len+1);
        break;

      case PAM_ERROR_MSG:
      case PAM_TEXT_INFO:
        xerr_warnx("PAM_MSG: %s", pam_msgh[i]->msg);
        break;

      default:
        xerr_warnx("Ignoring unexpected msg_style=%d", pam_msgh[i]->msg_style);
        break;

    } /* switch */

  } /* foreach message */

  return (PAM_SUCCESS);

pam_mem_conv_out:

  if (*pam_resph) {

    for (i = 0; i < pam_nmsg; ++i)
      if ((*pam_resph)[i].resp)
        free((*pam_resph)[i].resp);

    free(*pam_resph);

  }

  return pam_err;

} /* pam_mem_conv */

