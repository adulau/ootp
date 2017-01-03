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
 *      $Id: ffdb.c 13 2009-11-26 16:37:03Z maf $
 */

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

#include "xerr.h"
#include "ffdb.h"

/*
 * Simple flat file database.  Each key/data pair is stored in an
 * individual file.  Read and Write operations are atomic to avoid
 * race conditions when using dump or tar for live backups.  A key
 * (file) is locked during a read (shared lock) or write (exclusive lock)
 * operation.  Non ASCII keys can optionally be encoded in ASCII HEX 
 * for mapping to readable valid filenames.
 *
 **** 
 *
 * ffdb_ctx_new()       allocate new ffdb context
 * 
 * ffdb_ctx_free()      free ffdb context
 *  
 * ffdb_ctx_key_pn()    create pathname from key
 * 
 * ffdb_ctx_valid()     check ffdb context
 *
 ****
 *
 * ffdb_db_info()       ffdb info
 * 
 * ffdb_db_open()       open ffdb
 *
 * ffdb_db_close()      close ffdb
 *
 * ffdb_db_verbose()    set ffdb verbosity / debugging
 *
 ****
 *
 * ffdb_rec_exists()    test exists ffdb rec
 *
 * ffdb_rec_rm()        remove ffdb re
 *
 * ffdb_rec_iter()      iterate over ffdb rec's
 *
 ****
 *
 * ffdb_rec_open()      open ffdb rec
 *
 * ffdb_rec_close()     close ffdb rec
 *
 * ffdb_rec_get()       get/read ffdb rec
 *
 * ffdb_rec_put()       put/write ffdb rec
 *
 * ffdb_rec_lock()      lock/unlock ffdb rec
 * 
 */

/* private functions */
static uint8_t nta(uint8_t b);
static struct ffdb_ctx *ffdb_ctx_new(size_t max_key_size, size_t max_val_size,
  uint32_t flags);
static void ffdb_ctx_free(struct ffdb_ctx *ffdbctx);
static int ffdb_ctx_key_pn(struct ffdb_ctx *ffdbctx, struct ffdb_key *key);
static int ffdb_ctx_valid(struct ffdb_ctx *ffdbctx, char *who);


/*
 * function: nta()
 *
 * return ASCII value of low hex nybble
 *
 */
static uint8_t nta(uint8_t b)
{
  if (b < 10)
    b = '0' + b;
  else
    b = 'A' + (b-10);
    
  return b;
} /* nta */


/*
 * function: ffdb_ctx_new()
 *
 * Allocate a ffdb context with a maximum key size of max_key_size,
 * maximum value size of max_val_size.
 *
 * This is an internal function called by ffdb_db_open()
 *
 * arguments:
 *
 *  max_key_size - maximum key size
 *  max_val_size - maximum value size
 *  flags        - FFDB_DB_*
 *
 * returns: allocated and initialized ffdb_ctx, or 0L on failure.
 *
 */
static struct ffdb_ctx *ffdb_ctx_new(size_t max_key_size, size_t max_val_size,
  uint32_t flags)
{
  struct ffdb_ctx *ffdbctx;
  int ret;

  ret = -1; /* fail */

  if (!(ffdbctx = (struct ffdb_ctx*)malloc(sizeof *ffdbctx))) {
    xerr_warn("malloc(ffdbctx)");
    goto ffdb_ctx_new_out;
  }

  bzero(ffdbctx, sizeof *ffdbctx);

  ffdbctx->max_key_size = max_key_size;
  ffdbctx->max_val_size = max_val_size;
  ffdbctx->flags = flags;
  ffdbctx->valid = 1;
  ffdbctx->rec_open_ref_count = 0;

  if (!(ffdbctx->val.val = (char*)malloc(max_val_size))) {
    if (ffdbctx->verbose)
      xerr_warn("malloc(ffdbctx->val.val)");
    goto ffdb_ctx_new_out;
  }

  ret = 0;

ffdb_ctx_new_out:

  if (ret == -1) {
    ffdb_ctx_free(ffdbctx);
    ffdbctx = (struct ffdb_ctx*)0L;
  }

  return ffdbctx;

} /* ffdb_ctx_new */

/*
 * function: ffdb_ctx_free()
 *
 * Free resources in ffdb context.
 *
 * arguments:
 *
 *  ffdbctx - context from ffdb_ctx_new()
 *
 * This is an internal function called by ffdb_db_close() and/or
 * ffdb_db_open()
 *
 */
void ffdb_ctx_free(struct ffdb_ctx *ffdbctx)
{

  if (ffdb_ctx_valid(ffdbctx, "ffdb_ctx_free") == -1)
    return;

  if (ffdbctx->base_dir_pn) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_ctx_free(): fatal context has open db.");
    return;
  }

  if (ffdbctx->val.val) {
    bzero(ffdbctx->val.val, ffdbctx->max_val_size);
    free(ffdbctx->val.val);
    ffdbctx->val.val = (void*)0L;
  }

  /* iter which did not complete to last */
  if (ffdbctx->iter_DIR)
    closedir(ffdbctx->iter_DIR);


  if (ffdbctx) {
    bzero(ffdbctx, sizeof (*ffdbctx));
    free(ffdbctx);
  }

} /* ffdb_ctx_free */

/*
 * function: ffdb_ctx_key_pn()
 *
 * generate full pathname to key
 *
 * arguments:
 *
 *  ffdbctx - context from ffdb_ctx_new()
 *  key     - initialized key
 *
 * This is function used internally by ffdb_*
 *
 * returns: <0 error
 *           0 success
 *
 */
int ffdb_ctx_key_pn(struct ffdb_ctx *ffdbctx, struct ffdb_key *key)
{
  int i, j, bad;
  uint8_t *b;

  if (ffdb_ctx_valid(ffdbctx, "ffdb_ctx_key_pn") == -1)
    return -1;

  if (key->size > ffdbctx->max_key_size) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_make_fname(): fatal, max_key_size exceeded.");
    return -1;
  }

  /* encode key to ASCII HEX? */
  if (ffdbctx->flags & FFDB_DB_KEY_HEX) {

    ffdbctx->key_pn[ffdbctx->base_dir_pn_size + key->size*2+2] = 0;

    b = key->key;
    j = ffdbctx->base_dir_pn_size + 2;

    for (i = 0; i < key->size; ++i) {

      ffdbctx->key_pn[i+j] = nta(*b >> 4);
      ffdbctx->key_pn[i+j+1] = nta(*b & 0x0F);
      ++b;
      ++j;
    }

  } else {

    /*
     * keys which map directly to filenames need to be printable and
     * not have the pathname seperator
     */

    bad = 0;
    b = key->key;

    for (i = 0; i < key->size; ++i, ++b) {

      /* a-z */
      if ((*b >= 'a') && (*b <= 'z'))
        continue;

      /* A-Z */
      if ((*b >= 'A') && (*b <= 'Z'))
        continue;
      
      /* 0-9 */
      if ((*b >= '0') && (*b <= '9'))
        continue;

      /* .- */
      if ((*b == '.') || (*b == '-'))
        continue;

      bad = 1;
      break;

    }

    /* invalid char in key? */
    if (bad) {
      if (ffdbctx->verbose)
        xerr_warnx("ASCII key not in [a-zA-Z0-9.-]");
      return -1;
    }

    bcopy(key->key, &ffdbctx->key_pn[ffdbctx->base_dir_pn_size]+2,
      key->size);
    ffdbctx->key_pn[ffdbctx->base_dir_pn_size+key->size+2] = 0;

  } /* create pathname */

  return 0;

} /* ffdb_ctx_key_pn */

/*
 * function: ffdb_ctx_valid()
 *
 * Check if context is valid
 *
 * arguments:
 *
 *  ffdbctx - context from ffdb_ctx_new()
 *  who     - null terminated string representing calling function
 *
 * This is function used internally by ffdb_*
 *
 * returns: <0 error
 *           0 success
 *
 */
int ffdb_ctx_valid(struct ffdb_ctx *ffdbctx, char *who)
{

  if (!ffdbctx) {
    xerr_warnx("%s(): fatal, no context.", who);
    return -1;
  }

  if (!ffdbctx->valid) {
    if (ffdbctx->verbose)
      xerr_warnx("%s(): fatal, invalid context.", who);
    return -1;
  }

  return 0;

} /* ffdb_ctx_valid */

/*
 * function: ffdb_db_info()
 *
 * Gather stats on ffdb database referenced by base_dir_pn
 *
 * arguments:
 *
 *  base_dir_pn - base directory of a ffdb
 *  info        - stats including min and max key and value sizes
 *
 * returns: <0 error
 *           0 success
 *
 */
int ffdb_db_info(char *base_dir_pn, struct ffdb_info *info)
{
  DIR *dir;
  struct dirent *di;
  struct stat sb;
  char *d_path_name;
  int base_dir_pn_len, ret, d_namlen;
  size_t ts;

  ret = -1; /* fail */
  dir = (void*)0L;
  d_path_name = (void*)0L;

  base_dir_pn_len = strlen(base_dir_pn);

  bzero(info, sizeof (*info));

  /* storage to construct d_path_name as base_dir_pn/d/<filename> */
  if (!(d_path_name = (char*)malloc(base_dir_pn_len+4+MAXNAMLEN))) {
    xerr_warn("malloc(base_dir_pn_len+4)");
    goto ffdb_db_info_out;
  }

  /* construct d_path_name */
  bcopy(base_dir_pn, d_path_name, base_dir_pn_len);
  d_path_name[base_dir_pn_len] = '/';
  d_path_name[base_dir_pn_len+1] = 'd';
  d_path_name[base_dir_pn_len+2] = '/';
  d_path_name[base_dir_pn_len+3] = 0;

  /* database dir */
  if (!(dir = opendir(d_path_name))) {
    xerr_warn("opendir(%s)", d_path_name);
    goto ffdb_db_info_out;
  }

  while ((di = readdir(dir))) {

    d_namlen = strlen(di->d_name);

    if ((d_namlen == 1) && (di->d_name[0] == '.'))
      continue;

    if ((d_namlen == 2) && (di->d_name[0] == '.') &&
      (di->d_name[1] == '.')) 
      continue;

    ts = d_namlen; /* gcc: can't cast up portable */
    if (ts > MAXNAMLEN) {
      xerr_warnx("fddb_info(): fatal d_namlen >= MAXNAMLEN");
      return -1;
    }

    bcopy(di->d_name, &d_path_name[base_dir_pn_len+3], d_namlen);
    d_path_name[base_dir_pn_len+d_namlen+3] = 0;
    

    if (stat(d_path_name, &sb) < 0) {
      xerr_warn("stat(%s)", d_path_name);
      goto ffdb_db_info_out;
    }

    /* prime min's */
    if (info->num_keys == 0) {
      info->min_key_size = d_namlen;
      info->min_val_size = sb.st_size;
    }

    if (d_namlen > info->max_key_size)
      info->max_key_size = d_namlen;

    if (d_namlen < info->min_key_size)
      info->min_key_size = d_namlen;

    if (sb.st_size > info->max_val_size)
      info->max_val_size = sb.st_size;

    if (sb.st_size < info->min_val_size)
      info->min_val_size = sb.st_size;

    ++ info->num_keys;

  } /* while more dir entries to read */

  ret = 0; /* succes */

ffdb_db_info_out:

  if (d_path_name)
    free(d_path_name);

  if (dir)
    closedir(dir);

  return ret;

} /* ffdb_db_info */


/*
 * function: ffdb_db_open()
 *
 * Open a flat file database.  Database must be closed with ffdb_db_close()
 * to release allocated resources.
 *
 * arguments:
 *
 *  base_dir_pn  - base directory of a ffdb
 *  max_key_size - max size of key (database key)
 *  max_val_size - max size of value (database key value)
 *  flags        - db flags
 *    FFDB_DB_KEY_HEX        encode keys as ASCII HEX
 *    FFDB_DB_CREATE         create db
 *    FFDB_DB_SYNC_WRITES    enable synchronous writes
 *    FFDB_DB_STAT_READ      verify read size == stat size
 *    FFDB_DB_CREATE_SOFT    create db if it does not exist
 *    FFDB_DB_VERBOSE        verbose error messages
 *  file_mode    - unix mode bits to create files (database keys)
 *  dir_mode     - unix mode bits to create directories (database tree)
 *
 * returns: allocated and initialized ffdb_ctx on success
 *          0 on failure.
 *
 */
struct ffdb_ctx *ffdb_db_open(char *base_dir_pn, size_t max_key_size,
  size_t max_val_size, uint32_t flags, mode_t file_mode, mode_t dir_mode)
{
  struct stat sb;
  struct ffdb_ctx *ffdbctx;
  size_t key_pn_size, base_dir_pn_size;
  int ret, verbose;

  if (flags & FFDB_DB_VERBOSE)
    verbose = 1;
  else
    verbose = 0;

  ret = -1; /* fail */

  base_dir_pn_size = strlen(base_dir_pn) + 1;

  /*
   * key file is base_dir_pn/d/keyname
   * strlen(base_dir_pn) + 3(/d/) + key_name_length + 1(NULL)
   *
   * hex encoded keys are two ASCII bytes per key byte
   *
   * String is null terminated.  ffdbctx->base_dir_pn_size includes
   * space for / (without null).
   *
   * calcs:
   *  base_dir_pn = "b"
   *  base_dir_pn_size = strlen("b")+1 = 2
   *         01234567890
   *  key_pn = "b/d/KEY"
   *  key_pn = "b/d/AABBCC" (hex)
   *  key_pn_size = 8 = base_dir_pn_size + 3 + strlen(KEY) = 2 + 3 + 3
   *  key_pn_size_hex = 11 = base_dir_pn_size + 3 + strlen(KEY)*2 = 2 + 3 + 3*2
   *
   *
   *  / = base_dir_pn_size -1
   *  d = base_dir_pn_size 0
   *  / = base_dir_pn_size +1
   *  0 = base_dir_pn_size +2
   */

  /* hex key requires 2 bytes/byte when encoded */
  if (flags & FFDB_DB_KEY_HEX)
    key_pn_size = base_dir_pn_size + max_key_size*2 + 3;
  else
    key_pn_size = base_dir_pn_size + max_key_size + 3;

  if (key_pn_size > MAXNAMLEN) {
    if (verbose)
      xerr_warnx("ffdb_db_open(): key_pn_size > MAXNAMELEN");
    goto ffdb_db_open_out;
  }

  if (!(ffdbctx = ffdb_ctx_new(max_key_size, max_val_size, flags))) {
    if (verbose)
      xerr_warnx("ffdb_ctx_new(): failed");
    goto ffdb_db_open_out;
  }

  ffdbctx->verbose = verbose;
  ffdbctx->base_dir_pn_size = base_dir_pn_size;
  ffdbctx->file_mode = file_mode;
  ffdbctx->key_pn_size = key_pn_size;

  /* allocate mem for base dir */
  if (!(ffdbctx->base_dir_pn = (char*)malloc(ffdbctx->base_dir_pn_size))) {
    if (verbose)
      xerr_warn("malloc(ffdbctx->base_dir_pn)");
    goto ffdb_db_open_out;
  }

  /* copy in base_dir_pn */
  bcopy(base_dir_pn, ffdbctx->base_dir_pn, ffdbctx->base_dir_pn_size);

  /* allocate mem for key pathname */
  if (!(ffdbctx->key_pn = (char*)malloc(ffdbctx->key_pn_size))) {
    if (verbose)
      xerr_warn("malloc(ffdbctx->key_pn)");
    goto ffdb_db_open_out;
  }

  /* base dir of key will always be basedir/ */
  bcopy(base_dir_pn, ffdbctx->key_pn, ffdbctx->base_dir_pn_size);
  ffdbctx->key_pn[ffdbctx->base_dir_pn_size-1] = '/';
  ffdbctx->key_pn[ffdbctx->base_dir_pn_size+0] = 'd';
  ffdbctx->key_pn[ffdbctx->base_dir_pn_size+1] = '/';
  ffdbctx->key_pn[ffdbctx->base_dir_pn_size+2] = 0;

  /* create db dir? */
  if ((flags & FFDB_DB_CREATE) || (flags & FFDB_DB_CREATE_SOFT)) {

    ret = mkdir(base_dir_pn, dir_mode);

    if ((ret < 0) && (errno == EEXIST) && (flags & FFDB_DB_CREATE_SOFT))
      goto ffdb_db_open_skip1;

    if (ret < 0) {
      if (verbose)
        xerr_warn("mkdir(%s)", base_dir_pn);
      goto ffdb_db_open_out;
    }

ffdb_db_open_skip1:

    ret = mkdir(ffdbctx->key_pn, dir_mode);

    if ((ret < 0) && (errno == EEXIST) && (flags & FFDB_DB_CREATE_SOFT))
      goto ffdb_db_open_skip2;

    if (ret < 0) {
      if (verbose)
        xerr_warn("mkdir(%s)", ffdbctx->key_pn);
      goto ffdb_db_open_out;
    }

  } else {

    if (stat(ffdbctx->key_pn, &sb) < 0) {
      if (verbose)
        xerr_warn("stat(%s)", ffdbctx->key_pn);
      goto ffdb_db_open_out;
    }

    if (!S_ISDIR(sb.st_mode)) {
      if (verbose)
        xerr_warnx("S_ISDIR(%s): failed", ffdbctx->key_pn);
      goto ffdb_db_open_out;
    }

  } /* FFDB_DB_CREATE */

ffdb_db_open_skip2:

  ret = 0; /* success */

ffdb_db_open_out:

  if (ret == -1) {

    if (ffdbctx) {

      if (ffdbctx->base_dir_pn) {
        bzero(ffdbctx->base_dir_pn, ffdbctx->base_dir_pn_size);
        free(ffdbctx->base_dir_pn);
        ffdbctx->base_dir_pn = (void*)0L;
      }

      if (ffdbctx->key_pn) {
        bzero(ffdbctx->key_pn, ffdbctx->key_pn_size);
        free(ffdbctx->key_pn);
        ffdbctx->key_pn = (void*)0L;
      }

      bzero(ffdbctx, sizeof *ffdbctx);
      ffdb_ctx_free(ffdbctx);
      ffdbctx = (void*)0L;

    } /* ffdbctx */

  } /* error */

  return ffdbctx;

} /* ffdb_db_open */

/*
 * function: ffdb_db_close()
 *
 * Close a flat file database opened with ffdb_db_open()
 *
 * arguments:
 *
 *  ffdbctx      - ffdb context
 *
 * returns: <0 failure
 *           0 success
 *
 */
int ffdb_db_close(struct ffdb_ctx *ffdbctx)
{

  if (ffdb_ctx_valid(ffdbctx, "ffdb_db_close") == -1)
    return -1;

  if (ffdbctx->rec_open_ref_count != 0) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_rec_close(): rec_open_ref_count != 0.");
    return -1;
  }

  if (ffdbctx->base_dir_pn) {
    bzero(ffdbctx->base_dir_pn, ffdbctx->base_dir_pn_size);
    free(ffdbctx->base_dir_pn);
    ffdbctx->base_dir_pn = (void*)0L;
  }

  if (ffdbctx->key_pn) {
    bzero(ffdbctx->key_pn, ffdbctx->key_pn_size);
    free(ffdbctx->key_pn);
    ffdbctx->key_pn = (void*)0L;
  }

  bzero(ffdbctx, sizeof *ffdbctx);
  ffdb_ctx_free(ffdbctx);
  ffdbctx = (void*)0L;

  return 0;

} /* ffdb_db_close */


/*
 * function: ffdb_db_verbose()
 *
 * Enable/disable verbose warnings and errors with xerr_* functions.
 *
 * arguments:
 *
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  verbose      - verbose level 0=no messages, > 0 to display messages.
 *
 */
void ffdb_db_verbose(struct ffdb_ctx *ffdbctx, int verbose)
{
  if (ffdb_ctx_valid(ffdbctx, "ffdb_db_verbose") == -1)
    return;

  ffdbctx->verbose = verbose;
} /* ffdb_db_verbose */

/*
 * function: ffdb_db_exists()
 *
 * Test if a key exists in database.
 *
 * arguments:
 *
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  key          - database key to check
 *
 *  returns: <0 error
 *            0 key exists
 *            1 key does not exist
 */
int ffdb_rec_exists(struct ffdb_ctx *ffdbctx, struct ffdb_key *key)
{
  struct stat sb;
  int ret;

  if (ffdb_ctx_valid(ffdbctx, "ffdb_rec_exists") == -1)
    return -1;

  /* create pathname */
  if (ffdb_ctx_key_pn(ffdbctx, key) < 0) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_ctx_key_pn(): failed");
    return -1;
  }

  ret = stat(ffdbctx->key_pn, &sb);

  /* key exists? */
  if (ret == 0)
    return 0;

  /* key does not exist? */
  if ((ret <0) && (errno == ENOENT))
    return 1;

  /* fail? */
  if ((ret < 0) && ffdbctx->verbose)
    if (ffdbctx->verbose)
      xerr_warn("stat(%s)", ffdbctx->key_pn);

  return ret;

} /* ffdb_rec_exists */

/*
 * function: ffdb_db_exists()
 *
 * Remove a key from database
 *
 * arguments:
 *
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  key          - database key to remove
 *
 *  returns: <0 error
 *            0 success (key removed)
 */
int ffdb_rec_rm(struct ffdb_ctx *ffdbctx, struct ffdb_key *key)
{
  int ret;

  if (ffdb_ctx_valid(ffdbctx, "ffdb_rec_rm") == -1)
    return -1;

  /* create pathname */
  if (ffdb_ctx_key_pn(ffdbctx, key) < 0) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_ctx_key_pn(): failed");
    return -1;
  }

  ret = unlink(ffdbctx->key_pn);

  /* success? */
  if ((ret < 0) && ffdbctx->verbose)
    if (ffdbctx->verbose)
      xerr_warn("unlink(%s)", ffdbctx->key_pn);

  return ret;

} /* ffdb_rec_rm */

/*
 * function: ffdb_rec_iter()
 *
 * Iterate over keys in a database.  The first key is returned
 * by setting FFDB_ITER_FIRST.  Additional calls to ffdb_db_iter()
 * will set FFDB_ITER_NEXT.  When no more entries are available 
 * ffdb_db_iter() will return 1.  If the database walk is stopped
 * before the last entry, a last call to ffdb_db_iter() must set the
 * FFDB_ITER_DONE flag to free allocated resources.
 *
 * If the FFDB_ITER_DONE flag is set, a record value will be returned
 * in val.  val is overwritten on each call.  The caller is responsible
 * for copying this value out to permanent storage if necessary.
 *
 * arguments:
 *
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  key          - database key returned
 *  val          - optional database value returned
 *  iter_flags
 *    FFDB_ITER_FIRST  set on first call
 *    FFDB_ITER_NEXT   set after first call
 *    FFDB_ITER_GET    do ffdb_rec_get() / return value
 *    FFDB_ITER_DONE   clear resources allocated by FIRST
 *
 *  returns: <0 error
 *            0 success
 *            1 no more entries
 */
int ffdb_rec_iter(struct ffdb_ctx *ffdbctx, struct ffdb_key *key, 
  struct ffdb_val *val, int iter_flags)
{
  struct dirent *di;
  int ret, d_namlen;

  ret = -1; /* fail */

  if (ffdb_ctx_valid(ffdbctx, "ffdb_rec_iter") == -1)
    return -1;

  if (iter_flags & FFDB_ITER_DONE) {

    if (ffdbctx->iter_DIR)
      closedir(ffdbctx->iter_DIR);

    ffdbctx->iter_DIR = (void*)0L;

    return 0;

  } /* FFDB_ITER_DONE */

  if (iter_flags & FFDB_ITER_FIRST) {

    /* just the dir */
    ffdbctx->key_pn[ffdbctx->base_dir_pn_size+2] = 0;

    /* previous call which did not complete to last entry */
    if (ffdbctx->iter_DIR)
      closedir(ffdbctx->iter_DIR);

    ffdbctx->iter_DIR = (void*)0L;

    if (!(ffdbctx->iter_DIR = opendir(ffdbctx->key_pn))) {
      xerr_warn("opendir(%s)", ffdbctx->key_pn);
      goto ffdb_rec_iter_out;
    }

  } /* FFDB_ITER_FIRST */

  while (1) {

    di = readdir(ffdbctx->iter_DIR);

    /* last? */
    if (!di) {
      ret = 1; /* last */
      closedir(ffdbctx->iter_DIR);
      ffdbctx->iter_DIR = (void*)0L;
      goto ffdb_rec_iter_out;
    }

    d_namlen = strlen(di->d_name);

    if ((d_namlen == 1) && (di->d_name[0] == '.'))
      continue;

    if ((d_namlen == 2) && (di->d_name[0] == '.') &&
      (di->d_name[1] == '.')) 
      continue;

    key->key = di->d_name;
    key->size = d_namlen;

    if (iter_flags & FFDB_ITER_GET) {

      ret = ffdb_rec_open(ffdbctx, key, O_RDONLY, FFDB_OP_LOCK_SH);
      if (ret != -1) {
        ret = ffdb_rec_get(ffdbctx, key, val, 0);
        ffdb_rec_close(ffdbctx, key);
      }
      break;

    } else {

      ret = 0;
      break;

    } /* FFDB_ITER_GET */

  } /* get next item, not . or .. */

ffdb_rec_iter_out:

  return ret;

} /* ffdb_rec_iter */

/*
 * function: ffdb_rec_open()
 *
 * Open a database record for reading/writing.
 *
 * Once a database record is open ffdb_rec_put(), ffdb_rec_get(), and
 * ffdb_rec_get() can be used on the key.
 *
 * ffdb_rec_close() must be called on an open record to free resources
 * allocated by ffdb_rec_open()
 *
 * arguments:
 *
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  key          - database key returned
 *  open_flags   - see open(2)
 *  op_flags     -
 *    FFDB_OP_LOCK_NONE   - no locking
 *    FFDB_OP_LOCK_SH     - shared lock
 *    FFDB_OP_LOCK_EX     - exclusive lock
 *    FFDB_OP_LOCK_NB     - non blocking lock
 *    FFDB_OP_LOCK_UN     - unlock
 *
 *  returns: <0 error
 *            0 success
 */
int ffdb_rec_open(struct ffdb_ctx *ffdbctx, struct ffdb_key *key,
  int open_flags, int op_flags)
{
  struct stat sb;
  int ret, lock_flags;
  extern int errno;

  if (ffdb_ctx_valid(ffdbctx, "ffdb_rec_open") == -1)
    return -1;

  key->fd = -1;
  lock_flags = 0;

  /* create pathname */
  if (ffdb_ctx_key_pn(ffdbctx, key) < 0) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_ctx_key_pn(): failed");
    return -1;
  }

  /* open w. lock? */
  if (op_flags & FFDB_OP_LOCK_SH)
#ifdef O_SHLOCK
    open_flags |= O_SHLOCK;
#else
    lock_flags |= LOCK_SH;
#endif /* O_SHLOCK */

  if (op_flags & FFDB_OP_LOCK_EX)
#ifdef O_EXLOCK
    open_flags |= O_EXLOCK;
#else
    lock_flags |= LOCK_EX;
#endif /* O_EXLOCK */

  if (op_flags & FFDB_OP_LOCK_NB) {
    open_flags |= O_NONBLOCK;
    lock_flags |= LOCK_NB;
  }

  if (ffdbctx->flags & FFDB_DB_STAT_READ) {

    ret = stat(ffdbctx->key_pn, &sb);

    /*
     * if key does not exist, and may be creating it later, ignore
     */
    if (!((ret < 0) && (errno == ENOENT) && (open_flags & O_CREAT))) {

      if ((ffdbctx->verbose) && (ret < 0))
        xerr_warn("stat(%s)", ffdbctx->key_pn);

      if (ret < 0)
        goto ffdb_rec_open_out;

      if (sb.st_size > ffdbctx->max_val_size)
        if (ffdbctx->verbose)
          xerr_warnx("ffdb_rec_open(): sb.st_size > max_val_size");

    }

  } /* FFDB_DB_STAT_READ */

  ret = open(ffdbctx->key_pn, open_flags, ffdbctx->file_mode);

  if ((ret < 0) && ffdbctx->verbose)
    xerr_warn("open(%s)", ffdbctx->key_pn);

  key->fd = ret;

  if (ret < 0)
    goto ffdb_rec_open_out;

  if (lock_flags) {

    ret = flock(key->fd, lock_flags);

    if ((ret < 0) && ffdbctx->verbose)
      xerr_warn("flock(%s)", ffdbctx->key_pn);

    if (ret < 0)
      goto ffdb_rec_open_out;

  } /* lock_flags */

  ret = 0; /* success */
  ffdbctx->rec_open_ref_count ++;

ffdb_rec_open_out:

  return ret;

} /* ffdb_rec_open  */

/*
 * function: ffdb_rec_close()
 *
 * Close a database record opened with ffdb_rec_open()
 *
 * arguments:
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  key          - database key
 *
 *  returns: <0 error
 *            0 success
 */
int ffdb_rec_close(struct ffdb_ctx *ffdbctx, struct ffdb_key *key)
{
  int r;

  if (ffdb_ctx_valid(ffdbctx, "ffdb_rec_close") == -1)
    return -1;

  if (key->fd == -1) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_rec_close(): invalid fd.");
    return -1;
  }

  if (ffdbctx->rec_open_ref_count == 0) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_rec_close(): rec_open_ref_count == 0.");
    return -1;
  }

  if (!ffdbctx->valid) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_rec_close(): fatal, invalid context.");
    return -1;
  }

  r = close(key->fd);
  key->fd = -1;
  ffdbctx->rec_open_ref_count --;
  return r;

} /* ffdb_rec_close */

/*
 * function: ffdb_rec_get()
 *
 * Get a database record (value) opened with ffdb_rec_open().
 *
 * arguments:
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  key          - database key (in)
 *  val          - database key value (out)
 *  op_flags
 *    FFDB_OP_REWIND_NO - do not rewind() after read()
 *    FFDB_OP_VAL_ALLOC - allocate a private copy of val for caller
 *
 *  returns: <0 error
 *            0 success
 */
int ffdb_rec_get(struct ffdb_ctx *ffdbctx, struct ffdb_key *key,
  struct ffdb_val *val, int op_flags)
{
  int ret;

  ret = -1; /* fail */

  if (ffdb_ctx_valid(ffdbctx, "ffdb_rec_get") == -1)
    return -1;

  if (key->fd == -1) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_rec_get(): invalid fd.");
    return -1;
  }

  val->val = (void*)0L;

  /* allocate storage for val? */
  if (op_flags & FFDB_OP_VAL_ALLOC) {

    if (!(val->val = (char*)malloc(ffdbctx->max_val_size))) {
      if (ffdbctx->verbose)
        xerr_warn("malloc(val->val)");
      goto ffdb_rec_get_out;
    }

  /* no, use scratch val in context */
  } else {

    val->val = ffdbctx->val.val;

  }

  ret = read(key->fd, val->val, ffdbctx->max_val_size);

  if (!(op_flags & FFDB_OP_REWIND_NO))
    lseek(key->fd, (off_t)0L, SEEK_SET);

  if ((ret < 0) && ffdbctx->verbose)
    if (ffdbctx->verbose)
      xerr_warn("read(%s)", ffdbctx->key_pn);

  if (ret < 0)
    goto ffdb_rec_get_out;

  if (op_flags & FFDB_OP_VAL_ALLOC)
    ffdbctx->val.size = ret;

  val->size = ret;

  ret = 0; /* success */

ffdb_rec_get_out:

  return ret;

} /* ffdb_rec_get */

/*
 * function: ffdb_rec_put()
 *
 * Put a database record (value) opened with ffdb_rec_open().
 *
 * arguments:
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  key          - database key (out)
 *  val          - database key value (out)
 *  op_flags
 *   FFDB_OP_TRUNCATE_NO do not truncate before write()
 *   FFDB_OP_REWIND_NO - do not rewind() after write()
 *
 *  returns: <0 error
 *            0 success
 */
int ffdb_rec_put(struct ffdb_ctx *ffdbctx, struct ffdb_key *key,
  struct ffdb_val *val, int op_flags)
{
  int ret;

  if (ffdb_ctx_valid(ffdbctx, "ffdb_rec_put") == -1)
    return -1;

  if (key->fd == -1) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_rec_put(): invalid fd.");
    return -1;
  }

  if (!(op_flags & FFDB_OP_TRUNCATE_NO)) {
    ret = ftruncate(key->fd, (off_t)0L);
    if (ret < 0) {
      if (ffdbctx->verbose)
        xerr_warn("ftruncate(%s)", ffdbctx->key_pn);
      goto ffdb_rec_put_out;
    }
  }

  ret = write(key->fd, val->val, val->size);

  if (ret < 0) {
    if (ffdbctx->verbose)
      xerr_warn("write(%s)", ffdbctx->key_pn);
    goto ffdb_rec_put_out;
  }

  if (ffdbctx->flags & FFDB_DB_SYNC_WRITES) {
    ret = fsync(key->fd);
    if (ret < 0) {
      if (ffdbctx->verbose)
        xerr_warn("fsync(%s)", ffdbctx->key_pn);
      goto ffdb_rec_put_out;
    }
  } /* FFDB_DB_SYNC_WRITES */

  if (!(op_flags & FFDB_OP_REWIND_NO)) {
    ret = lseek(key->fd, (off_t)0L, SEEK_SET);
    if (ret < 0) {
      if (ffdbctx->verbose)
        xerr_warn("lseek(%s)", ffdbctx->key_pn);
      goto ffdb_rec_put_out;
    }
  }

  if (ret < 0)
    goto ffdb_rec_put_out;

  ret = 0; /* success */

ffdb_rec_put_out:

  return ret;

} /* ffdb_rec_put */

/*
 * function: ffdb_rec_lock()
 *
 * Perform flock() operations on database record opened with ffdb_rec_open()
 *
 * arguments:
 *  ffdbctx      - ffdb context created by ffdb_db_open()
 *  key          - database key
 *  op_flags
 *    FFDB_OP_LOCK_NONE   - no op
 *    FFDB_OP_LOCK_SH     - shared lock
 *    FFDB_OP_LOCK_EX     - exclusive lock
 *    FFDB_OP_LOCK_NB     - non blocking lock
 *    FFDB_OP_LOCK_UN     - unlock
 *
 *  returns: <0 error
 *            0 success
 */
int ffdb_rec_lock(struct ffdb_ctx *ffdbctx, struct ffdb_key *key, int op_flags)
{
  int ret, lock_flags;

  ret = -1;
  lock_flags = 0;

  if (ffdb_ctx_valid(ffdbctx, "ffdb_rec_lock") == -1)
    return -1;

  if (key->fd == -1) {
    if (ffdbctx->verbose)
      xerr_warnx("ffdb_rec_lock(): invalid fd.");
    return -1;
  }

  if (op_flags & FFDB_OP_LOCK_SH)
    lock_flags |= LOCK_SH;

  if (op_flags & FFDB_OP_LOCK_EX)
    lock_flags |= LOCK_EX;

  if (op_flags & FFDB_OP_LOCK_NB)
    lock_flags |= LOCK_NB;

  if (op_flags & FFDB_OP_LOCK_UN)
    lock_flags |= LOCK_UN;

  if (lock_flags) {

    ret = flock(key->fd, lock_flags);

    if ((ret < 0) && ffdbctx->verbose)
      xerr_warn("flock(%s)", ffdbctx->key_pn);

    if (ret < 0)
      goto ffdb_rec_lock_out;

  } /* lock_flags */

  ret = 0;

ffdb_rec_lock_out:

  return ret;

} /* ffdb_rec_lock */

#ifdef FFDB_EXAMPLE

#include <stdio.h>
#include "ffdb.h"


int main(int argc, char **argv)
{
  struct ffdb_ctx *ffdbctx;
  struct ffdb_key key, key2;
  struct ffdb_val val;
  struct ffdb_info info;
  mode_t file_mode, dir_mode;
  int ret;
  uint32_t flags;

  xerr_setid(argv[0]);

  file_mode = S_IRUSR|S_IWUSR;
  dir_mode = S_IRWXU;

/** 
  ffdb_info("/tmp/ffdb2", &info);
  printf("info.min_key_size=%lu\n", (unsigned long)info.min_key_size);
  printf("info.max_key_size=%lu\n", (unsigned long)info.max_key_size);

  printf("info.min_val_size=%lu\n", (unsigned long)info.min_val_size);
  printf("info.max_val_size=%lu\n", (unsigned long)info.max_val_size);

  printf("info.num_keys=%lu\n", (unsigned long)info.num_keys);

  flags = 0;
**/

/***/

  ffdbctx = ffdb_db_open("/tmp/ffdb-created", 12, 12,
    FFDB_DB_CREATE_SOFT|FFDB_DB_KEY_HEX|FFDB_DB_STAT_READ,
    file_mode, dir_mode);
  ret = (ffdbctx == 0L);
  printf("ffdb_db_open(): %d\n", ret);
  ret = ffdb_db_close(ffdbctx);
  printf("ffdb_db_close(): %d\n", ret);

/***/

  ffdbctx = ffdb_db_open("/tmp/ffdb2", 64, 64,
    FFDB_DB_KEY_HEX|FFDB_DB_STAT_READ, file_mode, dir_mode);
  ret = (ffdbctx == 0L);
  printf("ffdb_db_open(): %d\n", ret);
  ffdb_db_verbose(ffdbctx, 1);
  ret = ffdb_db_close(ffdbctx);
  printf("ffdb_db_close(): %d\n", ret);

/***/

  ffdbctx = ffdb_db_open("/tmp/ffdb2", 64, 64,
    FFDB_DB_STAT_READ|FFDB_DB_CREATE_SOFT,
    file_mode, dir_mode);
  ret = (ffdbctx == 0L);
  printf("ffdb_db_open(): %d\n", ret);
  ffdb_db_verbose(ffdbctx, 1);

/***/

  key.key = "ls2";
  key.size = 3;

  val.val = "ls2-data";
  val.size = 8;

  ret = ffdb_rec_open(ffdbctx, &key, O_RDWR|O_CREAT, FFDB_OP_LOCK_EX);
  printf("ffdb_rec_open(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_rec_put(ffdbctx, &key, &val, 0);
  printf("LOCKED: ffdb_put(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_rec_close(ffdbctx, &key);
  printf("ffdb_rec_close(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");
 
/***/

  ret = ffdb_rec_iter(ffdbctx, &key, &val, FFDB_ITER_FIRST|FFDB_ITER_GET);
  printf("ffdb_rec_iter(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");
  if (ret == 1) xerr_errx(1, "done");
  printf("iter: key.key=%s, key.size=%d\n", (char*)key.key, (int)key.size);
  printf("iter: val.val=%s, val.size=%d\n", (char*)val.val, (int)val.size);

  ret = ffdb_rec_iter(ffdbctx, &key, &val, FFDB_ITER_NEXT);
  printf("ffdb_rec_iter(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");
  if (ret == 1) xerr_errx(1, "done");
  printf("iter: key.key=%s, key.size=%d\n", (char*)key.key, (int)key.size);
  printf("iter: val.val=%s, val.size=%d\n", (char*)val.val, (int)val.size);

  ret = ffdb_rec_iter(ffdbctx, &key, &val, FFDB_ITER_DONE);
  printf("ffdb_rec_iter(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");
  if (ret == 1) xerr_errx(1, "done");

  key.key = "ls";
  key.size = 2;

  key2.key = "ll";
  key2.size = 2;

  ret = ffdb_rec_exists(ffdbctx, &key);
  printf("ffdb_rec_exists(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_rec_open(ffdbctx, &key, O_RDWR, FFDB_OP_LOCK_EX);
  printf("ffdb_rec_open(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_rec_open(ffdbctx, &key2, O_RDWR|O_CREAT, FFDB_OP_LOCK_EX);
  printf("ffdb_rec_open(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_rec_get(ffdbctx, &key, &val, FFDB_OP_REWIND_NO);
  printf("ffdb_rec_get(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_rec_get(ffdbctx, &key, &val, 0);
  printf("ffdb_rec_get(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  printf("size=%d\n", val.size);
  printf("val=%s\n", (char*)val.val);

/*
  ret = ffdb_rec_lock(ffdbctx, &key, FFDB_OP_LOCK_UN);
  printf("ffdb_lock(LOCK_UN): %d\n", ret);
*/

  ret = ffdb_rec_put(ffdbctx, &key2, &val, 0);
  printf("LOCKED: ffdb_put(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_rec_get(ffdbctx, &key, &val, 0);
  printf("LOCKED: ffdb_get(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  printf("size=%d\n", val.size);
  printf("val=%s\n", (char*)val.val);

  ret = ffdb_rec_close(ffdbctx, &key);
  printf("ffdb_rec_close(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_rec_close(ffdbctx, &key2);
  printf("ffdb_rec_close(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  ret = ffdb_db_close(ffdbctx);
  printf("ffdb_db_close(): %d\n", ret);
  if (ret < 0) xerr_errx(1, "fail");

  return 0;

} /* main */

#endif /* FFDB_EXAMPLE */
