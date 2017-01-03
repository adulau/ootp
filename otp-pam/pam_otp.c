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
 *      $Id: pam_otp.c 191 2011-06-12 16:32:33Z maf $
 */

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <utmp.h>

#include "otplib.h"
#include "xerr.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifndef __APPLE__
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#else
#include <pam/pam_modules.h>
#include <pam/pam_appl.h>
#endif

#define _pam_drop(X) \
do {                 \
    if (X) {         \
        free(X);     \
        X=NULL;      \
    }                \
} while (0)

#define _pam_overwrite(x)        \
do {                             \
     register char *__xx__;      \
     if ((__xx__=(x)))           \
          while (*__xx__)        \
               *__xx__++ = '\0'; \
} while (0)


struct opts {
  int debug;
  int use_first_pass;
  int try_first_pass;
  int expose_account;
  int display_count;
  int allow_inactive;
  int allow_unknown;
  int otp_window;
  char *otpdb_fname;
  char *service;
};

void load_opts(struct opts *opts, int argc, const char **argv);

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *ph, int flags, int argc,
  const char **argv)
{
  struct pam_message pam_msg;
  const struct pam_message *ppam_msg;
  struct pam_conv *pam_conv;
  struct pam_response *pam_resp;
  struct otp_ctx *otpctx;
  struct otp_user ou;
  struct opts opts;
  int r, ret, otpdb_flags;
  const char *user;
  char message[64], *cs;

  ppam_msg = &pam_msg;
  bzero(&pam_msg, sizeof (pam_msg));
  bzero(&opts, sizeof opts);
  pam_conv = 0L;
  pam_resp = 0L;
  ret = PAM_SERVICE_ERR;
  otpdb_flags = 0;

  xerr_setsyslog2(1); /* use syslog for output */
  xerr_setid("pam_otp.so");

  load_opts(&opts, argc, argv);

  if (opts.debug)
    otpdb_flags |= OTP_DB_VERBOSE;

  /* not supported */
  if (opts.use_first_pass || opts.try_first_pass)
    xerr_warnx("use/try_first_pass not supported");

  if (!(otpctx = otp_db_open(opts.otpdb_fname, otpdb_flags))) {
    xerr_warnx("otp_db_open(%s): failed.", opts.otpdb_fname);
    return PAM_SERVICE_ERR;
  }

  /* get the username */
  if ((r = pam_get_user(ph, &user, (char*)0L)) != PAM_SUCCESS) {
    xerr_warnx("pam_get_user(): %s", pam_strerror(ph, r));
    return PAM_SERVICE_ERR;
  }

  /* username not set or null then give up */
  if (!user || *user == '\0')
    return PAM_USER_UNKNOWN;

  if ((r = otp_user_exists(otpctx, (char*)user)) < 0) {
    xerr_warnx("otp_user_exists(%s): failed.", user);
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  /*
   * if user is not in database then possibly skip (return PAM_SUCCESS)
   *
   */
  if (r == 1) {
    if (opts.allow_unknown) {
      ret = PAM_SUCCESS;
      xerr_info("%s: user=%s pass otp_user_exists() allow_unknown=1",
        pam_strerror(ph, ret), user);
    } else {
      ret = PAM_AUTH_ERR;
      xerr_info("%s: user=%s via otp_user_exists() allow_unknown=0",
        pam_strerror(ph, ret), user);
    }
    goto cleanup;
  }

  /*
   * unknown response from otp_user_exists()
  */
  if (r != 0) {
    xerr_warnx("otp_user_exists() unknown response r=%d", r);
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  if (otp_urec_open(otpctx, (char*)user, &ou, O_RDONLY, FFDB_OP_LOCK_EX) < 0) {
    xerr_warnx("otp_urec_open(%s): failed.", user);
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  if (otp_urec_get(otpctx, &ou) < 0) {
    xerr_warnx("otp_urec_open(%s): failed.", user);
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  if (otp_urec_close(otpctx, &ou) < 0) {
    xerr_warnx("otp_urec_close(%s): failed.", user);
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  /*
   * if the user is inactive then either return SUCCESS (allow otp to be
   * disabled on a per user basis) or failure.
   *
   */
  if (ou.status == OTP_STATUS_INACTIVE) {
    if (opts.allow_inactive)
      ret = PAM_SUCCESS;
    else
      ret = PAM_AUTH_ERR;
    xerr_info("%s: user=%s status=INACTIVE.", pam_strerror(ph, ret), user);
    goto cleanup;
  }

  /* user can be locked out (disabled) */
  if (ou.status == OTP_STATUS_DISABLED) {
    ret = PAM_AUTH_ERR;
    xerr_info("%s: user=%s status=DISABLED.", pam_strerror(ph, ret), user);
    goto cleanup;
  }

  /* verify count not at ceiling */
  if (ou.count >= ou.count_ceil) {
    ret = PAM_AUTH_ERR;
    xerr_info("%s: user=%s count>count_ceil.", pam_strerror(ph, ret), user);
    goto cleanup;
  }

  /* get pointer to application supplied conversation function */
  if (pam_get_item(ph, PAM_CONV, (const void**)&pam_conv) != PAM_SUCCESS) {
    xerr_warnx("pam_get_item(PAM_CONV): failed.");
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  /* challenge prompt, echo on for reply */
  pam_msg.msg_style = PAM_PROMPT_ECHO_ON;
  pam_msg.msg = (char *)&message;

  /* send token to user? */
  if (ou.flags & OTP_FLAGS_SEND_TOKEN) {

    cs = "HOTP Sent";

    if (otp_user_send_token(otpctx, (char*)user, opts.service) < 0)
      xerr_warnx("otp_user_send_token(): failed.");

  } else {

    cs = "HOTP Challenge";

  } /* OTP_FLAGS_SEND_TOKEN */

  /* prompt for challenge with optional count */
  if (opts.display_count || (ou.flags & OTP_FLAGS_DSPCNT))
    snprintf(message, sizeof(message), "%s (%" PRIu64 "): ", cs, ou.count);
  else
    snprintf(message, sizeof(message), "%s: ", cs);

  /* use application conversation function to ask for challenge */
  if (pam_conv->conv(1, &ppam_msg, &pam_resp, pam_conv->appdata_ptr)
    != PAM_SUCCESS) {
    if (pam_resp) {
      _pam_overwrite(pam_resp->resp);
      _pam_drop(pam_resp->resp);
    }
    xerr_warnx("conv(message): failed.");
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  if (!pam_resp) {
    xerr_warnx("pam_resp is null");
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  if (opts.expose_account)
    xerr_info("OTP: user=%s response=%s window=%d", user,
      pam_resp->resp, opts.otp_window);

  if ((r = otp_user_auth(otpctx, (char*)user, pam_resp->resp,
    opts.otp_window)) < 0) {
    xerr_warnx("otp_user_auth(): failed.");
    ret = PAM_SERVICE_ERR;
    goto cleanup;
  }

  /* free return value from pam_conv->conv */
  _pam_overwrite(pam_resp->resp);
  _pam_drop(pam_resp);

  if (r == OTP_AUTH_PASS)
    ret = PAM_SUCCESS;
  else
    ret = PAM_AUTH_ERR;


cleanup:

  if (otp_db_close(otpctx) < 0) {
    xerr_warnx("otp_db_close(): failed.");
    ret = PAM_SERVICE_ERR;
  }

  if (opts.debug) {

    if (ret == PAM_SUCCESS)
      xerr_info("OTP: ret=PAM_SUCCESS");
    else if (ret == PAM_AUTH_ERR)
      xerr_info("OTP: ret=PAM_AUTH_ERR");
    else if (ret == PAM_SERVICE_ERR)
      xerr_info("OTP: ret=PAM_SERVICE_ERR");
    else
      xerr_info("OTP: ret=%d", ret);

  } /* opts.debug */

  return ret;

}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *ph,int flags,int argc
  ,const char **argv)
{ return PAM_SUCCESS; }

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *ph,int flags,int argc
  ,const char **argv)
{ return PAM_ACCT_EXPIRED; }

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *ph,int flags,int argc
  ,const char **argv)
{ return PAM_AUTHTOK_ERR; }

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *ph,int flags,int argc
  ,const char **argv)
{ return PAM_SYSTEM_ERR; }

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *ph,int flags,int argc
  ,const char **argv)
{ return PAM_SYSTEM_ERR; }


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_test_modstruct = {
    "pam_test",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif

void load_opts(struct opts *opts, int argc, const char **argv)
{
  u_long tmpul;
  char *endptr;

  bzero(opts, sizeof *opts);
  opts->otpdb_fname = OTP_DB_FNAME;
  opts->otp_window = OTP_WINDOW_DEFAULT;
  opts->service = "pam";

  /* foreach argument */
  while (argc--) {

    if (!strcmp(*argv, "debug")) {
      opts->debug = 1;
    } else if (!strcmp(*argv, "use_first_pass")) {
      opts->use_first_pass = 1;
    } else if (!strcmp(*argv, "try_first_pass")) {
      opts->use_first_pass = 1;
    } else if (!strcmp(*argv, "expose_account")) {
      opts->expose_account = 1;
    } else if (!strcmp(*argv, "display_count")) {
      opts->display_count = 1;
    } else if (!strcmp(*argv, "allow_inactive")) {
      opts->allow_inactive = 1;
    } else if (!strcmp(*argv, "require_db_entry")) {
      opts->allow_unknown = 0;
    } else if (!strcmp(*argv, "allow_unknown")) {
      opts->allow_unknown = 1;
    } else if (!strncmp(*argv, "otpdb=", 6)) {
      opts->otpdb_fname=(char*)(*argv)+6;
    } else if (!strncmp(*argv, "service=", 8)) {
      opts->service=(char*)(*argv)+8;
    } else if (!strncmp(*argv, "window=", 7)) {
      tmpul = strtoul(optarg, &endptr, 0);
      if (*endptr)
        xerr_errx(1, "stroul(%s): failed at %c.", *argv, *endptr);
      if (tmpul >  OTP_WINDOW_MAX)
        xerr_errx(1, "Challenge window %lu > %lu.", tmpul, OTP_WINDOW_MAX);
      opts->otp_window = tmpul;
    } else {
      xerr_errx(1, "Unrecognized argument - %s", argv);
    }

    ++argv;
  }

  if (opts->debug) {
    xerr_info("use_first_pass=%d, try_first_pass=%d, expose_account=%d, display_count=%d, allow_inactive=%d, allow_unknown=%d, otpdb=%s service=%s",
      opts->use_first_pass, opts->use_first_pass, opts->expose_account,
      opts->display_count, opts->allow_inactive, opts->allow_unknown,
      opts->otpdb_fname, opts->service);
  }

} /* load_opts */
