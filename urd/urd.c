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
 *      $Id: urd.c 176 2011-05-16 02:17:30Z maf $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <netdb.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif
#ifdef OOTP_ENABLE
#include "otplib.h"
#include "ffdb.h"
#endif /* OOTP_ENABLE */
#include "pw.h"
#include "rad.h"
#include "xerr.h"

/*
 * XXX
 * copy proxy variables into reply packet per RFC?
 * packet stress testing
 */

static void usage(void);
static int server_secret_load(char *fname, char *buf, int buf_len);
static u_long scan_ip(char *s);
static int write_pidfile(char *fname);

#define URDCTX_USER_NAME (allow_n_logins ?\
  urdctx->req.user_name_base : urdctx->req.user_name)

int main(int argc, char **argv)
{
  extern char *ootp_version;
  struct sockaddr_in loc_addr;
  struct urd_ctx *urdctx;
  struct pass_db_ctx *pdbctx;
#ifdef OOTP_ENABLE
  struct otp_ctx *otpctx;
  struct otp_user ou;
  char *otpdb_fname;
  int otp_allow_unknown, otpdb_flags, otp_enable;
#endif /* OOTP_ENABLE */
  fd_set rfd;
  u_long tmpul;
  uint64_t rep_state, rep_otp_count;
  uint32_t local_ip;
  uint16_t local_port;
  uint8_t rep_code;
  uint rem_addr_len;
  char *au_fname, *pwfile_fname, *server_secret_fname, *endptr, *loc;
  char server_secret[URD_SECRET_LEN+1], buf[1024], *pid_fname, *as_name;
  char *service;
  int rep_enc_flags, rep_cache_flags, debug, daemon_mode, pdb_type;
  int drop, drop_mode, req_cache_hit, buf_l, pkt_fd, r, i, otp_window;
  int opt_version, otp_display_count, tmp_cache_flags;
  int disable_authorized_users, allow_n_logins;

  struct option longopts[] = {
    { "authorized-users-db",          1, (void*)0L, 'a'},
    { "disable-authorized-users",     0, (void*)0L, 'A'},
    { "bind-ip-address",              1, (void*)0L, 'b'},
    { "bind-udp-port",                1, (void*)0L, 'B'},
#ifdef OOTP_ENABLE
    { "display-count",                0, (void*)0L, 'c'},
#endif /* OOTP_ENABLE */
    { "debug",                        1, (void*)0L, 'd'},
    { "disable-daemon-mode",          0, (void*)0L, 'D'},
    { "help",                         0, (void*)0L, 'h'},
    { "help",                         0, (void*)0L, '?'},
    { "pam-authentication-enable",    0, (void*)0L, 'm'},
    { "pam-authentication-exclusive", 0, (void*)0L, 'M'},
    { "n-logins-enable",              0, (void*)0L, 'n'},
#ifdef OOTP_ENABLE
    { "otp-db",                       1, (void*)0L, 'o'},
    { "otp-disable",                  0, (void*)0L, 'O'},
#endif /* OOTP_ENABLE */
    { "password-db",                  1, (void*)0L, 'p'},
    { "pidfile",                      1, (void*)0L, 'P'},
    { "server-secret",                1, (void*)0L, 's'},
    { "pam-service-name",             1, (void*)0L, 'S'},
#ifdef OOTP_ENABLE
    { "otp-allow-unknown-user",       0, (void*)0L, 'u'},
    { "service-name",                 0, (void*)0L, 'V'},
    { "otp-challenge-window",         1, (void*)0L, 'w'},
#endif /* OOTP_ENABLE */
    { "debug-drop-udp-packets",       0, (void*)0L, 'x'},
    { "version",                      0, &opt_version, 1},
    { 0, 0, 0, 0},
  };

  bzero(&loc_addr, sizeof loc_addr);
  bzero(&pkt_fd, sizeof pkt_fd);
  bzero(&rfd, sizeof rfd);
  allow_n_logins = 0;
  opt_version = 0;
  debug = 0;
  daemon_mode = 1;
  au_fname = "/var/urd/authorized_users";
  disable_authorized_users = 0;
  pwfile_fname = "/var/urd/passwd";
  server_secret_fname = "/var/urd/server_secret";
  pid_fname = (char*)0L;
  local_ip = INADDR_ANY;
  local_port = URD_PORT;
  drop = 1;
  drop_mode = 0;
  otp_window = OTP_WINDOW_DEFAULT;
  pdb_type = PASS_DB_TYPE_LOCAL;
  as_name = "urd";
  service = "urd";
#ifdef OOTP_ENABLE
  otpctx = (struct otp_ctx*)0L;
  otpdb_fname = OTP_DB_FNAME;
  otp_allow_unknown = 0;
  otpdb_flags = 0;
  otp_enable = 1;
  otp_display_count = 0;
#endif /* OOTP_ENABLE */
  
  xerr_setid(argv[0]);

#ifdef OOTP_ENABLE
  while ((i = getopt_long(argc, argv, "AhduDOx?a:cb:B:mMno:p:s:S:P:V:w:",
    longopts, (int*)0L)) != -1) {
#else
  while ((i = getopt_long(argc, argv, "AhdDx?a:b:B:mMnp:s:S:P:V:",
    longopts, (int*)0L)) != -1) {
#endif /* OOTP_ENABLE */

    switch (i) {

      case 'a':
        au_fname = optarg;
        break;

      case 'A':
        disable_authorized_users = 1;
        break;

      case 'b':
        if (!(local_ip = scan_ip(optarg)))
          xerr_errx(1, "scan_ip(%s): fatal", optarg);
        break;

      case 'B':
        tmpul = strtoul(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "stroul(%s): failed at %c.", optarg, *endptr);
        if (tmpul > 0xFFFF)
          xerr_errx(1, "UDP port out of range 0..65535.");
        local_port = tmpul;
        break;

      case 'c':
        otp_display_count = 1;
        break;

      case 'd':
        debug ++;
#ifdef OOTP_ENABLE
        otpdb_flags |= OTP_DB_VERBOSE;
#endif /* OOTP_ENABLE */
        break;

      case 'D':
        daemon_mode = 0;
        break;

      case 'h':
      case '?':
        usage();
        exit(0);
        break;

      case 'm':
        pdb_type = PASS_DB_TYPE_PAM;
        break;

      case 'M': /* xxx only here for compatability */
        disable_authorized_users = 1;
        break;

      case 'n':
        allow_n_logins = 1;
        break;

#ifdef OOTP_ENABLE
      case 'o':
        otpdb_fname = optarg;
        break;

      case 'O':
        otp_enable = 0;
        break;
#endif /* OOTP_ENABLE */

      case 'p':
        pwfile_fname = optarg;
        break;

      case 'P':
        pid_fname = optarg;
        break;

      case 's':
        server_secret_fname = optarg;
        break;

      case 'S':
        as_name = optarg;
        break;

      case 'V':
        service = optarg;
        break;

#ifdef OOTP_ENABLE
      case 'u':
        otp_allow_unknown = 1;
        break;

      case 'w':
        tmpul = strtoul(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "stroul(%s): failed at %c.", optarg, *endptr);
        if (tmpul > OTP_WINDOW_MAX)
          xerr_errx(1, "Challenge window %lu > %lu.", tmpul, OTP_WINDOW_MAX);
        otp_window = tmpul;
        break;
#endif /* OOTP_ENABLE */

      case 'x':
        drop_mode = 1;
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

  if (daemon_mode) {

    xerr_setsyslog2(1); /* use syslog for output */

    /* run in the background */
    if (daemon(0, 0) < 0)
      xerr_err(1, "dameon()");

  } /* daemon_mode */

  buf_l = snprintf(buf, sizeof(buf), "urd start:");
  if (debug) {
    for (i = 0; i < argc; ++i)
      buf_l += snprintf(buf+buf_l, sizeof(buf)-buf_l, " %s", argv[i]);
  }
  xerr_info(buf);

  /* init to recv UDP datagrams */
  loc_addr.sin_family = AF_INET;
  loc_addr.sin_addr.s_addr = htonl(local_ip);
  loc_addr.sin_port = htons(local_port);

  /* construct pid file name */
  if (!pid_fname) {

    if (local_ip || (local_port != URD_PORT)) {

      buf_l = snprintf(buf, sizeof(buf),
        "/var/urd/pid.%s.%d", inet_ntoa(loc_addr.sin_addr), (int)local_port);

    } else {

      buf_l = snprintf(buf, sizeof(buf), "/var/urd/pid");

    }

    pid_fname = (char*)&buf;

  }

  /* write out pidfile */
  if (write_pidfile(pid_fname) < 0)
    xerr_errx(1, "write_pidfile(%s): fatal", buf);

  /* load shared server secret */
  if (server_secret_load(server_secret_fname, server_secret,
    URD_SECRET_LEN+1) < 0)
    xerr_errx(1, "server_secret_load(%s): fatal", server_secret_fname);

  /* location is password file or pam service name */
  if (pdb_type == PASS_DB_TYPE_LOCAL)
    loc = pwfile_fname;
  else if (pdb_type == PASS_DB_TYPE_PAM)
    loc = as_name;
  else
    xerr_errx(1, "loc fatal, pdb_type=%d", pdb_type);

  /* disable authorized users? */
  if (disable_authorized_users) {
    if (pdb_type == PASS_DB_TYPE_LOCAL)
      pdb_type = PASS_DB_TYPE_EX_LOCAL;
    else if (pdb_type == PASS_DB_TYPE_PAM)
      pdb_type = PASS_DB_TYPE_EX_PAM;
    else
      xerr_errx(1, "au fatal, pdb_type=%d", pdb_type);
  }

  /* setup password database */
  if (!(pdbctx = pass_db_ctx_new(loc, au_fname, pdb_type)))
    xerr_errx(1, "pass_db_ctx_new(%s,%s): fatal", pwfile_fname, 
      au_fname);

  pass_db_debug(pdbctx, debug);

  /* load password database */
  if (pass_db_load(pdbctx) < 0)
    xerr_errx(1, "pass_db_load(): fatal");

  if (debug)
    pass_db_stats(pdbctx);

  /* socket to receive URD datagrams */
  if ((pkt_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    xerr_err(1, "socket()");

#ifdef OOTP_ENABLE
  /* creat OTP context */
  if (otp_enable)
    if (!(otpctx = otp_db_open(otpdb_fname, otpdb_flags)))
      xerr_errx(1, "otp_db_open(%s): failed", otpdb_fname);
#endif /* OOTP_ENABLE */

  /* create radius context */
  if (!(urdctx = urd_ctx_new(server_secret)))
    xerr_errx(1, "urd_ctx_new(): fatal");

  urd_debug(urdctx, debug);

  /* bind socket to address */
  if (bind(pkt_fd, (struct sockaddr*)&loc_addr, sizeof(loc_addr)) < 0)
    xerr_err(1, "bind(%s)", inet_ntoa(loc_addr.sin_addr));

  while (1) {

    /* grab a datagram */
    rem_addr_len = sizeof (urdctx->req.rem_addr);
    if ((urdctx->req.pkt_len = recvfrom(pkt_fd, &urdctx->req.pkt_buf,
      (size_t)URD_MAX_DGRAM_LEN, 0, (struct sockaddr*)&urdctx->req.rem_addr,
      &rem_addr_len)) < 0) {
      xerr_warn("recvfrom()");
      continue;
    }

    /*
     * Handle two types of authentication requests, those with state, and
     * those without.  Auth requests with state are used to tie the
     * OTP phase of a two phase authentication (reusable password, OTP)
     * together into a session.
     *
     * A request cache is kept with the code and state used for a reply
     * This is required for OTP to work robustly in an environment where
     * the client may have lost the reply from the server and retransmits
     * (OTP will only work once).
     *
     * Requests with state which can not be tied to the initial 
     * request without state (ie the reusable password phase) are
     * dropped.
     *
     * The request cache and state cache are unified with a hash
     * table for each.  Cache entries are stored in a fixed size
     * ring buffer.
     *
     * request with no state:
     *   req_cache lookup:
     *     hit :
     *       rep_code and state_counter from cache
     *     miss :
     *       rep_code based on pw_auth and otp requirements:
     *         access-reject: (no state, failed password auth)
     *         access-accept: (no state, user does not need OTP)
     *         access-challenge: (increment state)
     *   reply:
     *     reject: don't encode state or rep_msg
     *     access-challenge: encode state and rep_msg
     *     access-accept: don't encode state or rep_msg
     *
     * request with state:
     *   req_cache lookup:
     *     hit :
     *       rep_code and state_counter from cache
     *       rep_msg from cache 
     *     miss :
     *       state_cache lookup :
     *         hit :
     *           rep_code based on otp_auth:
     *             access-reject: encode state, no rep_msg
     *             access-accept: encode state, no rep_msg
     *             access-challenge: not permitted here
     *         miss :
     *           bogus, no previous state from pw_auth phase, reject, log
     *
     *   reply:
     *     reject: encode state, no rep_msg
     *     access-accept: encode state, no rep_msg
     *     access-challenge: not permitted here
     * 
     */

    /* reply constructed from cache? */
    req_cache_hit = 0;

    /* decode/sanity check request */
    if ((r = urd_req_decode(urdctx)) < 0) {
      xerr_warnx("urd_req_decode(): failed");
      continue;
    }

    /* non fatal packet decode xerr_error, ignore it */
    if (r > 1)
      continue;

    if (debug)
      urd_req_dump(urdctx);

    /* RADIUS ACCESS-REQUEST? */
    if (urdctx->req.dgram_header.code == RADIUS_CODE_ACCESS_REQUEST) {

      if (debug)
        xerr_info("req: ACCESS-REQUEST");

      /* check for minimum TLV's in packet */
      if ((!urdctx->req.tlv_User_Name) ||
          (!urdctx->req.tlv_User_Password) ||
          ((!urdctx->req.tlv_NAS_IP_Address) &&
           (!urdctx->req.tlv_NAS_Identifier))) {
        xerr_warnx("req: min required fields missing");
        continue;
      }

      req_cache_hit = 0;
      rep_code = RADIUS_CODE_ACCESS_REJECT;
      rep_state = 0LL;
      rep_enc_flags = 0;
      rep_cache_flags = 0;
      rep_otp_count = 0;

      /* initial no state access request */
      if (!urdctx->req.tlv_State) {

        if (debug)
          xerr_info("req: (no state)");

        /* first check the cache for a previously composed reply */
        if ((r = urd_req_cache_lookup(urdctx, &rep_code, &rep_state,
          &rep_otp_count, &tmp_cache_flags)) < 0)
          xerr_errx(1, "urd_req_cache_lookup(): fatal");

        /* hit, then skip to response gen */
        if (r == URD_REQ_CACHE_HIT) {

          req_cache_hit = 1;

          if ((rep_code == RADIUS_CODE_ACCESS_REJECT) ||
              (rep_code == RADIUS_CODE_ACCESS_ACCEPT)) {

            rep_enc_flags = 0x0;

          } else if (rep_code == RADIUS_CODE_ACCESS_CHALLENGE) {

            rep_enc_flags = URD_ENCODE_FLAG_STATE;

            if (tmp_cache_flags & URD_CACHE_FLAG_MSG)
              rep_enc_flags |= URD_ENCODE_FLAG_MSG;

          }

          if (debug)
            xerr_info("req: cache hit");

          goto access_request_rep;

        } else {

          if (debug)
            xerr_info("req: cache miss");

        }

        /* cache lookup invalid, default to ACCESS_REJECT */
        rep_code = RADIUS_CODE_ACCESS_REJECT;

        /* authenticate user */
        if ((r = pass_db_auth(pdbctx, URDCTX_USER_NAME,
          urdctx->req.user_pass)) < 0)
          xerr_errx(1, "pass_db_auth(): fatal");

        /* valid password? */
        if (r != PASS_DB_AUTH_SUCCESS) {

          if (debug)
            xerr_info("req: fail auth via pass_db_auth() ");

          goto access_request_rep;

        } else {

          if (debug)
            xerr_info("req: pass auth via pass_db_auth() ");

        }

        /* special urd_stats user? */
        if (!strcmp(urdctx->req.user_name, "urd_stats")) {

          urd_state_cache_stats(urdctx);
          urd_req_cache_stats(urdctx);
          goto access_request_rep;

        }

        /* special urd_debug user? */
        if (!strcmp(urdctx->req.user_name, "urd_debug")) {

          if (debug) {
            debug = 0;
            urd_debug(urdctx, 0);
          } else {
            debug = 1;
            urd_debug(urdctx, 1);
          }

          goto access_request_rep;

        }

#ifndef OOTP_ENABLE

        /*
         * without one time passwords compiled in, no additional auth
         * checks are required, reply with ACCEPT
         */

        rep_code = RADIUS_CODE_ACCESS_ACCEPT;
        rep_enc_flags = 0x0;
        if (debug)
          xerr_info("req: ACCEPT (nothing more to do).");
        goto access_request_rep;

#else /* OOTP_ENABLE */

        /*
         * if one time passwords are disabled then the password
         * check above meets auth requirements.  Reply with ACCESS_ACCEPT.
         *
         */
        if (!otp_enable) {

          rep_code = RADIUS_CODE_ACCESS_ACCEPT;
          rep_enc_flags = 0x0;
          if (debug)
            xerr_info("req: ACCEPT with OTP disabled.");
          goto access_request_rep;

        }

        /*
         * check OTP
         */
        if ((r = otp_user_exists(otpctx, URDCTX_USER_NAME)) < 0)
          xerr_errx(1, "otp_user_exists(): fail.");


        /*
         * if user does not exist and not okay to allow non OTP users
         * then authentication request fails with default ACCESS_REJECT.
         */
        if ((r == 1) && (otp_allow_unknown == 0)) {

          if (debug)
            xerr_info("req: fail via otp_user_exists() allow_unknown=0");

          /* reply with an REJECT */
          rep_code = RADIUS_CODE_ACCESS_REJECT;

          rep_enc_flags = 0x0;

          goto access_request_rep;

        }

        /*
         * if user does not exist in database and okay to allow non OTP
         * users then authentication request is successful without OTP.
         * password check was done above, reply with ACCEPT
         */
        if ((r == 1) && (otp_allow_unknown == 1)) {

          if (debug)
            xerr_info("req: pass via otp_user_exists() allow_unknown=1");

          /* reply with an ACCEPT, no state, no challenge message */
          rep_code = RADIUS_CODE_ACCESS_ACCEPT;

          rep_enc_flags = 0x0;

          goto access_request_rep;

        }

        /*
         * unknown response from otp_user_exists()
         */
        if (r != 0) {

          if (debug)
            xerr_info("otp_user_exists() unknown response r=%d", r);

          /* reply with an REJECT */
          rep_code = RADIUS_CODE_ACCESS_REJECT;

          rep_enc_flags = 0x0;

          goto access_request_rep;

        }

        if (otp_urec_open(otpctx, URDCTX_USER_NAME, &ou,
          O_RDONLY, FFDB_OP_LOCK_EX) < 0)
          xerr_errx(1, "otp_urec_open(%s): failed.", URDCTX_USER_NAME);

        if (otp_urec_get(otpctx, &ou) < 0)
          xerr_errx(1, "otp_urec_get(): failed.");

        if (otp_urec_close(otpctx, &ou) < 0)
          xerr_errx(1, "otp_urec_close(): failed.");

        /* disabled user defaults to ACCESS_REJECT */
        if (ou.status == OTP_STATUS_DISABLED) {

          if (debug)
            xerr_info("req: fail via otp_user_get() (disabled)");

          goto access_request_rep;

        }

        /* inactive user does not need OTP */
        if (ou.status == OTP_STATUS_INACTIVE) {

          /* reply with an ACCEPT, no state, no challenge message */
          rep_code = RADIUS_CODE_ACCESS_ACCEPT;

          rep_enc_flags = 0x0;

          if (debug)
            xerr_info("req: pass via otp_user_get() (inactive)");

          goto access_request_rep;

        }

        /* verify count not at ceiling */
        if (ou.count >= ou.count_ceil) {

          if (debug)
            xerr_info("req: fail ou.count >= ou.count_ceil.");

          goto access_request_rep;

        }

        /*
         * made it this far then user is in authorized_users database,
         * reusable password is valid in password database, and user
         * exists in the OTP database in an active state
         */
        if (ou.status == OTP_STATUS_ACTIVE) {

          /* reply with challenge, challenge message, new state */
          rep_code = RADIUS_CODE_ACCESS_CHALLENGE;

          rep_enc_flags = URD_ENCODE_FLAG_STATE;

          rep_state = ++urdctx->state_counter;

          rep_otp_count = ou.count;

          rep_cache_flags = URD_CACHE_FLAG_STATE;

          if (otp_display_count || ou.flags & OTP_FLAGS_DSPCNT) {
            rep_enc_flags |= URD_ENCODE_FLAG_MSG;
            rep_cache_flags |= URD_CACHE_FLAG_MSG;
          }

          if (ou.flags & OTP_FLAGS_SEND_TOKEN) {

            if (otp_user_send_token(otpctx, URDCTX_USER_NAME, service) < 0)
              xerr_warnx("otp_user_send_token(): failed.");

          }

          if (debug)
            xerr_info("req: pass via otp_user_get() (active)");

          goto access_request_rep;

        }
#endif /* OOTP_ENABLE */

      } else if (urdctx->req.tlv_State) {

#ifndef OOTP_ENABLE

        /*
         * without one time passwords compiled in, a request with
         * state will always return REJECT.
         *
         */

        /* reply with inbound state */
        rep_state = urdctx->req.state_counter;

        if (debug)
          xerr_info("req: state set, nothing to do, REJECT.");

        goto access_request_rep;

#else /* OOTP_ENABLE */
        /* request has state, always reply with it */
        rep_enc_flags = URD_ENCODE_FLAG_STATE;

        if (debug)
          xerr_info("req: (state)");

        if ((r = urd_req_cache_lookup(urdctx, &rep_code, &rep_state,
          &rep_otp_count, &tmp_cache_flags)) < 0)
          xerr_errx(1, "urd_req_cache_lookup(): fatal");

        /* hit, then skip to response gen */
        if (r == URD_REQ_CACHE_HIT) {

          req_cache_hit = 1;

          if (debug)
            xerr_info("req: cache hit");

          goto access_request_rep;

        } else {

          if (debug)
            xerr_info("req: cache miss");

        }

        /* cache lookup invalid, default to ACCESS_REJECT */
        rep_code = RADIUS_CODE_ACCESS_REJECT;

        /* reply with inbound state */
        rep_state = urdctx->req.state_counter;

        /*
         * state cache lookup -- user must have previously authenticated
         * successfully to continue
         */
        if ((r = urd_state_cache_lookup(urdctx, &rep_code)) < 0)
          xerr_errx(1, "urd_state_cache_lookup(): fatal");

        /* if no hit then can not continue */
        if (r != URD_REQ_CACHE_HIT) {

          if (debug)
            xerr_info("state: cache miss (user not validated with passwd)");

          /* cache lookup invalid, default to ACCESS_REJECT */
          rep_code = RADIUS_CODE_ACCESS_REJECT;

          goto access_request_rep;

        } else {

          if (debug)
            xerr_info("state: cache hit");

        }

        /* double check code */
        if (rep_code != RADIUS_CODE_ACCESS_CHALLENGE) {

          if (debug)
            xerr_warnx("req: fail cache'd state rep_code");

          goto access_request_rep;

        }

        /*
         * default to ACCESS_REJECT.  State cache lookup will have
         * ACCESS_CHALLENGE code as it is shared with the request cache.
         */

        rep_code = RADIUS_CODE_ACCESS_REJECT;

        if ((r = otp_user_exists(otpctx, URDCTX_USER_NAME)) < 0)
          xerr_errx(1, "otp_user_exists(): fail.");

        /* user exist?, if not failure */
        /* note, initial access request checked this */
        if (r != 0) {

          if (debug)
            xerr_info("req: fail via otp_user_exists()");

          goto access_request_rep;

        }

        if (otp_urec_open(otpctx, URDCTX_USER_NAME, &ou,
          O_RDONLY, FFDB_OP_LOCK_EX) < 0)
          xerr_errx(1, "otp_urec_open(%s): failed.", URDCTX_USER_NAME);
  
        if (otp_urec_get(otpctx, &ou) < 0)
          xerr_errx(1, "otp_urec_get(): failed.");

        if (otp_urec_close(otpctx, &ou) < 0)
          xerr_errx(1, "otp_urec_close(): failed.");

        /* note, initial access request checked this */
        if (ou.status != OTP_STATUS_ACTIVE) {

          if (debug)
            xerr_info("req: fail via otp_user_get() (not ACTIVE)");

          goto access_request_rep;

        }

        /* verify count not at ceiling */
        /* note, initial access request checked this */
        if (ou.count >= ou.count_ceil) {

          if (debug)
            xerr_info("req: fail ou.count >= ou.count_ceil.");

          goto access_request_rep;

        }

        if ((r = otp_user_auth(otpctx, URDCTX_USER_NAME,
          urdctx->req.user_pass, otp_window)) < 0)
            xerr_errx(1, "otp_user_auth(): failed.");

        if (r == OTP_AUTH_PASS) {

          rep_code = RADIUS_CODE_ACCESS_ACCEPT;

          if (debug)
            xerr_info("req: pass via otp_user_auth()");

          goto access_request_rep;

        } else {

          if (debug)
            xerr_info("req: fail via otp_user_auth()");

        }

        /* failed authentication... */

#endif /* OOTP_ENABLE */

      } else {

        xerr_info("unsupported code=%2.2X",
          (int)urdctx->req.dgram_header.code);

      } /* type of request */

/* reply to request */
access_request_rep:

      if (debug) {

        if (rep_code == RADIUS_CODE_ACCESS_ACCEPT)
          xerr_info("rep: ACCESS-ACCEPT");

        else if (rep_code == RADIUS_CODE_ACCESS_REJECT)
          xerr_info("rep: ACCESS-REJECT");

        else if (rep_code == RADIUS_CODE_ACCESS_CHALLENGE)
          xerr_info("rep: ACCESS-CHALLENGE");

      } /* debug */

      /*
       * construct reply
       */

      if (urd_rep_encode(urdctx, rep_code, rep_state, rep_otp_count,
        rep_enc_flags) < 0) {
        xerr_errx(1, "urd_rep_encode(): fatal");
      }

      /* update reply cache */
      if (urd_req_cache_update(urdctx, rep_code, rep_state, rep_otp_count,
        rep_cache_flags) < 0)
        xerr_errx(1, "urd_req_cache_update(): fatal");

      /* debugging / drop every other packet */
      if (drop_mode) {
        if (drop) {
          drop = 0;
          continue; /* skip packet send */
        } else {
          drop = 1;
        }
      }

      if (sendto(pkt_fd, &urdctx->rep.pkt_buf, urdctx->rep.pkt_len, 0,
        (struct sockaddr*) &urdctx->rep.rem_addr,
          sizeof(urdctx->rep.rem_addr)) < 0) {
        xerr_err(1, "sendto()");
      } 

    } /* ACCESS_REQUEST */

  } /* forever */

  /* not reached */

  /* cleanup */
  pass_db_ctx_free(pdbctx);

#ifdef OOTP_ENABLE
  otp_db_close(otpctx);
#endif /* OOTP_ENABLE */

} /* main */
/*
 * function: scan_ip
 *
 *  IP address in string S is converted to a u_long
 *  (borrowed from tcpdump)
 *
 *  left shift any partial dotted quads, ie 10 is 0x0a000000 not 0x0a
 *  so scan_ip_prefix() works for standard prefix notation, ie 10/8
 */
u_long scan_ip(char *s)
{
  struct hostent *he;
  struct in_addr *ina;
  u_long addr = 0;
  uint n;
  int dns, shift;
  char *t;

  /* if there is anything ascii in here, this may be a hostname */
  for (dns = 0, t = s; *t; ++t) {
    if (islower((int)*t) || isupper((int)*t)) {
      dns = 1;
      break;
    }
  }

  if (dns) {

    if (!(he = gethostbyname(s)))
      goto numeric;

    if (he->h_addrtype != AF_INET)
      goto numeric;

    if (he->h_length != sizeof (uint32_t))
      goto numeric;

    ina = (struct in_addr*)*he->h_addr_list;
    return (ntohl(ina->s_addr));

  } /* dns */

  shift = 0;

numeric:
  while (1) {

    /* n is the nibble */
    n = 0;

    /* nibble's are . bounded */
    while (*s && (*s != '.') && (*s != ' ') && (*s != '\t'))
      n = n * 10 + *s++ - '0';

    /* shift in the nibble */
    addr <<=8;
    addr |= n & 0xff;
    ++shift;

    /* return on end of string */
    if ((!*s) || (*s == ' ') || (*s == '\t'))
      goto ndone;

    /* skip the . */
    ++s;
  } /* forever */

ndone:

  for (; shift < 4; ++shift)
    addr <<=8;

  return addr;

} /* scan_ip */

/*
 * function: server_secret_load()
 *
 * load a one line secret (password) from fname into buf of length buf_len
 * secret is assumed to be ASCII and will be null terminated
 *
 * returns: < 0 : fail
 *            0 : success
 */
int server_secret_load(char *fname, char *buf, int buf_len)
{
  struct stat sb;
  int fd, len, ret, i;

  fd = -1;
  ret = -1;

  /* open secret file */
  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    xerr_warn("open(%s)", fname);
    goto server_secret_load_out;
  }

  /* grab size */
  if (fstat(fd, &sb) < 0) {
    xerr_warn("stat(%s)", fname);
    goto server_secret_load_out;
  }

  if ((sb.st_size+1) >= buf_len) {
    xerr_warn("secret buffer too small");
    goto server_secret_load_out;
  }

  if ((len = read(fd, buf, sb.st_size)) < 0) {
    xerr_warn("read(%s)", fname);
    goto server_secret_load_out;
  }

  if (len != sb.st_size) {
    xerr_warnx("short read(%s)", fname);
    goto server_secret_load_out;
  }

  /* strip \n */
  for (i = 0; i < sb.st_size; ++i)
    if (buf[i] == '\n')
      buf[i] = 0;

  /* ensure null termination */
  buf[sb.st_size] = 0;

  /* success */
  ret = 0;

server_secret_load_out:

  if (fd != -1)
    close(fd);

  return ret;

} /* server_secret_load */

/*
 * function: write_pidfile()
 *
 * Store proces ID in ASII to fname.
 *
 * returns: < 0 : fail
 *            0 : success
 */
int write_pidfile(char *fname)
{
  int fd, buf_l;
  char buf[512];

  buf_l = snprintf(buf, sizeof(buf), "%lu\n", (unsigned long)getpid());

  if ((fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0 ) {
    xerr_warn("open(%s)", fname);
    return -1;
  }

  if (write(fd, buf, buf_l) < 0) {
    xerr_warn("write(%s)", fname);
    close (fd);
    return -1;
  }

  return (close(fd));

} /* write_pidfile */

/*
 * function: usage()
 *
 */
void usage(void)
{
#ifdef OOTP_ENABLE
  fprintf(stderr,
    "urd [-AhcdDmMnOux?] [-a allowed_users_file] [-b local_ip] [-B local_port ]\n");
  fprintf(stderr,
    "             [-o otp_db] [-p passwd_file] [-P pid_file] [-s secret_file]\n");
#else
  fprintf(stderr,
    "urd [-AdDmMnhx?] [-a allowed_users_file] [-b local_ip] [-B local_port ]\n");
  fprintf(stderr,
    "             [-p passwd_file] [-P pid_file] [-s secret_file]\n");

#endif /* OOTP_ENABLE */
  fprintf(stderr, "             [-S auth_service_name] [-w otp_window]\n\n");
  fprintf(stderr, "  -A disable authorized_users file (all users in passwd_file valid)\n");
  fprintf(stderr, "  -h help\n");
  fprintf(stderr, "  -d enable debugging\n");
  fprintf(stderr, "  -D disable daemon mode\n");
  fprintf(stderr, "  -m use PAM for password authentication\n");
  fprintf(stderr, "  -M use PAM exclusively for password authentication\n");
#ifdef OOTP_ENABLE
  fprintf(stderr, "  -O disable one time passwords\n");
  fprintf(stderr, "  -u allow users which do not exist in OTP database\n");
#endif /* OOTP_ENABLE */
  fprintf(stderr, "  -x drop alternate replies (debugging)\n");
} /* help */


