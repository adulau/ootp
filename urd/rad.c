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
 *      $Id: rad.c 13 2009-11-26 16:37:03Z maf $
 */

#include <sys/types.h>
#include <openssl/evp.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

#include "xerr.h"
#include "byte.h"
#include "rad.h"

uint8_t nta(uint8_t b);

/*
 * Simple radius packet encode and decode routines.  Length and other
 * potential data corrupting input is sanity checked on receive.
 *
 * urd_ctx_new( )            Create urd_ctx, allocate and init resources.
 * urd_req_free()            Free resources associated with urd_ctx allocated
 *                           with urd_ctx_new().
 *
 * urd_req_decode()          decode radius UDP packet content with
 *                           client/server shared secret rsecret.
 *                           Initialize a list of TLV pointers with common
 *                           TLV's available without searching.  Unhide
 *                           UserPassword TLV using rsecret.  Create C style
 *                           strings for UserName, UserPassword as the TLV's
 *                           are not null terminated.
 * 
 * urd_req_dump()            dump contents of radius packet decoded with
 *                           urd_req_decode().
 *
 * urd_rep_encode()          Encode a radius reply as either ACCESS-ACCEPT,
 *                           ACCESS-REJECT, or ACCESS-CHALLENGE.  An
 *                           ACCESS-CHALLENGE will encode a state variable
 *                           used by the upper layer to emulate a session.
 *                           State is required for a robust one time password
 *                           authentication implementation.
 *
 * urd_debug()               enable/disable debugging.
 *
 * urd_req_cache_update()    Update request cache with code,state.
 *
 * urd_req_cache_lookup()    Lookup request in request cache, return code,
 *                           state.
 * urd_state_cache_lookup()  Lookup state variable in state cache.
 *
 * urd_req_cache_stats()     Dump stats for request cache.
 * 
 * urd_state_cache_stats()   Dump stats for state cache.
 *
 */

/*
 * function: urd_req_decode()
 *
 * Sanity check and decode RADIUS Access-Request datagrams.
 *
 * Ignore Accounting-Request
 *
 * Drop requests with null authenticator.
 *
 * Setup pointers to TLV's for direct access:
 *   User-Name
 *   User-Password
 *   NAS-IP-Address
 *   NAS-Port
 *   NAS-Port-Type
 *   NAS-Identifier
 *   State
 *
 * Create C strings for User-Name and User-Password.
 *
 * User-Password is un-hidden per standard and available as user_pass
 *
 * Decode urd state variable into 64 bit counter.
 *
 * returns < 0 : fail
 *           0 : success
 */
int urd_req_decode(struct urd_ctx *urdctx)
{
  uint8_t md_val[EVP_MAX_MD_SIZE], md_i[RADIUS_AUTHENTICATOR_LEN];
  uint8_t *bp, v, h;
  uint md_len;
  int bytes_left, i, j, na, tlv_count;

  /* min packet length */
  if (urdctx->req.pkt_len < URD_PACKET_LEN_MIN) {
    xerr_warnx("decode_fail: pkt_len=%d<%d", urdctx->req.pkt_len,
      URD_PACKET_LEN_MIN);
    return -1;
  }

  /* first few bytes are the header */
  bcopy(&urdctx->req.pkt_buf, &urdctx->req.dgram_header,
    sizeof (struct radius_dgram_header));

  /* length is in network byte order */
#if BYTE_ORDER == LITTLE_ENDIAN
  SWAPINT16(urdctx->req.dgram_header.length);
#elif BYTE_ORDER == BIG_ENDIAN
#else
  BYTE_ORDER not defined
#endif

  /* check for null authenticator */
  for (i = 0, na = 0; i < RADIUS_AUTHENTICATOR_LEN; ++i) {
    if (urdctx->req.dgram_header.authenticator[i] != 0) {
      na = 1;
      break;
    }
  }

  /* null authenticator? */
  if (na == 0) {
    xerr_warnx("decode_fail: null authenticator");
    return -1;
  }

  /* verify length field does not overrun packet buffer */
  if (urdctx->req.dgram_header.length > urdctx->req.pkt_len) {
    xerr_warnx("decode_fail: pkg_header.length=%d > pkt_len=%d",
      urdctx->req.dgram_header.length, urdctx->req.pkt_len);
    return -1;
  }

  /* expecting ACCESS-REQUEST or ACCOUNTING_REQUEST */
  if ((urdctx->req.dgram_header.code != RADIUS_CODE_ACCESS_REQUEST) &&
      (urdctx->req.dgram_header.code != RADIUS_CODE_ACCOUNTING_REQUEST)) {
    xerr_warnx("decode_fail: Unexpected code=0x%X",
      (int)urdctx->req.dgram_header.code);
    return -1;
  }

  /* ignore accounting packets */
  if (urdctx->req.dgram_header.code == RADIUS_CODE_ACCOUNTING_REQUEST)
    return 1;

  /* start of TLV area */
  bp = urdctx->req.pkt_buf + sizeof (struct radius_dgram_header);

  /* no TLV's so far */
  urdctx->req.tlv_count = 0;

  /* bytes left before end of packet */
  bytes_left = urdctx->req.pkt_len - sizeof (struct radius_dgram_header);

  /*
   * run through list of attributes (TLV), verify sane length's
   * init TLV array and TLV shortcust.
   */
  urdctx->req.tlv_User_Name = (struct urd_tlv*)0L;
  urdctx->req.tlv_NAS_IP_Address = (struct urd_tlv*)0L;
  urdctx->req.tlv_NAS_Port = (struct urd_tlv*)0L;
  urdctx->req.tlv_NAS_Port_Type = (struct urd_tlv*)0L;
  urdctx->req.tlv_NAS_Identifier = (struct urd_tlv*)0L;
  urdctx->req.tlv_User_Password = (struct urd_tlv*)0L;
  urdctx->req.tlv_State = (struct urd_tlv*)0L;
  bzero(&urdctx->req.user_name, URD_USER_NAME_LEN+1);
  bzero(&urdctx->req.user_pass, URD_USER_PASS_LEN+1);
  urdctx->req.state_counter = 0;

  while (1) {

    /* TLV count */
    tlv_count = urdctx->req.tlv_count;

    /* min 2 bytes left to decode tlv_count and tlv_len */
    if (bytes_left < 2) {
      xerr_warnx("decode_fail: bytes_left=%d < 2", bytes_left);
      return -1;
    }

    if (tlv_count >= URD_MAX_TLV) {
      xerr_warnx("decode:fail: TLV count %d exceeds %d", tlv_count,
        URD_MAX_TLV);
      return -1;
    }

    urdctx->req.tlv[tlv_count].type = *bp;
    urdctx->req.tlv[tlv_count].len = *(bp+1);

    if (urdctx->req.tlv[tlv_count].len < 2) {
      xerr_warnx("decode_fail: illegal TLV len=%d < 2",
        urdctx->req.tlv[tlv_count].len);
      return -1;
    }

    /* len is now the length of the data item */
    urdctx->req.tlv[tlv_count].len -= 2;

    if (urdctx->req.tlv[tlv_count].len)
      urdctx->req.tlv[tlv_count].val = bp+2;
    else /* empty TLV */
      urdctx->req.tlv[tlv_count].val = (uint8_t*)0L;

    /* advance byte pointer past current TLV */
    bp += urdctx->req.tlv[tlv_count].len + 2;

    /* bytes left is less the current TLV */
    bytes_left -= (urdctx->req.tlv[tlv_count].len + 2);

    /*
     * setup shortcuts to first instance of common attributes
     */
    switch (urdctx->req.tlv[tlv_count].type) {

      case RADIUS_ATTRIB_USER_NAME:
        if (!urdctx->req.tlv_User_Name)
          urdctx->req.tlv_User_Name = &urdctx->req.tlv[tlv_count];
        break;

      case RADIUS_ATTRIB_NAS_IP_ADDRESS:
        if (!urdctx->req.tlv_NAS_IP_Address)
          urdctx->req.tlv_NAS_IP_Address = &urdctx->req.tlv[tlv_count];
        break;

      case RADIUS_ATTRIB_NAS_PORT:
        if (!urdctx->req.tlv_NAS_Port)
          urdctx->req.tlv_NAS_Port = &urdctx->req.tlv[tlv_count];
        break;

      case RADIUS_ATTRIB_NAS_PORT_TYPE:
        if (!urdctx->req.tlv_NAS_Port_Type)
          urdctx->req.tlv_NAS_Port_Type = &urdctx->req.tlv[tlv_count];
        break;

      case RADIUS_ATTRIB_NAS_IDENTIFIER:
        if (!urdctx->req.tlv_NAS_Identifier)
          urdctx->req.tlv_NAS_Identifier = &urdctx->req.tlv[tlv_count];
        break;

      case RADIUS_ATTRIB_USER_PASSWORD:
        if (!urdctx->req.tlv_User_Password)
          urdctx->req.tlv_User_Password = &urdctx->req.tlv[tlv_count];
        break;

      case RADIUS_ATTRIB_STATE:
        if (!urdctx->req.tlv_State)
          urdctx->req.tlv_State = &urdctx->req.tlv[tlv_count];
        break;

    } /* switch */

    urdctx->req.tlv_count ++;

    if (!bytes_left)
      break;

  } /* decode TLV's */

  /* C string */
  if (urdctx->req.tlv_User_Name) {

    if ((urdctx->req.tlv_User_Name->len > URD_USER_NAME_LEN) ||
        (urdctx->req.tlv_User_Name->len == 0)) {
      xerr_warnx("decode_fail: UserName TLV length=%d max=%d,min=0",
        urdctx->req.tlv_User_Name->len, URD_USER_NAME_LEN);
      return -1;
    }

    bcopy(urdctx->req.tlv_User_Name->val, &urdctx->req.user_name,
      urdctx->req.tlv_User_Name->len);
    urdctx->req.user_name[urdctx->req.tlv_User_Name->len] = 0;

  } /* urdctx->req.tlv_User_Name */

  /* C string */
  if (urdctx->req.tlv_User_Password) {

    if ((urdctx->req.tlv_User_Password->len > URD_USER_PASS_LEN) ||
        (urdctx->req.tlv_User_Password->len == 0)) {
      xerr_warnx("decode_fail: UserPassword TLV length=%d max=%d,min=0",
        urdctx->req.tlv_User_Password->len, URD_USER_PASS_LEN);
      return -1;
    }

  } /* urdctx->req.tlv_User_Password */

  /* valid state? */
  if (urdctx->req.tlv_State) {

    /* urd:0123456789abcdef */
    if (urdctx->req.tlv_State->len != 20) {
      xerr_warnx("decode_fail: State TLV len=%d != 20",
        (int)urdctx->req.tlv_State->len);
      return -1;
    }

    if ((urdctx->req.tlv_State->val[0] != 'u') ||
        (urdctx->req.tlv_State->val[1] != 'r') ||
        (urdctx->req.tlv_State->val[2] != 'd') ||
        (urdctx->req.tlv_State->val[3] != ':')) {
      xerr_warnx("decode_fail: State TLV expecting urd:");
      return -1;
    }

    for (i = 4; i < 20; ++i) {

      h = urdctx->req.tlv_State->val[i];

      /* decode nybble */
      if (h >= '0' && h <= '9')
        v = h - '0';
      else if (h >= 'A' && h <= 'F')
        v = h - 'A' + 10;
      else if (h >= 'a' && h <= 'f')
        v = h - 'a' + 10;
      else {
        xerr_warnx("decode_fail: State TLV expecting hex");
        return -1;
      }

      /* shift in nybble */
      urdctx->req.state_counter = (urdctx->req.state_counter<<4) | v;

    } /* foreach hex digit */

  } /* urdctx->req.tlv_State */

  /* unmunge the User-Password? and convert to C string */
  if (urdctx->rsecret && urdctx->req.tlv_User_Password) {

    /* first round of MD5 input authenticator */
    bcopy(&urdctx->req.dgram_header.authenticator, md_i,
      RADIUS_AUTHENTICATOR_LEN);

    for (i = 0; i < urdctx->req.tlv_User_Password->len; i += 16) {

      /* MD5 hash of rsecret + md_i */
      EVP_DigestInit_ex(&urdctx->req.mdctx, EVP_md5(), NULL);
      EVP_DigestUpdate(&urdctx->req.mdctx, urdctx->rsecret,
        strlen(urdctx->rsecret));
      EVP_DigestUpdate(&urdctx->req.mdctx, md_i, RADIUS_AUTHENTICATOR_LEN);
      EVP_DigestFinal_ex(&urdctx->req.mdctx, md_val, &md_len);
      EVP_MD_CTX_cleanup(&urdctx->req.mdctx);

      for (j = 0; j < 16; ++j) {
        urdctx->req.user_pass[i+j] =\
          urdctx->req.tlv_User_Password->val[i+j] ^ md_val[j];
      }

      /* next round of MD5 from previous */
      bcopy(&urdctx->req.tlv_User_Password->val[i], md_i,
        RADIUS_AUTHENTICATOR_LEN);

    } /* for each 16 byte chunk of user password */

    /* C string, null terminate */
    urdctx->req.user_pass[urdctx->req.tlv_User_Password->len] = 0;

  }

  return 0;

} /* urd_req_decode */

/*
 * function: urd_req_dump()
 *
 * Debug tool for RADIUS requests passed through urd_req_decode(). 
 * dumps interesting fields and TLV's.
 *
 */
void urd_req_dump(struct urd_ctx *urdctx)
{
  int buf_l, i, j, decode_type;
  char buf[1024];

  buf_l = snprintf(buf, 1024,
    "pkt.code=%2.2X, pkt.id=%2.2X, pkt.len=%2.2X, pkt.auth=",
    (int)urdctx->req.dgram_header.code,
    (int)urdctx->req.dgram_header.identifier,
    (int)urdctx->req.dgram_header.length);
  for (j = 0; j < RADIUS_AUTHENTICATOR_LEN; ++j)
    buf_l += snprintf(buf+buf_l, 1024-buf_l, "%2.2X",
      ((int)urdctx->req.dgram_header.authenticator[j]));

  xerr_info(buf);

  xerr_info("pkt_len=%d, tlv->count=%d", urdctx->req.pkt_len,
    urdctx->req.tlv_count);

  for (i = 0; i < urdctx->req.tlv_count; ++i) {

    /* decode type */
    switch (urdctx->req.tlv[i].type) {

      case RADIUS_ATTRIB_USER_NAME:
        decode_type = URD_DECODE_TYPE_CHAR;
        break;

      case RADIUS_ATTRIB_NAS_IP_ADDRESS:
      case RADIUS_ATTRIB_FRAMED_IP_ADDRESS:
      case RADIUS_ATTRIB_FRAMED_IP_NETMASK:
        decode_type = URD_DECODE_TYPE_IP;
        break;

      default:
        decode_type = URD_DECODE_TYPE_HEX;
        break;

    } /* switch */

    buf_l = snprintf(buf, 1024,
      "  TLV type=%d, len=%d, val=", (int)urdctx->req.tlv[i].type,
      (int)urdctx->req.tlv[i].len);

    switch (decode_type) {

      case URD_DECODE_TYPE_HEX:
        buf_l += snprintf(buf+buf_l, 1024-buf_l, "H ");
        for (j = 0; j < urdctx->req.tlv[i].len; ++j)
          buf_l += snprintf(buf+buf_l, 1024-buf_l, "%2.2X",
            (int)urdctx->req.tlv[i].val[j]);
        break;

      case URD_DECODE_TYPE_CHAR:
        buf_l += snprintf(buf+buf_l, 1024-buf_l, "C ");
        for (j = 0; j < urdctx->req.tlv[i].len; ++j)
          buf_l += snprintf(buf+buf_l, 1024-buf_l, "%c",
            urdctx->req.tlv[i].val[j]);
        break;

      case URD_DECODE_TYPE_IP:
        buf_l += snprintf(buf+buf_l, 1024-buf_l, "I %d.%d.%d.%d",
          (int)urdctx->req.tlv[i].val[0], (int)urdctx->req.tlv[i].val[1],
           (int)urdctx->req.tlv[i].val[2], (int)urdctx->req.tlv[i].val[3]);
        break;

    } /* switch */

    xerr_info(buf);

  } /* foreach TLV/Attribute */

} /* urd_req_dump */

/*
 * function: urd_rep_encode()
 *
 * Encode radius reply from request.
 * 
 * Request must be decoded by urd_req_decode() first.
 *
 * code (one of):
 *   RADIUS_CODE_ACCESS_ACCEPT
 *   RADIUS_CODE_ACCESS_REJECT
 *   RADIUS_CODE_ACCESS_CHALLENGE
 *
 * flags:
 *   URD_ENCODE_FLAG_STATE - state variable is encoded and added to TLV's
 *   URD_ENCODE_FLAG_MSG   - message is encoded and added to TLV's
 *
 * state_counter is encoded as ASCII hex to avoid buggy client
 * implementations which do not treat state as opaque.
 *
 * authenticator field is set based on packet contents and shared
 * client/server secret per standard.
 *
 */
int urd_rep_encode(struct urd_ctx *urdctx, uint8_t code,
  uint64_t state_counter, int rep_encode_flags)
{
  struct radius_dgram_header dgram_header, *dh;
  struct urd_tlv_state tlv_state;
  struct urd_tlv_rep_msg tlv_rep_msg;
  u_char md_val[EVP_MAX_MD_SIZE];
  uint md_len;
  int i, pkt_p;
  char *c;

  bzero(&dgram_header, sizeof dgram_header);
  bzero(&tlv_state, sizeof tlv_state);
  bzero(&tlv_rep_msg, sizeof tlv_rep_msg);

  /* destination IP is source of request */
  bcopy(&urdctx->req.rem_addr, &urdctx->rep.rem_addr,
    sizeof (urdctx->req.rem_addr));

  /* construct reply header from request */
  dgram_header.code = code;
  dgram_header.identifier = urdctx->req.dgram_header.identifier;
  dgram_header.length = sizeof (dgram_header);
  bcopy(&urdctx->req.dgram_header.authenticator, &dgram_header.authenticator,
    sizeof dgram_header.authenticator);

  /* add state? */
  if (rep_encode_flags & URD_ENCODE_FLAG_STATE) {

    dgram_header.length += sizeof (tlv_state);

    /* encode state_counter as urd: followed by 8 bytes as hex/ASCII */
    tlv_state.type = RADIUS_ATTRIB_STATE;
    tlv_state.len = sizeof (tlv_state);
    tlv_state.val[0] = 'u'; tlv_state.val[1] = 'r';
    tlv_state.val[2] = 'd'; tlv_state.val[3] = ':';

    c = (char*)&state_counter;
    i = 19;
    
    while (i > 4) {

      tlv_state.val[i--] = nta(*c & 0x0F);
      tlv_state.val[i--] = nta(*c >> 4);
      ++c;

    }

  } /* URD_ENCODE_FLAG_STATE */

  /* add reply message? */
  if (rep_encode_flags & URD_ENCODE_FLAG_MSG) {

    dgram_header.length += sizeof (tlv_rep_msg);

/* XXX hard coded to ABCD... */
    tlv_rep_msg.type = RADIUS_ATTRIB_REPLY_MESSAGE;
    tlv_rep_msg.len = sizeof (tlv_rep_msg);
    for (i = 0; i < 7; ++i)
      tlv_rep_msg.val[i] = 'A'+i;
    tlv_rep_msg.val[7] = 0;

  } /* URD_ENCODE_FLAG_MSG */

  /* preserve length in host byte order */
  urdctx->rep.pkt_len = dgram_header.length;

  /* length is in network byte order */
#if BYTE_ORDER == LITTLE_ENDIAN
  SWAPINT16(dgram_header.length);
#elif BYTE_ORDER == BIG_ENDIAN
#else
  BYTE_ORDER not defined
#endif

  /* copy packet header into reply buffer */
  bcopy(&dgram_header, &urdctx->rep.pkt_buf, sizeof (dgram_header));
  pkt_p = sizeof (dgram_header);

  if (rep_encode_flags & URD_ENCODE_FLAG_STATE) {
    bcopy(&tlv_state, (char*)&urdctx->rep.pkt_buf + pkt_p, sizeof(tlv_state));
    pkt_p += sizeof(tlv_state);
  }

  if (rep_encode_flags & URD_ENCODE_FLAG_MSG) {
    bcopy(&tlv_rep_msg, (char*)&urdctx->rep.pkt_buf + pkt_p,
      sizeof(tlv_rep_msg));
    pkt_p += sizeof(tlv_rep_msg);
  }

  /* MD5(reply packet + secret) */
  EVP_DigestInit_ex(&urdctx->req.mdctx, EVP_md5(), NULL);
  EVP_DigestUpdate(&urdctx->req.mdctx, &urdctx->rep.pkt_buf, pkt_p);
  EVP_DigestUpdate(&urdctx->req.mdctx, urdctx->rsecret,
    strlen(urdctx->rsecret));
  EVP_DigestFinal_ex(&urdctx->req.mdctx, md_val, &md_len);
  EVP_MD_CTX_cleanup(&urdctx->req.mdctx);

  dh = (struct radius_dgram_header*)&urdctx->rep.pkt_buf;

  /* copy this directly back into packet */
  bcopy(&md_val, &dh->authenticator, sizeof dgram_header.authenticator);

  return 0;

} /* urd_rep_encode */

/*
 * function: urd_ctx_new()
 *
 * Allocates and initialize urd_ctx
 *
 * urd_ctx_free() will release relources.
 *
 * returns   sturct urd_ctx*
 *           0L for failure
 */
struct urd_ctx *urd_ctx_new(char *rsecret)
{
  struct urd_ctx *urdctx;
  uint i;

  if (!(urdctx = (struct urd_ctx*)malloc(sizeof *urdctx))) {
    xerr_warn("malloc(urd_ctx)");
    return urdctx;
  }

  bzero(urdctx, sizeof (*urdctx));

  strncpy(urdctx->rsecret, rsecret, URD_SECRET_LEN);
  urdctx->rsecret[URD_SECRET_LEN] = 0;

  for (i = 0; i < 1<<URD_REQ_HASH_BUCKET_BITS; ++i) {
    LIST_INIT(&urdctx->req_cache_bucket[i]);
  }

  EVP_MD_CTX_init(&urdctx->req.mdctx);

  return urdctx;

} /* urd_ctx_new */

/*
 * function: urd_ctx_free()
 *
 * Free resources allocated with urd_ctx_new()
 *
 */
void urd_ctx_free(struct urd_ctx *urdctx)
{
  if (urdctx)
    free (urdctx);
} /* urd_ctx_free */

/*
 * function: urd_req_cache_update()
 *
 * UserName and UserPassWord TLV's must be in request (req)
 * and be of length <= URD_USER_NAME_LEN/URD_USER_PASS_LEN
 *
 * The request cache is keyed from the authenticator field
 * in a radius request.  Requests have a lifetime started
 * at create_time.  The cache provides the code and state
 * variables to the upper layer.
 *
 * Optionally update the state cache if flags has URD_CACHE_FLAG_STATE
 * set.  The state cache is keyed from the state cache TLV present
 * in an Access-Request generated via a Access-Challenge response
 * to a previous Access-Request.
 *
 * returns: < 0 : fail
 *            0 : success
 *
 */
int urd_req_cache_update(struct urd_ctx *urdctx, uint8_t rep_code,
  uint64_t state_counter, int req_cache_flags)
{
  uint16_t req_hash, req_hash_mask, state_hash, state_hash_mask;
  struct urd_req_cache_entry *e;
  int i;

  req_hash = 0;
  req_hash_mask = (uint16_t)((1<<URD_REQ_HASH_BUCKET_BITS)-1);

  for (i = 0; i < RADIUS_AUTHENTICATOR_LEN; i += 2) {
    req_hash ^= (uint16_t)(urdctx->req.dgram_header.authenticator[i]) |
                (uint16_t)(urdctx->req.dgram_header.authenticator[i+1]<<8);
  }
  req_hash ^= urdctx->req.dgram_header.identifier;
  req_hash &= req_hash_mask;

  /* next free request cache entry */
  e = &urdctx->req_cache[urdctx->req_cache_len++];
  bzero(e, sizeof *e);

  /* insert entry into hash bucket req_chain */
  LIST_INSERT_HEAD(&urdctx->req_cache_bucket[req_hash], e, req_chain);

  /* hash table for state? */
  if (req_cache_flags & URD_CACHE_FLAG_STATE) {

    state_hash_mask = (uint16_t)((1<<URD_STATE_HASH_BUCKET_BITS)-1);

    state_hash = (state_counter & 0x0000FFFF);
    state_hash ^= ((state_counter>>16) & 0x0000FFFF);
    state_hash ^= ((state_counter>>32) & 0x0000FFFF);
    state_hash ^= ((state_counter>>48) & 0x0000FFFF);

    state_hash &= state_hash_mask;

    /* insert entry into hash bucket state_chain */
    LIST_INSERT_HEAD(&urdctx->state_cache_bucket[state_hash], e, state_chain);

    e->flags = URD_STATE_CACHE_FLAGS_INUSE;

  } /* hash table for state */

  /*
   * fill in entry
   */

  bcopy(urdctx->req.user_pass, e->user_pass, URD_USER_PASS_LEN+1);
  bcopy(urdctx->req.user_name, e->user_name, URD_USER_NAME_LEN+1);
  bcopy(urdctx->req.dgram_header.authenticator, e->rad_auth,
    RADIUS_AUTHENTICATOR_LEN);

  e->state_counter = state_counter;

  e->create_time = time((time_t*)0L);

  e->rad_code = rep_code;

  e->rad_id = urdctx->req.dgram_header.identifier;

  e->rexmit_count = 0;

  e->flags ^= URD_REQ_CACHE_FLAGS_INUSE;

  /* rollover */
  if (urdctx->req_cache_len == URD_REQ_CACHE_ENTRIES)
    urdctx->req_cache_len = 0;

  /* if the current entry was previously in use, remove from hash chain */
  if (urdctx->req_cache[urdctx->req_cache_len].flags &
    URD_REQ_CACHE_FLAGS_INUSE) {

    LIST_REMOVE(&urdctx->req_cache[urdctx->req_cache_len], req_chain);

    urdctx->req_cache[urdctx->req_cache_len].flags &=\
      ~URD_REQ_CACHE_FLAGS_INUSE;

  } /* in use? */

  /* if the current entry was previously in use, remove from hash chain */
  if (urdctx->req_cache[urdctx->req_cache_len].flags &
    URD_STATE_CACHE_FLAGS_INUSE) {

    LIST_REMOVE(&urdctx->req_cache[urdctx->req_cache_len], state_chain);

    urdctx->req_cache[urdctx->req_cache_len].flags &=\
      ~URD_STATE_CACHE_FLAGS_INUSE;

  } /* in use? */

  return 0;

} /* urd_req_cache_update */

/*
 * function: urd_req_cache_lookup()
 *
 * The request cache is used to provide re-transmitted requests
 * (packet loss between client and server) to a client.
 *
 * UserName and UserPassWord TLV's must be in request (req)
 * and be of length <= URD_USER_NAME_LEN/URD_USER_PASS_LEN
 *
 * Lookup request in cache by Authenticator field.  Additionally
 * verify identifier, user_name, user_pass and state (if present) match
 * the cache'd request.  If the entry has not expired (older than
 * URD_REQ_CACHE_LIFETIME seconds), return code and state associated
 * with cache.
 *
 * returns: URD_REQ_CACHE_HIT (cache hit)
 *          URD_REQ_CACHE_MISS (cache miss)
 *
 */
int urd_req_cache_lookup(struct urd_ctx *urdctx, uint8_t *code,
  uint64_t *state_counter)
{
  time_t now;
  uint16_t hash, hash_mask;
  struct urd_req_cache_entry *e;
  int i, match, depth;

  hash = 0;
  hash_mask = (uint16_t)((1<<URD_REQ_HASH_BUCKET_BITS)-1);

  for (i = 0; i < RADIUS_AUTHENTICATOR_LEN; i += 2) {
    hash ^= (uint16_t)(urdctx->req.dgram_header.authenticator[i]) |
            (uint16_t)(urdctx->req.dgram_header.authenticator[i+1]<<8);
  }
  hash ^= urdctx->req.dgram_header.identifier;
  hash &= hash_mask;

  /* not found yet */
  match = 0;

  /* debugging, depth of chain */
  depth = 0;

  /* run down the chain */
  LIST_FOREACH(e, &urdctx->req_cache_bucket[hash], req_chain) {

    /* debugging */
    depth += 1;

    /* match on key fields */
    if (!(bcmp(&e->rad_auth, &urdctx->req.dgram_header.authenticator,
      RADIUS_AUTHENTICATOR_LEN))) {

      if ((!strcmp(e->user_name, urdctx->req.user_name)) &&
          (!strcmp(e->user_pass, urdctx->req.user_pass)) &&
          (e->rad_id == urdctx->req.dgram_header.identifier)) {

        if ((!urdctx->req.tlv_State) ||
          ((urdctx->req.tlv_State) &&
           (urdctx->req.state_counter == e->state_counter))) {

          /* cache entry older than URD_REQ_CACHE_LIFETIME seconds? */
          now = time((time_t*)0L);
          if ((now - e->create_time) < URD_REQ_CACHE_LIFETIME) {

            /*
             * cache hit
             */

            /* number of packet retransmits */
            ++e->rexmit_count;

            if (urdctx->debug)
              xerr_info("rexmit_count=%d", (int)e->rexmit_count);

            /* cached result code and state */
            *code = e->rad_code;
            *state_counter = e->state_counter;

            match = 1;
            break;

          /* state timeout */
          } else if (urdctx->debug) {
              xerr_info("urd_req_cache_lookup: entry expired");
          }
        /* state match */
        } else if (urdctx->debug) {
            xerr_info("urd_req_cache_lookup: miss state");
        }
      /* inner match */
      } else if (urdctx->debug) {
          xerr_info("urd_req_cache_lookup: miss inner");
      }
    } /* match authenticator */

  } /* LIST_FOREACH */

  if (urdctx->debug)
    xerr_info("urd_req_cache_lookup depth=%d", depth);

  if (match)
    return URD_REQ_CACHE_HIT;
  else
    return URD_REQ_CACHE_MISS;

} /* urd_req_cache_lookup */

/*
 * function: urd_state_cache_lookup()
 *
 * The state cache is used to pair an Access-Request with state
 * to a previous Access-Request without state.  The initial
 * Access-Request (no state) is used to verify a username/re-usable
 * password pair.  The stateful request performs the one time
 * password authentication.
 *
 * UserName and UserPassWord TLV's must be in request (req)
 * and be of length <= URD_USER_NAME_LEN/URD_USER_PASS_LEN
 *
 * Lookup request in cache by state field.  Additionally
 * verify user_name matches the initial Access-Request.
 * If the entry has not expired (older than URD_STATE_CACHE_LIFETIME seconds
 * return a hit.
 *
 * returns: URD_REQ_CACHE_HIT (cache hit)
 *          URD_REQ_CACHE_MISS (cache miss)
 *
 */
int urd_state_cache_lookup(struct urd_ctx *urdctx, uint8_t *code)
{
  time_t now;
  uint16_t state_hash, state_hash_mask;
  struct urd_req_cache_entry *e;
  int match, depth;

  state_hash = 0;
  state_hash_mask = (uint16_t)((1<<URD_STATE_HASH_BUCKET_BITS)-1);

  state_hash = (urdctx->req.state_counter & 0x0000FFFF);
  state_hash ^= ((urdctx->req.state_counter>>16) & 0x0000FFFF);
  state_hash ^= ((urdctx->req.state_counter>>32) & 0x0000FFFF);
  state_hash ^= ((urdctx->req.state_counter>>48) & 0x0000FFFF);

  state_hash &= state_hash_mask;

  /* not found yet */
  match = 0;

  /* debugging, depth of chain */
  depth = 0;

  /* run down the chain */
  LIST_FOREACH(e, &urdctx->state_cache_bucket[state_hash], state_chain) {

    /* debugging */
    depth += 1;

    /* match on key fields */
    if (e->state_counter == urdctx->req.state_counter) {

      if (!strcmp(e->user_name, urdctx->req.user_name)) {

        /* cache entry older than URD_STATE_CACHE_LIFETIME seconds? */
        now = time((time_t*)0L);
        if ((now - e->create_time) < URD_STATE_CACHE_LIFETIME) {

          /*
           * cache hit
           */

          /* number of packet retransmits */
          ++e->rexmit_count;

          if (urdctx->debug)
            xerr_info("rexmit_count=%d", (int)e->rexmit_count);

          /* cached result code and state */
          *code = e->rad_code;

          match = 1;
          break;

        /* state timeout */
        } else if (urdctx->debug) {
            xerr_info("urd_state_cache_lookup: entry expired");
        }
      /* inner match */
      } else if (urdctx->debug) {
        xerr_info("urd_state_cache_lookup: miss inner");
      }

    } /* match state_counter */

  } /* LIST_FOREACH */

  if (urdctx->debug)
    xerr_info("urd_state_cache_lookup depth=%d", depth);

  if (match)
    return URD_STATE_CACHE_HIT;
  else
    return URD_STATE_CACHE_MISS;

} /* urd_state_cache_lookup */

/*
 * function: urd_state_cache_stats()
 *
 * Dump state_cache hash table depths.
 *
 */
void urd_state_cache_stats(struct urd_ctx *urdctx)
{
  struct urd_req_cache_entry *e;
  int depth, i;

  xerr_info("state_cache_stats:");

  for (i = 0; i < 1<<URD_STATE_HASH_BUCKET_BITS; ++i) {

    if (LIST_EMPTY(&urdctx->state_cache_bucket[i]))
      continue;

    depth = 0;
    LIST_FOREACH(e, &urdctx->state_cache_bucket[i], state_chain)
      ++depth;

    xerr_info(" bucket=%d,depth=%d", i, depth);

  } /* hash bucket */

} /* urd_state_cache_stats */

/*
 * function: urd_req_cache_stats()
 *
 * Dump req_cache hash table depths.
 *
 */
void urd_req_cache_stats(struct urd_ctx *urdctx)
{
  struct urd_req_cache_entry *e;
  int depth, i;

  xerr_info("req_cache_stats:");

  for (i = 0; i < 1<<URD_REQ_HASH_BUCKET_BITS; ++i) {

    if (LIST_EMPTY(&urdctx->req_cache_bucket[i]))
      continue;

    depth = 0;
    LIST_FOREACH(e, &urdctx->req_cache_bucket[i], req_chain)
      ++depth;

    xerr_info(" bucket=%d,depth=%d", i, depth);

  } /* hash bucket */

} /* urd_req_cache_stats */

/*
 * function: urd_debug()
 *
 * set/clear urd context debug 
 *
 */
void urd_debug(struct urd_ctx *urdctx, int debug)
{
  urdctx->debug = debug;
} /* urd_debug() */

/*
 * function: nta()
 *
 * return ASCII value of low hex nybble
 *
 */
uint8_t nta(uint8_t b)
{
  if (b < 10)
    b = '0' + b;
  else
    b = 'A' + (b-10);

  return b;
} /* nta */

