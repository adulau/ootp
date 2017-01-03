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
 *      $Id: rad.h 13 2009-11-26 16:37:03Z maf $
 */

#include <openssl/evp.h>
#include "sys/queue.h"
#include <time.h>

#define URD_PORT 1812                /* UDP port */
#define URD_HEADER_LEN 20            /* radius packet header length */
#define URD_MAX_DGRAM_LEN 4096       /* MAX datagram size */
#define URD_MAX_TLV 2048             /* MAX number of TLV's */
#define URD_USER_PASS_LEN  32        /* MAX user password - multiples of 16 */
#define URD_USER_NAME_LEN  32        /* MAX user name length */
#define URD_SECRET_LEN 32            /* MAX server/client secret length */

#define URD_PACKET_LEN_MIN 20        /* minimum datagram length */

#define URD_TLV_STATE_LEN  20        /* length of state tlv data */
/* XXX */
#define URD_TLV_REPLY_MSG_LEN 8      /* length of state reply message data */

/*
 * The cache length should be a minimum (max queries/second * cache seconds)
 * ie, 1000 queries per second * 10 second cache lifetime = 10000 entries
 * entries are kept in a ring buffer with a hashed entry lookup.
 *
 * The state cache shares the request cache entry list.  State caching
 * is used to pair up requests in a challenge/response to emulate a 
 * session.  These cache entries will need to live for as long as it
 * takes a user to enter their challenge/reponse, ie 60 seconds or
 * more.  At 1000 queries/second * 90 second cache lifetime = 90000
 * entries.  A challenge/response will also consume two entries, one
 * for the original request and one for the challenge (state) request.
 */
#define URD_REQ_CACHE_LIFETIME 10     /* lifetime of cache entry in seconds */
#define URD_REQ_CACHE_ENTRIES  16384  /* reply cache entries */

#define URD_REQ_CACHE_HIT 1          /* cache hit */
#define URD_REQ_CACHE_MISS 0         /* cache miss */

#define URD_REQ_CACHE_FLAGS_INUSE 0x1    /* cache entry is in use */
#define URD_STATE_CACHE_FLAGS_INUSE 0x2  /* cache entry is in use */

/* Hash buckets is dependent on the hash function.. */
#define URD_REQ_HASH_BUCKET_BITS 16    /* number of hash buckets */

#define URD_STATE_CACHE_LIFETIME 90    /* lifetime of cache entry in seconds */

#define URD_STATE_CACHE_HIT 1          /* cache hit */
#define URD_STATE_CACHE_MISS 0         /* cache miss */

#define URD_CACHE_FLAG_STATE 0x1       /* prep lookup by state too */

#define URD_ENCODE_FLAG_STATE   0x1    /* encode state in reply */
#define URD_ENCODE_FLAG_MSG     0x2    /* encode message in reply */

/* Hash buckets is dependent on the hash function.. */
#define URD_STATE_HASH_BUCKET_BITS 16    /* number of hash buckets */

#define RADIUS_AUTHENTICATOR_LEN        16

#define RADIUS_CODE_ACCESS_REQUEST      1
#define RADIUS_CODE_ACCESS_ACCEPT       2
#define RADIUS_CODE_ACCESS_REJECT       3
#define RADIUS_CODE_ACCOUNTING_REQUEST  4
#define RADIUS_CODE_ACCOUNTING_RESPONSE 5
#define RADIUS_CODE_ACCESS_CHALLENGE    11
#define RADIUS_CODE_STATUS_SERVER       12
#define RADIUS_CODE_STATUS_CLIENT       13
#define RADIUS_CODE_RESERVED            255

#define RADIUS_ATTRIB_USER_NAME                1
#define RADIUS_ATTRIB_USER_PASSWORD            2
#define RADIUS_ATTRIB_CHAP_PASSWORD            3
#define RADIUS_ATTRIB_NAS_IP_ADDRESS           4
#define RADIUS_ATTRIB_NAS_PORT                 5
#define RADIUS_ATTRIB_SERVICE_TYPE             6
#define RADIUS_ATTRIB_FRAMED_PROTOCOL          7
#define RADIUS_ATTRIB_FRAMED_IP_ADDRESS        8
#define RADIUS_ATTRIB_FRAMED_IP_NETMASK        9
#define RADIUS_ATTRIB_FRAMED_ROUTING           10
#define RADIUS_ATTRIB_FILTER_ID                11
#define RADIUS_ATTRIB_FRAMED_MTU               12
#define RADIUS_ATTRIB_FRAMED_COMPRESSION       13
#define RADIUS_ATTRIB_LOGIN_IP_HOST            14
#define RADIUS_ATTRIB_LOGIN_SERVICE            15
#define RADIUS_ATTRIB_LOGIN_TCP_PORT           16
#define RADIUS_ATTRIB_REPLY_MESSAGE            18
#define RADIUS_ATTRIB_CALLBACK_NUMBER          19
#define RADIUS_ATTRIB_CALLBACK_ID              20
#define RADIUS_ATTRIB_FRAMED_ROUTE             22
#define RADIUS_ATTRIB_FRAMED_IPX_NETWORK       23
#define RADIUS_ATTRIB_STATE                    24
#define RADIUS_ATTRIB_CLASS                    25
#define RADIUS_ATTRIB_VENDOR_SPECIFIC          26
#define RADIUS_ATTRIB_SESSION_TIMEOUT          27
#define RADIUS_ATTRIB_IDLE_TIMEOUT             28
#define RADIUS_ATTRIB_TERMINATION_ACTION       29
#define RADIUS_ATTRIB_CALLED_STATION_ID        30
#define RADIUS_ATTRIB_CALLING_STATION_ID       31
#define RADIUS_ATTRIB_NAS_IDENTIFIER           32
#define RADIUS_ATTRIB_PROXY_STATE              33
#define RADIUS_ATTRIB_LOGIN_LAT_SERVICE        34
#define RADIUS_ATTRIB_LOGIN_LAT_GROUP          35
#define RADIUS_ATTRIB_FRAMED_APPLETALK_LINK    36
#define RADIUS_ATTRIB_FRAMED_APPLETALK_NETWORK 37
#define RADIUS_ATTRIB_FRAMED_APPLETALK_ZONE    38
#define RADIUS_ATTRIB_CHAP_CHALLENGE           60
#define RADIUS_ATTRIB_NAS_PORT_TYPE            61
#define RADIUS_ATTRIB_PORT_LIMIT               62
#define RADIUS_ATTRIB_LOGIN_LAT_PORT           63

#define URD_DECODE_TYPE_HEX    0
#define URD_DECODE_TYPE_CHAR   1
#define URD_DECODE_TYPE_IP     2

struct radius_dgram_header {
  uint8_t   code;
  uint8_t   identifier;
  uint16_t  length;
  uint8_t   authenticator[16];
};

struct urd_tlv {
  uint8_t type;
  uint8_t len;
  uint8_t *val;
};

struct urd_tlv_state {
  uint8_t type;
  uint8_t len;
  uint8_t val[URD_TLV_STATE_LEN];
};

struct urd_tlv_rep_msg {
  uint8_t type;
  uint8_t len;
  uint8_t val[URD_TLV_REPLY_MSG_LEN];
};

struct urd_req_cache_entry {
  uint8_t   rad_auth[16];                       /* req_hash/rkey */
  char      user_name[URD_USER_NAME_LEN+1];     /* key */
  char      user_pass[URD_USER_PASS_LEN+1];     /* key */
  uint64_t  state_counter;                      /* state_hash/key */
  time_t    create_time;                        /* cache maintenance */
  uint8_t   rad_code;                           /* data to be cached */
  uint8_t   rad_id;                             /* req_hash/key */
  uint8_t   rexmit_count;                       /* retransmit count */
  uint8_t   flags;                              /* flags */
  LIST_ENTRY (urd_req_cache_entry) req_chain;   /* req_hash chain */
  LIST_ENTRY (urd_req_cache_entry) state_chain; /* state_hash chain */
};

/*
 * contiguous list of urd_req_cache_entry [0..URD_REQ_CACHE_SIZE-1]
 *
 * allocation is done on a round robin basis:
 *   if (++ce_index >= URD_REQ_CACHE_SIZE)
 *     rce_index = 0;
 *
 * when storing an entry (rce_index always points to the next free entry)
 * if (entry.flags & URD_REQ_CACHE_FLAGS_INUSE) then
 *   remove entry from req_chain before using.
 *
 * counter initialized to 1, counter=0 is a stateless cache entry, ie
 * initial request
 *
 * all _new_ replies go into the cache
 *   state = rad_auth+user_name+rad_id+counter
 *
 *  cache_expire
 *    - incremental by n (512) entries
 *  cache_lookup
 *
 */

struct urd_req {
  EVP_MD_CTX          mdctx;                            /* MD5 context */
  uint8_t             pkt_buf[URD_MAX_DGRAM_LEN];       /* raw datagram */
  struct              radius_dgram_header dgram_header; /* datagram header */
  struct              sockaddr_in rem_addr;             /* remote host */
  int                 pkt_len;                          /* packet length */
  int                 tlv_count;                        /* number TLV's */
  struct urd_tlv      tlv[URD_MAX_TLV];                 /* decoded TLV's */
  char                user_name[URD_USER_NAME_LEN+1];   /* C string */
  char                user_pass[URD_USER_PASS_LEN+1];   /* C string (clear) */
  uint64_t            state_counter;                    /* decoded state TLV */
  /* shortcuts */
  struct urd_tlv   *tlv_User_Name;
  struct urd_tlv   *tlv_NAS_IP_Address;
  struct urd_tlv   *tlv_NAS_Port;
  struct urd_tlv   *tlv_NAS_Port_Type;
  struct urd_tlv   *tlv_NAS_Identifier;
  struct urd_tlv   *tlv_User_Password;
  struct urd_tlv   *tlv_State;
};

struct urd_rep {
  uint8_t             pkt_buf[URD_MAX_DGRAM_LEN];     /* raw datagram */
  int                 pkt_len;                        /* packet length */
  struct              sockaddr_in rem_addr;           /* remote host */
};

struct urd_ctx {
  uint64_t  state_counter;
  struct urd_req req;
  struct urd_rep rep;
  int req_cache_len;
  LIST_HEAD(urd_req_cache_entry_head, urd_req_cache_entry)\
    req_cache_bucket[1<<(URD_REQ_HASH_BUCKET_BITS)];
  LIST_HEAD(urd_state_cache_entry_head, urd_req_cache_entry)\
    state_cache_bucket[1<<(URD_STATE_HASH_BUCKET_BITS)];
  struct urd_req_cache_entry req_cache[URD_REQ_CACHE_ENTRIES];
  char rsecret[URD_SECRET_LEN+1];
  int debug;
};

int urd_req_decode(struct urd_ctx *urdctx);
void urd_req_dump(struct urd_ctx *urdctx);
int urd_rep_encode(struct urd_ctx *urdctx, uint8_t code, 
 uint64_t state_counter, int rep_encode_flags);
struct urd_ctx *urd_ctx_new(char *rsecret);
void urd_ctx_free(struct urd_ctx *urdctx);
int urd_req_cache_update(struct urd_ctx *urdctx, uint8_t code,
  uint64_t state_counter, int req_cache_flags);
int urd_req_cache_lookup(struct urd_ctx *urdctx, uint8_t *code,
  uint64_t *state_counter);
int urd_state_cache_lookup(struct urd_ctx *urdctx, uint8_t *code);
void urd_state_cache_stats(struct urd_ctx *urdctx);
void urd_req_cache_stats(struct urd_ctx *urdctx);
void urd_debug(struct urd_ctx *urdctx, int debug);

