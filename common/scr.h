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
 *      $Id: scr.h 26 2009-11-29 23:01:37Z maf $
 */

#include "acr30.h"

#ifdef SCR_PCSC
#include <wintypes.h>
#include <winscard.h>
#endif /* SCR_PCSC */

#ifndef SCR_H
#define SCR_H

#define SCR_READER_EMBEDDED_ACR30S 0x01
#define SCR_READER_PCSC            0x02

#define SCR_EMBEDDED_ACR30S_NAME    "embedded:acr30s"
#define SCR_EMBEDDED_ACR30S_DEVICE  "/dev/cuaU0"

#ifndef SCR_DEFAULT_READER
/* #define SCR_DEFAULT_READER "embedded:acr30s:/dev/cuaU0" */
#define SCR_DEFAULT_READER "PCSC:"
#endif

#define SCR_TX_BUF_LEN 254
#define SCR_RX_BUF_LEN 254

/*
 * reader format
 *
 * PCSC:gemplus\0
 * embedded:acr30s:/dev/cuaU0\0
 */

struct scr_ctx
{
  struct acr30_ctx *acr30ctx;
#ifdef SCR_PCSC
  SCARDCONTEXT hContext;
  SCARDHANDLE hCard;
  DWORD dwActiveProtocol;
  char *pcsc_active_reader;
#endif /* SCR_PCSC */
  int verbose, valid, valid_readers, active_reader;
  int num_readers;
  char **readers;
  char *reader;
  int pcsc_reader_first;
};

struct scr_io {

  u_char tx_cla, tx_ins, tx_lc, tx_le;
  u_char tx_buf[SCR_TX_BUF_LEN], tx_buf_len;

  useconds_t tx_delay;

  u_char rx_buf[SCR_RX_BUF_LEN], rx_buf_len;
  u_char rx_SW1, rx_SW2;

}; /* scr_io */


struct scr_ctx* scr_ctx_new(int valid_readers, int verbose);
int scr_ctx_connect(struct scr_ctx *scrctx, char *reader);
int scr_ctx_cmd(struct scr_ctx *scrctx, struct scr_io *scrio);
void scr_ctx_free(struct scr_ctx *scr);
int scr_ctx_valid(struct scr_ctx *scrctx, char *who);
int scr_checksw1sw2_rx(struct scr_io *scrio, u_char dlen, u_char SW1,
  u_char SW2, u_char SW1_mask, u_char SW2_mask, int verbose);
int scr_ctx_reset(struct scr_ctx *scrctx);

#endif /* SCR_H */
