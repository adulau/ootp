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
 *      $Id: sccmd.h 13 2009-11-26 16:37:03Z maf $
 */


#ifndef SCCMD_H
#define SCCMD_H

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stddef.h>
#include "scr.h"

int sccmd_GetVersion(struct scr_ctx *scrctx, u_char fv, u_char *sc_version);
int sccmd_GetCapabilities(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_capabilities);
int sccmd_TestPIN(struct scr_ctx *scrctx, u_char fv, char *sc_PIN);
int sccmd_SetPIN(struct scr_ctx *scrctx, u_char fv, char *sc_PIN,
  char *sc_newPIN);
int sccmd_GetHOTP(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  char *sc_PIN, u_char *sc_hotp);
int sccmd_GetHOTPHost(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  char *sc_PIN, u_char *sc_hotp, char *sc_hostname);
int sccmd_GetHOTPCount32(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  char *sc_PIN, u_char *sc_count32, u_char *sc_hotp);
int sccmd_GetHOTPHostCount32(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  char *sc_PIN, u_char *sc_count32, u_char *sc_hotp, char *sc_hostname);
int sccmd_SetAdminMode(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_adminmode, u_char *sc_adminkey);
int sccmd_SetAdminKey(struct scr_ctx *scrctx, u_char fv, u_char *sc_adminkey);
int sccmd_GetHost(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_idx, u_char *sc_count, char *sc_hostname, u_char *sc_hotpkey);
int sccmd_GetHost32(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  u_char *sc_count32, char *sc_hostname, u_char *sc_hotpkey);
int sccmd_GetHostName(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_idx, char *sc_PIN, char *sc_hostname);
int sccmd_SetHost(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  u_char *sc_count, char *sc_hostname, u_char *sc_hotpkey);
int sccmd_SetHost32(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  u_char *sc_count32, char *sc_hostname, u_char *sc_hotpkey);
int sccmd_SetBalanceCardIndex(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_idx);
int sccmd_ClearAll(struct scr_ctx *scrctx, u_char fv);

int sccmd_BCGetState(struct scr_ctx *scrctx, u_char *sc_state,
  u_char *sc_version, u_char *sc_version_len);
int sccmd_BCEEPromSize(struct scr_ctx *scrctx, u_char *sc_start,
   u_char *sc_len);
int sccmd_BCSetState(struct scr_ctx *scrctx, u_char sc_state);
int sccmd_BCClearEEProm(struct scr_ctx *scrctx, uint8_t *sc_EEAddr,
  uint8_t *sc_EELen);
int sccmd_BCWriteEEProm(struct scr_ctx *scrctx, uint8_t *sc_EEAddr,
  uint8_t *sc_EELen, uint8_t *sc_EEData);
int sccmd_BCEEPromCRC(struct scr_ctx *scrctx, uint8_t *sc_EEAddr,
  uint8_t *sc_EELen, uint8_t *sc_EECRC);

int sccmd_SetSpyrusEEBlock(struct scr_ctx *scrctx, uint8_t *sc_idx,
  uint8_t *sc_blockData);
int sccmd_GetSpyrusEEBlock(struct scr_ctx *scrctx, uint8_t *sc_idx,
  uint8_t *sc_blockData);

int sccmd_SetReaderKey(struct scr_ctx *scrctx, uint8_t *sc_readerKey);

#endif /* SCCMD_H */

