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
 *      $Id: sccmd.c 37 2009-12-01 13:30:02Z maf $
 */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include "otpsc.h"
#include "scr.h"
#include "sccmd.h"
#include "str.h"
#include "xerr.h"

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

/* ZC commands CLA=80
 *  b =  Byte             Idx,Mode,Version
 *  i =  Integer          Count
 *  l =  Long             Count32,Capabilities
 *  sn = String length n  Hostname(12),ZCKey(20),*PIN(5),HOTP(5),AdminKey(20)
 *                        eeBlock(16),readerKey(5)
 *
 *  00   PRDisplay  (CLA=C8)    -                             00000001
 *                RecordNumber(byte), DataFormat(byte), DigitCount(byte)
 *                DecimalPoint(byte), Delay(byte), MoreData(byte),Data(String)
 *  40   SetHost                Idx,Count,Hostname,HOTPKey    00000002
 *  42   GetHost                Idx,Count,Hostname,HOTPKey    00000004
 *  44   GetHostName            Idx,myPIN,Hostname            00000008
 *  46   GetHOTP                Idx,myPIN,HOTP                00000010
 *  48   SetAdminMode           Mode,AdminKey                 00000020
 *  4A   SetBalanceCardIndex    Idx                           00000040
 *  4C   SetPIN                 myPIN,newPIN                  00000080
 *  4E   TestPIN                myPIN                         00000100
 *  50   GetVersion             Version                       00000200
 *  52   SetAdminKey            AdminKey                      00000400
 *  54   SetHost32              Idx,Count32,Hostname,HOTPKey  00000800
 *  56   GetHost32              Idx,Count32,Hostname,HOTPKey  00001000
 *  58   GetHOTPCount32         Idx,myPIN,Count32,HOTP        00002000
 *  5A   GetHOTPHost            Idx,myPIN,HOTP,Hostname       00004000
 *  5C   GetHOTPHostCount32     Idx,myPIN,Count,HOTP,Hostname 00008000
 *  5E   ClearAll                                             00010000
 *  60   SetReaderKey           readerKey                     00020000
 *  90   GetCapabilities        Capabilities                  XXXXXXXX
 *  A0   GetEEBlock             P1=Idx,eeBlock                XXXXXXXX
 *  A1   SetEEBlock             P1=Idx,eeBlock                XXXXXXXX

 *
 */

int sccmd_BCEEPromCRC(struct scr_ctx *scrctx, uint8_t *sc_EEAddr,
  uint8_t *sc_EELen, uint8_t *sc_EECRC)
{
  struct scr_io scrio;
  int i, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = 2;
  scrio.tx_le = 2;
  scrio.tx_delay = SC_BCEEPROMCRC_DELAY;
  scrio.rx_buf_len = 2;
  i = 0;

  scrio.tx_buf[i++] = SC_BCEEPROMCRC_CLA;    /* CLA */
  scrio.tx_buf[i++] = SC_BCEEPROMCRC_INS;    /* INS */
  scrio.tx_buf[i++] = sc_EEAddr[0];          /* P1 */
  scrio.tx_buf[i++] = sc_EEAddr[1];          /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;           /* LC */
  scrio.tx_buf[i++] = sc_EELen[0];           /* data */
  scrio.tx_buf[i++] = sc_EELen[1];
  scrio.tx_buf[i++] = scrio.tx_le;           /* LE */

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0x00,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  sc_EECRC[0] = scrio.rx_buf[0];
  sc_EECRC[1] = scrio.rx_buf[1];

  return 0;

} /* sccmd_BCEEPromCRC */


int sccmd_BCWriteEEProm(struct scr_ctx *scrctx, uint8_t *sc_EEAddr,
  uint8_t *sc_EELen, uint8_t *sc_EEData)
{
  struct scr_io scrio;
  int i, j, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = sc_EELen[0];
  scrio.tx_le = 0;
  scrio.tx_delay = SC_BCWRITEEEPROM_DELAY;
  scrio.rx_buf_len = 0;
  i = 0;

  scrio.tx_buf[i++] = SC_BCWRITEEEPROM_CLA;  /* CLA */
  scrio.tx_buf[i++] = SC_BCWRITEEEPROM_INS;  /* INS */
  scrio.tx_buf[i++] = sc_EEAddr[0];          /* P1 */
  scrio.tx_buf[i++] = sc_EEAddr[1];          /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;           /* LC */

  for (j = 0; j < sc_EELen[0]; ++j)          /* EEProm bytes */
    scrio.tx_buf[i++] = sc_EEData[j];

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0x00,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_BCWriteEEProm */


int sccmd_BCClearEEProm(struct scr_ctx *scrctx, uint8_t *sc_EEAddr,
  uint8_t *sc_EELen)
{
  struct scr_io scrio;
  int i, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = 2;
  scrio.tx_le = 0;
  scrio.tx_delay = SC_BCCLEAREEPROM_DELAY;
  scrio.rx_buf_len = 0;
  i = 0;

  scrio.tx_buf[i++] = SC_BCCLEAREEPROM_CLA;  /* CLA */
  scrio.tx_buf[i++] = SC_BCCLEAREEPROM_INS;  /* INS */
  scrio.tx_buf[i++] = sc_EEAddr[0];          /* P1 */
  scrio.tx_buf[i++] = sc_EEAddr[1];          /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;           /* LC */
  scrio.tx_buf[i++] = sc_EELen[0];
  scrio.tx_buf[i++] = sc_EELen[1];

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0x00,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_BCClearEEProm */

int sccmd_BCSetState(struct scr_ctx *scrctx, u_char sc_state)
{
  struct scr_io scrio;
  int i, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = 0;
  scrio.tx_le = 0;
  scrio.tx_delay = SC_BCSETSTATE_DELAY;
  scrio.rx_buf_len = 0;
  i = 0;

  /*
   * only supported for enhanced cards.  Newer will return
   * SW1=61 and SW2=n+1 where n is the length of the data
   * representing a version string.
   *
   */

  scrio.tx_buf[i++] = SC_BCSETSTATE_CLA;   /* CLA */
  scrio.tx_buf[i++] = SC_BCSETSTATE_INS;   /* INS */
  scrio.tx_buf[i++] = sc_state;            /* P1 */
  scrio.tx_buf[i++] = 0x0;                 /* P2 */

  /* ACR30S does not appear to work properly with LC and LE absent */
  if (scrctx->active_reader == SCR_READER_EMBEDDED_ACR30S) {
    scrio.tx_buf[i++] = scrio.tx_lc;         /* LC */
    scrio.tx_buf[i++] = scrio.tx_le;         /* LE */
  }

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0x00,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_BCSetState */


int sccmd_BCGetState(struct scr_ctx *scrctx, u_char *sc_state,
  u_char *sc_version, u_char *sc_version_len)
{
  struct scr_io scrio;
  int i, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = 0;
  scrio.tx_le = 3; /* not known before call, guess */
  scrio.tx_delay = SC_BCGETSTATE_DELAY;
  scrio.rx_buf_len = 3; /* not known before call, guess */
  i = 0;

  /*
   * only supported for enhanced cards.  Newer will return
   * SW1=61 and SW2=n+1 where n is the length of the data
   * representing a version string.
   *
   */

  scrio.tx_buf[i++] = SC_BCGETSTATE_CLA;   /* CLA */
  scrio.tx_buf[i++] = SC_BCGETSTATE_INS;   /* INS */
  scrio.tx_buf[i++] = 0x0;                 /* P1 */
  scrio.tx_buf[i++] = 0x0;                 /* P2 */
  scrio.tx_buf[i++] = scrio.tx_le;         /* LE */

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0x00,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  sc_state[0] = scrio.rx_buf[0];
  sc_version[0] = scrio.rx_buf[1];
  sc_version[1] = scrio.rx_buf[2];
  *sc_version_len = 2;

  return 0;

} /* sccmd_BCGetState */

int sccmd_BCEEPromSize(struct scr_ctx *scrctx, u_char *sc_start,
  u_char *sc_len)
{
  struct scr_io scrio;
  int i, j, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = 0;
  scrio.tx_le = 4;
  scrio.tx_delay = SC_BCEEPROMSIZE_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_BCEEPROMSIZE_CLA; /* CLA */
  scrio.tx_buf[i++] = SC_BCEEPROMSIZE_INS; /* INS */
  scrio.tx_buf[i++] = 0x0;                 /* P1 */
  scrio.tx_buf[i++] = 0x0;                 /* P2 */
  scrio.tx_buf[i++] = scrio.tx_le;         /* LE */

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  j = 0;
  sc_start[0] = scrio.rx_buf[j++];
  sc_start[1] = scrio.rx_buf[j++];
  sc_len[0] = scrio.rx_buf[j++];
  sc_len[1] = scrio.rx_buf[j++];

  return 0;

} /* sccmd_BCEEPromSize */

int sccmd_SetHost(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  u_char *sc_count, char *sc_hostname, u_char *sc_hotpkey)
{
  struct scr_io scrio;
  int i, r, j;

  scrio.tx_lc = SC_INDEX_LEN+SC_COUNT_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_COUNT_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN;
  scrio.tx_delay = SC_SETHOST_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_SETHOST_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_SETHOST_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_SETHOST_INS;    /* INS */
  scrio.tx_buf[i++] = 0x0;                 /* P1 */
  scrio.tx_buf[i++] = 0x0;                 /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;         /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_COUNT_LEN; ++j)
    scrio.tx_buf[i++] = sc_count[j];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    scrio.tx_buf[i++] = sc_hostname[j];
  for (j = 0; j < SC_HOTPKEY_LEN; ++j)
    scrio.tx_buf[i++] = sc_hotpkey[j];
  scrio.tx_buf[i++] = scrio.tx_le;         /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }
 
  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    sc_idx[j] = scrio.rx_buf[j];
  for (j = 0; j < SC_COUNT_LEN; ++j)
    sc_count[j] = scrio.rx_buf[j+SC_INDEX_LEN];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    sc_hostname[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_COUNT_LEN];
  for (j = 0; j < SC_HOTPKEY_LEN; ++j)
    sc_hotpkey[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_COUNT_LEN+SC_HOSTNAME_LEN];

  return 0;

} /* sccmd_SetHost */

int sccmd_GetHost(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  u_char *sc_count, char *sc_hostname, u_char *sc_hotpkey)
{
  struct scr_io scrio;
  int i, r, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_INDEX_LEN+SC_COUNT_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_COUNT_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN;
  scrio.tx_delay = SC_GETHOST_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETHOST_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_GETHOST_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_GETHOST_INS;   /* INS */
  scrio.tx_buf[i++] = 0x0;                /* P1 */
  scrio.tx_buf[i++] = 0x0;                /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;        /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_COUNT_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN; ++j)
    scrio.tx_buf[i++] = 0;
  scrio.tx_buf[i++] = scrio.tx_le;        /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    sc_idx[j] = scrio.rx_buf[j];
  for (j = 0; j < SC_COUNT_LEN; ++j)
    sc_count[j] = scrio.rx_buf[j+SC_INDEX_LEN];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    sc_hostname[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_COUNT_LEN];
  for (j = 0; j < SC_HOTPKEY_LEN; ++j)
    sc_hotpkey[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_COUNT_LEN+SC_HOSTNAME_LEN];

  return 0;

} /* sccmd_GetHost */

int sccmd_GetHostName(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  char *sc_PIN, char *sc_hostname)
{
  struct scr_io scrio;
  int i, r, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_INDEX_LEN+SC_PIN_LEN+SC_HOSTNAME_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_PIN_LEN+SC_HOSTNAME_LEN;
  scrio.tx_delay = SC_GETHOSTNAME_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETHOSTNAME_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_GETHOSTNAME_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_GETHOSTNAME_INS;    /* INS */
  scrio.tx_buf[i++] = 0x0;                     /* P1 */
  scrio.tx_buf[i++] = 0x0;                     /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;             /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_PIN[j];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    scrio.tx_buf[i++] = 0;
  scrio.tx_buf[i++] = scrio.tx_le;             /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    sc_idx[j] = scrio.rx_buf[j];
  for (j = 0; j < SC_PIN_LEN; ++j)
    sc_PIN[j] = scrio.rx_buf[j+SC_INDEX_LEN];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    sc_hostname[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_PIN_LEN];

  return 0;

} /* sccmd_GetHostName */

int sccmd_GetHOTP(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  char *sc_PIN, u_char *sc_hotp)
{
  struct scr_io scrio;
  int r, i, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_INDEX_LEN+SC_PIN_LEN+SC_HOTP_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_PIN_LEN+SC_HOTP_LEN;
  scrio.tx_delay = SC_GETHOTP_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETHOTP_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_GETHOTP_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_GETHOTP_INS;   /* INS */
  scrio.tx_buf[i++] = 0x0;                /* P1 */
  scrio.tx_buf[i++] = 0x0;                /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;        /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_PIN[j];
  for (j = 0; j < SC_HOTP_LEN; ++j)
    scrio.tx_buf[i++] = sc_hotp[j];
  scrio.tx_buf[i++] = scrio.tx_le;        /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_HOTP_LEN; ++j) {
    sc_hotp[j] = scrio.rx_buf[SC_INDEX_LEN+SC_PIN_LEN+j];
  }

  return 0;

} /* sccmd_GetHOTP */

int sccmd_SetAdminMode(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_adminmode, u_char *sc_adminkey)
{
  struct scr_io scrio;
  int i, r, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_ADMINMODE_LEN+SC_ADMINKEY_LEN;
  scrio.tx_le = SC_ADMINMODE_LEN+SC_ADMINKEY_LEN;
  scrio.tx_delay = SC_SETADMINMODE_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_SETADMINMODE_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_SETADMINMODE_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_SETADMINMODE_INS;    /* INS */
  scrio.tx_buf[i++] = 0x0;                      /* P1 */
  scrio.tx_buf[i++] = 0x0;                      /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;              /* LC */
  for (j = 0; j < SC_ADMINMODE_LEN; ++j)
    scrio.tx_buf[i++] = sc_adminmode[j];
  for (j = 0; j < SC_ADMINKEY_LEN; ++j)
    scrio.tx_buf[i++] = sc_adminkey[j];
  scrio.tx_buf[i++] = scrio.tx_le;              /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_SetAdminMode */

int sccmd_SetBalanceCardIndex(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_idx)
{
  struct scr_io scrio;
  int r, i, j;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_INDEX_LEN;
  scrio.tx_le = SC_INDEX_LEN;
  scrio.tx_delay = SC_SETBALANCECARDINDEX_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_SETBALANCECARDINDEX_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_SETBALANCECARDINDEX_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_SETBALANCECARDINDEX_INS;    /* INS */
  scrio.tx_buf[i++] = 0x0;                             /* P1 */
  scrio.tx_buf[i++] = 0x0;                             /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;                     /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  scrio.tx_buf[i++] = scrio.tx_lc;                     /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }
 
  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_SetBalanceCardIndex */

int sccmd_SetPIN(struct scr_ctx *scrctx, u_char fv, char *sc_PIN,
  char *sc_newPIN)
{
  struct scr_io scrio;
  int r, i, j;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_PIN_LEN+SC_PIN_LEN;
  scrio.tx_le = SC_PIN_LEN+SC_PIN_LEN;
  scrio.tx_delay = SC_SETPIN_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;
    
  scrio.tx_buf[i++] = SC_SETPIN_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_SETPIN_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_SETPIN_INS;    /* INS */
  scrio.tx_buf[i++] = 0x0;                /* P1 */
  scrio.tx_buf[i++] = 0x0;                /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;        /* LC */
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_PIN[j];
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_newPIN[j];
  scrio.tx_buf[i++] = scrio.tx_le;        /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }
 
  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_SetPIN */

int sccmd_TestPIN(struct scr_ctx *scrctx, u_char fv, char *sc_PIN)
{
  struct scr_io scrio;
  int i, j, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_PIN_LEN;
  scrio.tx_le = SC_PIN_LEN;
  scrio.tx_delay = SC_TESTPIN_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_TESTPIN_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_TESTPIN_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_TESTPIN_INS;    /* INS */
  scrio.tx_buf[i++] = 0x0;                 /* P1 */
  scrio.tx_buf[i++] = 0x0;                 /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;         /* LC */
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_PIN[j];
  scrio.tx_buf[i++] = scrio.tx_lc;         /* LE */
 
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }
 
  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0)
    return -1;

  return 0;
    
} /* sccmd_TestPIN */


int sccmd_GetVersion(struct scr_ctx *scrctx, u_char fv, u_char *sc_version)
{
  struct scr_io scrio;
  int i, j, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_VERSION_LEN;
  scrio.tx_le = SC_VERSION_LEN;
  scrio.tx_delay = SC_GETVERSION_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETVERSION_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_GETVERSION_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_GETVERSION_INS;    /* INS */
  scrio.tx_buf[i++] = 0x0;                    /* P1 */
  scrio.tx_buf[i++] = 0x0;                    /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;            /* LC */
  for (j = 0; j < SC_VERSION_LEN; ++j)
    scrio.tx_buf[i++] = 0;
  scrio.tx_buf[i++] = scrio.tx_le;            /* LE */

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_VERSION_LEN; ++j)
    sc_version[j] = scrio.rx_buf[j];

  return 0;

} /* sccmd_GetVersion */

int sccmd_SetAdminKey(struct scr_ctx *scrctx, u_char fv, u_char *sc_adminkey)
{
  struct scr_io scrio;
  int i, r, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_ADMINKEY_LEN;
  scrio.tx_le = SC_ADMINKEY_LEN;
  scrio.tx_delay = SC_SETADMINKEY_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_SETADMINKEY_CLA;      /* CLA */
  if (fv < 5)
    scrio.tx_buf[i++] = SC_SETADMINKEY_V1_INS; /* INS */
  else
    scrio.tx_buf[i++] = SC_SETADMINKEY_INS;    /* INS */
  scrio.tx_buf[i++] = 0x0;                     /* P1 */
  scrio.tx_buf[i++] = 0x0;                     /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;             /* LC */
  for (j = 0; j < SC_ADMINKEY_LEN; ++j)
    scrio.tx_buf[i++] = sc_adminkey[j];
  scrio.tx_buf[i++] = scrio.tx_lc;             /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_SetAdminKey */

int sccmd_SetHost32(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  u_char *sc_count32, char *sc_hostname, u_char *sc_hotpkey)
{
  struct scr_io scrio;
  int i, r, j;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_INDEX_LEN+SC_COUNT32_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_COUNT32_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN;
  scrio.tx_delay = SC_SETHOST32_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_SETHOST32_CLA; /* CLA */
  scrio.tx_buf[i++] = SC_SETHOST32_INS; /* INS */
  scrio.tx_buf[i++] = 0x0;              /* P1 */
  scrio.tx_buf[i++] = 0x0;              /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;      /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_COUNT32_LEN; ++j)
    scrio.tx_buf[i++] = sc_count32[j];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    scrio.tx_buf[i++] = sc_hostname[j];
  for (j = 0; j < SC_HOTPKEY_LEN; ++j)
    scrio.tx_buf[i++] = sc_hotpkey[j];
  scrio.tx_buf[i++] = scrio.tx_le;      /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }
 
  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    sc_idx[j] = scrio.rx_buf[j];
  for (j = 0; j < SC_COUNT32_LEN; ++j)
    sc_count32[j] = scrio.rx_buf[j+SC_INDEX_LEN];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    sc_hostname[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_COUNT32_LEN];
  for (j = 0; j < SC_HOTPKEY_LEN; ++j)
    sc_hotpkey[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_COUNT32_LEN+\
     SC_HOSTNAME_LEN];

  return 0;

} /* sccmd_SetHost32 */

int sccmd_GetHost32(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  u_char *sc_count32, char *sc_hostname, u_char *sc_hotpkey)
{
  struct scr_io scrio;
  int i, r, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_INDEX_LEN+SC_COUNT32_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_COUNT32_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN;
  scrio.tx_delay = SC_GETHOST32_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETHOST32_CLA; /* CLA */
  scrio.tx_buf[i++] = SC_GETHOST32_INS; /* INS */
  scrio.tx_buf[i++] = 0x0;              /* P1 */
  scrio.tx_buf[i++] = 0x0;              /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;      /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_COUNT32_LEN+SC_HOSTNAME_LEN+SC_HOTPKEY_LEN; ++j)
    scrio.tx_buf[i++] = 0;
  scrio.tx_buf[i++] = scrio.tx_le;      /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    sc_idx[j] = scrio.rx_buf[j];
  for (j = 0; j < SC_COUNT32_LEN; ++j)
    sc_count32[j] = scrio.rx_buf[j+SC_INDEX_LEN];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    sc_hostname[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_COUNT32_LEN];
  for (j = 0; j < SC_HOTPKEY_LEN; ++j)
    sc_hotpkey[j] = scrio.rx_buf[j+SC_INDEX_LEN+SC_COUNT32_LEN+\
     SC_HOSTNAME_LEN];

  return 0;

} /* sccmd_GetHost32 */

int sccmd_GetHOTPCount32(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  char *sc_PIN, u_char *sc_count32, u_char *sc_hotp)
{
  struct scr_io scrio;
  int r, i, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_INDEX_LEN+SC_PIN_LEN+SC_COUNT32_LEN+SC_HOTP_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_PIN_LEN+SC_COUNT32_LEN+SC_HOTP_LEN;
  scrio.tx_delay = SC_GETHOTPCOUNT32_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETHOTPCOUNT32_CLA;  /* CLA */
  scrio.tx_buf[i++] = SC_GETHOTPCOUNT32_INS;  /* INS */
  scrio.tx_buf[i++] = 0x0;                    /* P1 */
  scrio.tx_buf[i++] = 0x0;                    /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;            /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_PIN[j];
  for (j = 0; j < SC_COUNT32_LEN; ++j)
    scrio.tx_buf[i++] = sc_count32[j];
  for (j = 0; j < SC_HOTP_LEN; ++j)
    scrio.tx_buf[i++] = sc_hotp[j];
  scrio.tx_buf[i++] = scrio.tx_le;           /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_COUNT32_LEN; ++j) {
    sc_count32[j] =  scrio.rx_buf[SC_INDEX_LEN+SC_PIN_LEN+j];
  }

  /* copy out SC response */
  for (j = 0; j < SC_HOTP_LEN; ++j) {
    sc_hotp[j] =  scrio.rx_buf[SC_INDEX_LEN+SC_PIN_LEN+SC_COUNT32_LEN+j];
  }

  return 0;

} /* sccmd_GetHOTPCount32 */

int sccmd_GetHOTPHost(struct scr_ctx *scrctx, u_char fv, u_char *sc_idx,
  char *sc_PIN, u_char *sc_hotp, char *sc_hostname)
{
  struct scr_io scrio;
  int r, i, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_INDEX_LEN+SC_PIN_LEN+SC_HOTP_LEN+SC_HOSTNAME_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_PIN_LEN+SC_HOTP_LEN+SC_HOSTNAME_LEN;
  scrio.tx_delay = SC_GETHOTPHOST_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETHOTPHOST_CLA;   /* CLA */
  scrio.tx_buf[i++] = SC_GETHOTPHOST_INS;   /* INS */
  scrio.tx_buf[i++] = 0x0;                  /* P1 */
  scrio.tx_buf[i++] = 0x0;                  /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;          /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_PIN[j];
  for (j = 0; j < SC_HOTP_LEN; ++j)
    scrio.tx_buf[i++] = sc_hotp[j];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    scrio.tx_buf[i++] = 0;
  scrio.tx_buf[i++] = scrio.tx_le;          /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0)
    return -1;

  /* copy out SC response */
  for (j = 0; j < SC_HOTP_LEN; ++j) {
    sc_hotp[j] = scrio.rx_buf[SC_INDEX_LEN+SC_PIN_LEN+j];
  }

  /* copy out SC response */
  for (j = 0; j < SC_HOSTNAME_LEN; ++j) {
    sc_hostname[j] = scrio.rx_buf[SC_INDEX_LEN+SC_PIN_LEN+SC_HOTP_LEN+j];
  }

  return 0;

} /* sccmd_GetHOTPHost */

int sccmd_GetHOTPHostCount32(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_idx, char *sc_PIN, u_char *sc_count32, u_char *sc_hotp,
  char *sc_hostname)
{
  struct scr_io scrio;
  int r, i, j;

  bzero(&scrio, sizeof scrio);
 
  scrio.tx_lc = SC_INDEX_LEN+SC_PIN_LEN+SC_COUNT32_LEN+SC_HOTP_LEN+\
    SC_HOSTNAME_LEN;
  scrio.tx_le = SC_INDEX_LEN+SC_PIN_LEN+SC_COUNT32_LEN+SC_HOTP_LEN+\
    SC_HOSTNAME_LEN;
  scrio.tx_delay = SC_GETHOTPHOSTCOUNT32_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETHOTPHOSTCOUNT32_CLA;  /* CLA */
  scrio.tx_buf[i++] = SC_GETHOTPHOSTCOUNT32_INS;  /* INS */
  scrio.tx_buf[i++] = 0x0;                        /* P1 */
  scrio.tx_buf[i++] = 0x0;                        /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;                /* LC */
  for (j = 0; j < SC_INDEX_LEN; ++j)
    scrio.tx_buf[i++] = sc_idx[j];
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_PIN[j];
  for (j = 0; j < SC_COUNT32_LEN; ++j)
    scrio.tx_buf[i++] = sc_count32[j];
  for (j = 0; j < SC_HOTP_LEN; ++j)
    scrio.tx_buf[i++] = sc_hotp[j];
  for (j = 0; j < SC_HOSTNAME_LEN; ++j)
    scrio.tx_buf[i++] = 0;
  scrio.tx_buf[i++] = scrio.tx_le;                /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_COUNT32_LEN; ++j) {
    sc_count32[j] = scrio.rx_buf[SC_INDEX_LEN+SC_PIN_LEN+j];
  }

  /* copy out SC response */
  for (j = 0; j < SC_HOTP_LEN; ++j) {
    sc_hotp[j] = scrio.rx_buf[SC_INDEX_LEN+SC_PIN_LEN+SC_COUNT32_LEN+j];
  }

  /* copy out SC response */
  for (j = 0; j < SC_HOSTNAME_LEN; ++j) {
    sc_hostname[j] = scrio.rx_buf[SC_INDEX_LEN+SC_PIN_LEN+SC_COUNT32_LEN+\
      SC_HOTP_LEN+j];
  }

  return 0;
  
} /* sccmd_GetHOTPHostCount32 */



int sccmd_ClearAll(struct scr_ctx *scrctx, u_char fv)
{
  struct scr_io scrio;
  int i, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = 0;
  scrio.tx_le = 0;
  scrio.tx_delay = SC_CLEARALL_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_CLEARALL_CLA;   /* CLA */
  scrio.tx_buf[i++] = SC_CLEARALL_INS;   /* INS */
  scrio.tx_buf[i++] = 0x0;               /* P1 */
  scrio.tx_buf[i++] = 0x0;               /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;       /* LC */
  scrio.tx_buf[i++] = scrio.tx_le;       /* LE */

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_ClearAll */

int sccmd_GetCapabilities(struct scr_ctx *scrctx, u_char fv,
  u_char *sc_capabilities)
{
  struct scr_io scrio;
  int i, j, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_CAPABILITIES_LEN;
  scrio.tx_le = SC_CAPABILITIES_LEN;
  scrio.tx_delay = SC_GETCAPABILITIES_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETCAPABILITIES_CLA;   /* CLA */
  scrio.tx_buf[i++] = SC_GETCAPABILITIES_INS;   /* INS */
  scrio.tx_buf[i++] = 0x0;                      /* P1 */
  scrio.tx_buf[i++] = 0x0;                      /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;              /* LC */
  for (j = 0; j < SC_CAPABILITIES_LEN; ++j)
    scrio.tx_buf[i++] = 0;
  scrio.tx_buf[i++] = scrio.tx_le;              /* LE */

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  for (j = 0; j < SC_CAPABILITIES_LEN; ++j)
    sc_capabilities[j] = scrio.rx_buf[j];

  return 0;

} /* sccmd_GetCapabilities */

int sccmd_SetSpyrusEEBlock(struct scr_ctx *scrctx, uint8_t *sc_idx,
  uint8_t *sc_blockData)
{
  struct scr_io scrio;
  int i, j, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_SPYRUSEEBLOCK_LEN+SC_SPYRUSEEIDX_LEN;
  scrio.tx_le = 0;
  scrio.tx_delay = SC_SETSPYRUSEEBLOCK_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_SETSPYRUSEEBLOCK_CLA;  /* CLA */
  scrio.tx_buf[i++] = SC_SETSPYRUSEEBLOCK_INS;  /* INS */
  scrio.tx_buf[i++] = 0x0;                      /* P1 */
  scrio.tx_buf[i++] = 0x0;                      /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;              /* LC */
  scrio.tx_buf[i++] = *sc_idx;                  /* data */
  for (j = 0; j < SC_SPYRUSEEBLOCK_LEN; ++j)
    scrio.tx_buf[i++] = sc_blockData[j];

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_SetSpyrusEEBlock */

int sccmd_GetSpyrusEEBlock(struct scr_ctx *scrctx, uint8_t *sc_idx,
  uint8_t *sc_blockData)
{
  struct scr_io scrio;
  int i, j, r;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_SPYRUSEEIDX_LEN;
  scrio.tx_le = SC_SPYRUSEEBLOCK_LEN+SC_SPYRUSEEIDX_LEN;
  scrio.tx_delay = SC_GETSPYRUSEEBLOCK_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;

  scrio.tx_buf[i++] = SC_GETSPYRUSEEBLOCK_CLA;  /* CLA */
  scrio.tx_buf[i++] = SC_GETSPYRUSEEBLOCK_INS;  /* INS */
  scrio.tx_buf[i++] = 0x0;                      /* P1 */
  scrio.tx_buf[i++] = 0x0;                      /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;              /* LC */
  scrio.tx_buf[i++] = *sc_idx;                  /* data */
  scrio.tx_buf[i++] = scrio.tx_le;              /* LE */

  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }

  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  /* copy out SC response */
  *sc_idx = scrio.rx_buf[0];
  for (j = 0; j < SC_SPYRUSEEBLOCK_LEN; ++j)
    sc_blockData[j] = scrio.rx_buf[j+SC_SPYRUSEEIDX_LEN];

  return 0;

} /* sccmd_GetSpyrusEEBlock */

int sccmd_SetReaderKey(struct scr_ctx *scrctx, uint8_t *sc_readerKey)
{
  struct scr_io scrio;
  int r, i, j;

  bzero(&scrio, sizeof scrio);

  scrio.tx_lc = SC_READERKEY_LEN;
  scrio.tx_le = 0;
  scrio.tx_delay = SC_SETREADERKEY_DELAY;
  scrio.rx_buf_len = scrio.tx_le;
  i = 0;
    
  scrio.tx_buf[i++] = SC_SETREADERKEY_CLA; /* CLA */
  scrio.tx_buf[i++] = SC_SETREADERKEY_INS; /* INS */
  scrio.tx_buf[i++] = 0x0;                 /* P1 */
  scrio.tx_buf[i++] = 0x0;                 /* P2 */
  scrio.tx_buf[i++] = scrio.tx_lc;         /* LC */
  for (j = 0; j < SC_PIN_LEN; ++j)
    scrio.tx_buf[i++] = sc_readerKey[j];
  scrio.tx_buf[i++] = scrio.tx_le;         /* LE */
    
  scrio.tx_buf_len = i;

  /* SC transaction */
  if (scr_ctx_cmd(scrctx, &scrio) < 0) {
    if (scrctx->verbose)
      xerr_warnx("sc_ctx_cmd(): failed.");
    return -1;
  }
 
  /* check response code and size */
  if ((r = scr_checksw1sw2_rx(&scrio, scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF,
    scrctx->verbose)) != 0) {
    return -1;
  }

  return 0;

} /* sccmd_SetReaderKey */

