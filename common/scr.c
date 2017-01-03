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
 *      $Id: scr.c 29 2009-11-30 01:11:17Z maf $
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "scr.h"
#include "xerr.h"

#ifdef SCR_PCSC
#include <wintypes.h>
#include <winscard.h>
#endif /* SCR_PCSC */

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

/*
 *
 * High level abstraction for Smart Card communications.  Supports
 * embedded ACR30 driver and PC/SC combatible readers with PCSC-Lite
 *
 * scr_ctx_new()        - create context / allocate resources
 * scr_ctx_free()       - free context / deallocate resources
 * scr_ctx_valid()      - context valid check
 * scr_ctx_connect()    - connect to SC reader
 * scr_ctx_reset()      - reset SC
 * scr_ctx_cmd()        - issue command to SC
 * scr_checksw1sw2_rx() - chek SW1SW2 bytes from SC command response
 *
 */

/*
 * function: scr_ctx_new()
 *
 * Allocate scr context.
 *
 * arguments:
 *
 *  valid_readers - SCR_READER_* bitmap to enable reader classes.
 *                  support EMBEDDED_ACR30S and PCSC
 *  verbose       - enable verbose output
 *
 * returns: scr_ctx or 0L on failure
 *
 */
struct scr_ctx* scr_ctx_new(int valid_readers, int verbose)
{
  struct scr_ctx *scrctx;
  size_t ralloc;
  int r, ret, cur_reader;
  char *buf;
#ifdef SCR_PCSC
  char *pcsc_rdr_buf, *p;
  DWORD pcsc_rdr_buf_len;
  int pcsc_rdr_count;
#endif /* SCR_PCSC */

  ret = -1; /* fail */
  ralloc = 0;
#ifdef SCR_PCSC
  pcsc_rdr_buf = (char*)0L;
#endif /* SCR_PCSC */

  if (!(scrctx = (struct scr_ctx*)malloc(sizeof *scrctx))) {
    if (verbose)
      xerr_warn("malloc(scrctx)");
    goto scr_ctx_new_out;
  }

  bzero(scrctx, sizeof *scrctx);
  scrctx->verbose = verbose;

  if (valid_readers & SCR_READER_EMBEDDED_ACR30S) {

    ++ scrctx->num_readers;

    ralloc += strlen(SCR_EMBEDDED_ACR30S_NAME)+1;

  }

#ifdef SCR_PCSC

  if (valid_readers & SCR_READER_PCSC) {

    if ((r = SCardEstablishContext(SCARD_SCOPE_SYSTEM, (void*)0L, (void*)0L,
        &scrctx->hContext)) != SCARD_S_SUCCESS) {
      if (scrctx->verbose)
        xerr_warnx("SCardEstablishContext(): %s.", pcsc_stringify_error(r));
    }

    pcsc_rdr_buf = (char*)0L;

    /*
     * SCARD_AUTOALLOCATE not portable.  Do this in two steps
     * and live with the race condition.  first get # readers
     */
    if ((r = SCardListReaders(scrctx->hContext, (void*)0L, (void*)0L,
        &pcsc_rdr_buf_len)) != SCARD_S_SUCCESS) {
      if (scrctx->verbose)
        xerr_warnx("SCCardListReaders(): %s.", pcsc_stringify_error(r));
      goto scr_ctx_new_out;
    } 

    if (!(pcsc_rdr_buf = malloc(pcsc_rdr_buf_len))) {
      if (scrctx->verbose)
        xerr_warnx("malloc(pcsc_rdr_buf): failed.");
      goto scr_ctx_new_out;
    }
    
    if ((r = SCardListReaders(scrctx->hContext, (void*)0L, pcsc_rdr_buf,
        &pcsc_rdr_buf_len)) != SCARD_S_SUCCESS) {
      if (scrctx->verbose)
        xerr_warnx("SCCardListReaders(): %s", pcsc_stringify_error(ret));
      goto scr_ctx_new_out;
    }

    /* run through PSCS reader names to get count */
    for (p = pcsc_rdr_buf, pcsc_rdr_count = 0;*p;++pcsc_rdr_count)
      p += strlen(p);

    /* first PCSC reader in the list */
    if (pcsc_rdr_count)
      scrctx->pcsc_reader_first = scrctx->num_readers;

    /* add PCSC readers to total available via scr */
    scrctx->num_readers += pcsc_rdr_count;

    /* resrve space for reader name + "PCSC:" */
    ralloc += pcsc_rdr_buf_len + (pcsc_rdr_count * 5);

  } /* SCR_READER_PCSC */

#endif /* SCR_PCSC */

  /* foreach reader allocate char */
  ralloc += (scrctx->num_readers) * sizeof (char*);

  if (!(scrctx->readers = (char**)malloc(ralloc))) {
    if (scrctx->verbose)
      xerr_warn("malloc(scrctx->readers)");
    goto scr_ctx_new_out;
  }

  /* start storing strings after pointers */
  buf = (char*)scrctx->readers + (sizeof (char*))*scrctx->num_readers;
  cur_reader = 0;

  if (valid_readers & SCR_READER_EMBEDDED_ACR30S) {
    scrctx->readers[cur_reader++] = buf;
    strcpy(buf, SCR_EMBEDDED_ACR30S_NAME);
    buf += strlen(SCR_EMBEDDED_ACR30S_NAME) + 1;
  } /* SCR_READER_PCSC */

#ifdef SCR_PCSC

  if (valid_readers & SCR_READER_PCSC) {

    p = pcsc_rdr_buf;
    while (*p) {
      scrctx->readers[cur_reader++] = buf;
      bcopy("PCSC:", buf, 5);
      buf += 5;
      strcpy(buf, p);
      buf += strlen(p)+1;
      p += strlen(p)+1;
    }

  } /* SCR_READER_PCSC */

#endif /* SCR_PCSC */

  scrctx->valid = 1;
  scrctx->valid_readers = valid_readers;

  ret = 0; /* success */

scr_ctx_new_out:

#ifdef SCR_PCSC
  if (pcsc_rdr_buf)
    free(pcsc_rdr_buf);
#endif /* SCR_PSCS */

  if (ret == -1) {

    if (scrctx && scrctx->readers)
      free(scrctx->readers);

    if (scrctx)
      free(scrctx);

    scrctx = (struct scr_ctx*)0L;

  }

  return scrctx;

} /* scr_ctx_new */

/*
 * function: scr_ctx_new()
 *
 * Test context is valid
 *
 * arguments:
 *
 *  scrctx        - scr context context allocated by scr_ctx_new()
 *  who           - id representing caller.
 *
 * returns: 0  success, context is valid
 *          <0 failure
 *
 */
int scr_ctx_valid(struct scr_ctx *scrctx, char *who)
{

  if (!scrctx) {
    xerr_warnx("%s(): fatal, no context.", who);
    return -1;
  }

  if (!scrctx->valid) {
    if (scrctx->verbose)
      xerr_warnx("%s(): fatal, invalid context.", who);
    return -1;
  }

  return 0;

} /* scr_ctx_valid */

/*
 * function: scr_ctx_free()
 *
 * Free context, deallocate resources, disconnect from reader, etc.
 *
 * arguments:
 *
 *  scrctx        - scr context context allocated by scr_ctx_new()
 *
 * returns: 0  success
 *          <0 failure
 *
 */
void scr_ctx_free(struct scr_ctx *scrctx)
{
  int r;
  scr_ctx_valid(scrctx, (char*)__FUNCTION__);

  if (scrctx->active_reader == SCR_READER_EMBEDDED_ACR30S)
    acr30_close(scrctx->acr30ctx);

  if (scrctx && scrctx->readers)
    free(scrctx->readers);

#ifdef SCR_PCSC

  if (scrctx->active_reader == SCR_READER_PCSC) {
    if ((r = SCardDisconnect(scrctx->hCard, SCARD_LEAVE_CARD))
       != SCARD_S_SUCCESS)
      xerr_warnx("SCardDisconnect(): %s.", pcsc_stringify_error(r));
  }

  if (scrctx->hContext) {
    if ((r = SCardReleaseContext(scrctx->hContext)) != SCARD_S_SUCCESS)
      xerr_warnx("SCardReleaseContext(): %s.", pcsc_stringify_error(r));
  }

#endif /* SCR_PCSC */

  if (scrctx->reader)
    free(scrctx->reader);

  if (scrctx)
    free(scrctx);


} /* scr_ctx_free() */

/*
 * function: scr_ctx_connect()
 *
 * Connect to reader.
 *
 * arguments:
 *
 *  scrctx        - scr context context allocated by scr_ctx_new()
 *  reader        - reader string.
 *
 * reader string is of the form
 *   PCSC:<pcsc reader name>
 *   embedded:acr30s:<serial_device>
 *
 * The reader name and serial device are optional.  PCSC will default
 * to the first reader, embedded:acr30s will default to 
 * SCR_EMBEDDED_ACR30S_DEVICE
 *
 * returns: 0  success, connected to reader
 *          <0 failure
 *
 */
int scr_ctx_connect(struct scr_ctx *scrctx, char *reader)
{
  int r, ret;
  char *serialio, n;

  ret = -1; /* fail */

  if (scr_ctx_valid(scrctx, (char*)__FUNCTION__) == -1)
    goto scr_ctx_connect_out;

  n = strlen(reader);

  if (!(scrctx->reader = (char*)malloc(n+1))) {
    if (scrctx->verbose)
      xerr_warn("malloc(reader)");
    goto scr_ctx_connect_out;
  }

  strcpy(scrctx->reader, reader);

  if (scrctx->valid_readers & SCR_READER_EMBEDDED_ACR30S) {

    n = strlen(SCR_EMBEDDED_ACR30S_NAME);

    if (!strncmp(reader, SCR_EMBEDDED_ACR30S_NAME, n)) {

      serialio = reader + n;

      /* parse out device name, or use default */
      if ((!*serialio) || ((*serialio == ':') && (!*(serialio+1))))
        serialio = SCR_EMBEDDED_ACR30S_DEVICE;
      else
        serialio += 1;

      if (!(scrctx->acr30ctx = acr30_open(serialio, scrctx->verbose))) {
        xerr_warnx("acr30_open(%s): failed", serialio);
        goto scr_ctx_connect_out;
      }

      scrctx->active_reader = SCR_READER_EMBEDDED_ACR30S;

    }

  } /* SCR_READER_EMBEDDED_ACR30 */

#ifdef SCR_PCSC 

  if (scrctx->valid_readers & SCR_READER_PCSC) {

    if (!strncmp(scrctx->reader, "PCSC:", 5)) {

      /* skip PCSC: */
      scrctx->pcsc_active_reader = scrctx->reader + 5;

      /* PCSC: alone defaults to first PCSC reader */
      if (!*scrctx->pcsc_active_reader)
        scrctx->pcsc_active_reader =\
          scrctx->readers[scrctx->pcsc_reader_first]+5;

      if ((r = SCardConnect(scrctx->hContext, scrctx->pcsc_active_reader,
          SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T1, &scrctx->hCard,
          &scrctx->dwActiveProtocol)) != SCARD_S_SUCCESS) {
        if (scrctx->verbose)
          xerr_warnx("ScardConnect(): %s.", pcsc_stringify_error(r));
        goto scr_ctx_connect_out;
      }

      if (scrctx->dwActiveProtocol != SCARD_PROTOCOL_T1) {
        if (scrctx->verbose)
          xerr_warnx("dwActiveProtocol=0x%2.2x SCARD_PROTOCOL_T1=0x%2.2x",
            (int)scrctx->dwActiveProtocol, SCARD_PROTOCOL_T1);
        goto scr_ctx_connect_out;
      }

      scrctx->active_reader = SCR_READER_PCSC;

    }

  } /* SCR_READER_PCSC */

#endif /* SCR_PCSC */

  if (!scrctx->active_reader) {
    xerr_warnx("No active reader.");
    goto scr_ctx_connect_out;
  }

  ret = 0; /* success */

scr_ctx_connect_out:

  return ret;

} /* scr_ctx_connect */

/*
 * function: scr_ctx_reset()
 *
 * Perform reset function on SC.  For PCSC this is no more than a
 * disconnect followed by connect.  The embedded ACR30S driver 
 * will issue a reset command to the SC and wait for a success reply.
 *
 * arguments:
 *
 *  scrctx        - scr context context allocated by scr_ctx_new()
 *
 * returns: 0  success, SC reset.
 *          <0 failure
 *
 */
int scr_ctx_reset(struct scr_ctx *scrctx)
{
  int ret, r;

  ret = -1; /* fail */

  if (scrctx->active_reader == SCR_READER_EMBEDDED_ACR30S) {

    if (acr30_reset(scrctx->acr30ctx) < 0) {
      xerr_warnx("acr30_reset(): failed.");
      goto scr_ctx_reset_out;
    }

    ret = 0; /* success */

  }

#ifdef SCR_PCSC

  if (scrctx->active_reader == SCR_READER_PCSC) {

    if ((r = SCardDisconnect(scrctx->hCard, SCARD_RESET_CARD))
       != SCARD_S_SUCCESS) {
      xerr_warnx("SCardDisconnect(): %s.", pcsc_stringify_error(r));
      goto scr_ctx_reset_out;
    }

    if ((r = SCardConnect(scrctx->hContext, scrctx->pcsc_active_reader,
        SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T1, &scrctx->hCard,
        &scrctx->dwActiveProtocol)) != SCARD_S_SUCCESS) {
      if (scrctx->verbose)
        xerr_warnx("ScardConnect(): %s.", pcsc_stringify_error(r));
      goto scr_ctx_reset_out;
    }

    if (scrctx->dwActiveProtocol != SCARD_PROTOCOL_T1) {
      if (scrctx->verbose)
        xerr_warnx("dwActiveProtocol=0x%2.2x SCARD_PROTOCOL_T1=0x%2.2x",
          (int)scrctx->dwActiveProtocol, SCARD_PROTOCOL_T1);
      goto scr_ctx_reset_out;
    }

    ret = 0; /* success */

  }

#endif /* SCR_PCSC */

scr_ctx_reset_out:

  return ret;

} /* scr_ctx_reset */

/*
 * function: scr_ctx_cmd()
 *
 * Send a command to the SC.  Decode the reply.
 *
 * arguments:
 *
 *  scrctx        - scr context context allocated by scr_ctx_new()
 *  scrio         - SCR I/O structure.
 *
 * scrio example:
 *
 *   bzero(&scrio, sizeof scrio);
 *   i = 0;
 *
 *   scrio.tx_lc =       LC
 *   scrio.tx_le =       LE
 *   scrio.tx_delay =    DELAY_AFTER_CMD
 *   scrio.rx_buf_len =  RECEIVE BUFFER LEN (usually LE)
 *
 *   scrio.tx_buf[i++] = CLA
 *   scrio.tx_buf[i++] = INS
 *   scrio.tx_buf[i++] = P1
 *   scrio.tx_buf[i++] = P2
 *   scrio.tx_buf[i++] = LC
 *   scrio.tx_buf[i++] = <data>
 *   scrio.tx_buf[i++] = LE
 *
 * issue command:
 *
 *  scr_ctx_cmd(scrctx, &scrio)
 *
 * check reply for normal SW1=90, SW2=00
 *
 *  scr_checksw1sw2_rx(&scrio,  scrio.tx_le, 0x90, 0x00, 0xFF, 0xFF, 1);
 *
 * copy out response (if necessary)
 *
 * for (j = 0; j < REPLY_DATA_LEN; ++j)
 *   mybuf[j] = scrio.rx_buf[j]
 *
 * returns: 0  success, command completed.
 *          <0 failure
 *
 */
int scr_ctx_cmd(struct scr_ctx *scrctx, struct scr_io *scrio)
{
  int ret;
#ifdef SCR_PCSC
  DWORD dwSendLength;
  DWORD dwRecvLength;
#endif /* SCR_PCSC */

  ret = -1; /* fail */

  if (scrctx->active_reader == SCR_READER_EMBEDDED_ACR30S) {

    bzero(&scrctx->acr30ctx->tx, sizeof (scrctx->acr30ctx->tx));

    scrctx->acr30ctx->tx.header = ACR30_HEADER_START;
    scrctx->acr30ctx->tx.instruction = ACR30_CMD_MCU;
    bcopy(&scrio->tx_buf, &scrctx->acr30ctx->tx.data, scrio->tx_buf_len);
    scrctx->acr30ctx->tx.data_len = scrio->tx_buf_len;

    if (acr30_transaction(scrctx->acr30ctx, scrio->tx_delay, 0x90, 0x00,
      scrio->tx_le) < 0) {
      if (scrctx->verbose)
        xerr_warnx("acr30_transaction(): failed.");
      goto scr_ctx_cmd_out;
    }

    scrio->rx_buf_len = scrctx->acr30ctx->rx.data_len;
    bcopy(&scrctx->acr30ctx->rx.data, &scrio->rx_buf, scrio->rx_buf_len);
    scrio->rx_SW1 = scrctx->acr30ctx->rx.SW1;
    scrio->rx_SW2 = scrctx->acr30ctx->rx.SW2;

    ret = 0; /* success */

  } /* SCR_READER_EMBEDDED_ACR30S */

#ifdef SCR_PCSC
  if (scrctx->active_reader == SCR_READER_PCSC) {

    dwSendLength = scrio->tx_buf_len;
    dwRecvLength = scrio->rx_buf_len + 2; /* data + SW1 SW2 */

    if ((ret = SCardTransmit(scrctx->hCard, SCARD_PCI_T1,
      (BYTE*)&scrio->tx_buf, dwSendLength, 0L, (BYTE*)&scrio->rx_buf,
      &dwRecvLength)) != SCARD_S_SUCCESS) {
      if (scrctx->verbose)
        xerr_warnx("SCardTransmit(): %s.", pcsc_stringify_error(ret));
      goto scr_ctx_cmd_out;
    }

    scrio->rx_buf_len = dwRecvLength;

    ret = 0; /* success */

  } /* SCR_READER_PCSC */
#endif /* SCR_PCSC */

  ret = 0; /* success */

scr_ctx_cmd_out:

  return ret;

} /* scr_ctx_cmd */

/*
 * function: scr_checksw1sw2_rx()
 *
 * Check SW1 SW2 in scrio receive buffer.
 *
 * arguments:
 *
 *  scrio         - SCR I/O structure.
 *  dlen          - expected length of data.
 *  SW1           - expected value SW1
 *  SW2           - expected value SW2
 *  SW1_MASK      - mask bits for SW1.  Use 0xFF for exact match. 
 *  SW2_MASK      - mask bits for SW2.  Use 0xFF for exact match.
 *
 * returns: 0  success, SW1, SW2 matched expected values
 *          <0 failure
 *
 */
int scr_checksw1sw2_rx(struct scr_io *scrio, u_char dlen, u_char SW1,
  u_char SW2, u_char SW1_mask, u_char SW2_mask, int verbose)
{
  u_char cmd_SW1, cmd_SW2;

  if (scrio->rx_buf_len < 2) {
    if (verbose)
      xerr_warnx("scr_checksw1sw2_rx(): no data for SW1,SW2");
    return -1; /* fail */
  }

  cmd_SW1 = scrio->rx_buf[scrio->rx_buf_len-2];
  cmd_SW2 = scrio->rx_buf[scrio->rx_buf_len-1];

  if ((cmd_SW1 == 0x69) && (cmd_SW2 == 0xC2)) {
    xerr_warnx("Access Denied.");
    return 2; /* fail */
  }

  if ((cmd_SW1 == 0x66) && (cmd_SW2 == 0xC7)) {
    xerr_warnx("Card Locked.  Access Denied.");
    return 2; /* fail */
  }

  if (((cmd_SW1 & SW1_mask) != SW1) || ((cmd_SW2 & SW2_mask) != SW2)) {
    if (verbose)
      xerr_warnx(
        "response: SW1=%2.2X,SW2=%2.2X expecting: SW1=%2.2X/%2.2X, SW2=%2.2X/%2.2X",
        (int)cmd_SW1, (int)cmd_SW2, (int)SW1, (int)SW1_mask, (int)SW2,
          (int)SW2_mask);
    return 1; /* fail */
  }

  /* expected recponse length is SW1+SW2+data */
  if (scrio->rx_buf_len != dlen+2) {
    if (verbose)
      xerr_warnx("Expecting %d bytes in response, got %d.", (int)dlen+2,
        scrio->rx_buf_len);
    return -1; /* fail */
  }

  return 0; /* succes */

} /* scr_checksw1sw2_rx */

#ifdef SCR_EXAMPLE


#include <stdio.h>
#include "scr.h"
#include "otpsc.h"
#include "xerr.h"

main()
{
  struct scr_ctx *scrctx;
  char sc_hostname[SC_HOSTNAME_LEN+1];
  u_char sc_hotp[SC_HOTP_LEN+1], sc_idx[SC_INDEX_LEN+1];
  u_char sc_version[SC_VERSION_LEN+1], sc_adminkey[SC_ADMINKEY_LEN+1];
  u_char sc_count[SC_COUNT_LEN+1], sc_count32[SC_COUNT32_LEN+1];
  u_char sc_hotpkey[SC_HOTPKEY_LEN+1], sc_adminmode[SC_ADMINMODE_LEN+1];
  u_char sc_firmware, sc_count_len, tmp8u;
  char fmt_buf[1024];
  int i, j, k;

  xerr_setid("test");

  if (!(scrctx = scr_ctx_new(SCR_READER_EMBEDDED_ACR30S|SCR_READER_PCSC, 1))) {
    xerr_errx(1, "scr_ctx_new(): failed");
  }

  char *c = (char*)__FUNCTION__;
  scr_ctx_valid(scrctx, c);

  for (i = 0; i < scrctx->num_readers; ++i)
    printf("%d:%s\n", i, scrctx->readers[i]);

  if (scr_ctx_connect(scrctx, "embedded:acr30s") < 0) {
    xerr_errx(1, "scr_ctx_connect(): failed");
  }

/*
  if (scr_ctx_connect(scrctx, "PCSC:OmniKey CardMan 1021 00 00") < 0) {
    xerr_errx(1, "scr_ctx_connect(): failed");
  }
*/

/*
  if (scr_ctx_connect(scrctx, "PCSC:") < 0) {
    xerr_errx(1, "scr_ctx_connect(): failed");
  }
*/

  if (sccmd_GetVersion(scrctx, &sc_version) < 0) {
    xerr_errx(1, "sccmd_GetVersion(): failed");
  }

  str_hex_dump(fmt_buf, sc_version, 1);
  printf("Version: 0x%s\n", fmt_buf);

  sc_count_len = 4;

  for (j = 0; j < 7; ++j) {

    sc_idx[0] = j;
  
    if (sccmd_GetHost32(scrctx, &sc_idx, sc_count32, sc_hostname,
      sc_hotpkey) < 0) {
      xerr_errx(1, "sccmd_GetVersion(): failed");
    }
  
    str_hex_dump(fmt_buf, sc_idx, SC_INDEX_LEN);
    i = (SC_INDEX_LEN<<1); fmt_buf[i] = ':'; i += 1;
  
    /* count */
    /* pad to 32 bits */
    for (k = 0; k < (4-sc_count_len)<<1; ++k)
      fmt_buf[i++] = '0';
    str_hex_dump(fmt_buf+i, sc_count32, sc_count_len);
    i += (sc_count_len<<1); fmt_buf[i] = ':'; i += 1;
  
    /* hostname */
    str_hex_dump(fmt_buf+i, (u_char*)sc_hostname, SC_HOSTNAME_LEN);
    i += (SC_HOSTNAME_LEN<<1); fmt_buf[i] = ':'; i += 1;
  
    /* key */
    str_hex_dump(fmt_buf+i, sc_hotpkey, SC_HOTPKEY_LEN);
  
    printf("%s\n", fmt_buf);

  } /* for */

  scr_ctx_free(scrctx);

} /* main */

#endif /* SCR_EXAMPLE */
