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
 *      $Id: acr30.c 28 2009-11-29 23:09:09Z maf $
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include "str.h"
#include "xerr.h"
#include "acr30.h"

#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif

/* ACR30 debug format buffer */
#define DBG_FMT_BUF_LEN 1024

/* enable verbose debugging */
#define ACR30_DEBUG

/*
 *
 * embedded driver for ACR30S based readers.
 * http://www.acs.com.hk/drivers/eng/REF_ACx30.pdf included in doc
 *
 * Supports normal commands only.
 *
 * external:
 *  acr30_open()          - create context / open serial port
 *  acr30_reset()         - reset ARC30S
 *  acr30_powerdown()     - power down SC.  Use reset to power up.
 *  acr30_get_acr_stat()  - get status of ACR30
 *  acr30_transaction()   - perform SC transaction
 *  acr30_close()         - free context / close serial port
 *
 * internal:
 *  acr30_read()          - read output from SC
 *  acr30_process_resp()  - process SC response
 *  acr30_tx_encode()     - encode SC transaction
 *  acr30_rx_decode()     - decode SC transaction
 *  acr30_checksw1sw2()   - check ACR30S SW1SW2 field in transactions
 *                          not the same as SC SW1SW2 code.
 *  acr30_comm_debug()    - i/o debugging
 *  acr30_ATR()           - display SC ATR
 *
 */

/*
 * function: acr30_open()
 *
 * create context for ACR30S SC reader.  Open serial port,
 * reset device, wait for card to be inserted.
 *
 * call acr30_close() to free resources.
 *
 * arguments:
 *
 *  dev   - serial port device name
 *  debug - debugging level
 *
 * returns: allocated acr30_ctx, or 0L on failure.
 *
 */
struct acr30_ctx *acr30_open(char *dev, int debug)
{
  struct termios t;
  struct acr30_ctx *acr30ctx;
  int ret;

  ret = -1; /* fail */

  if (!(acr30ctx = (struct acr30_ctx*)malloc(sizeof *acr30ctx))) {
    xerr_warn("malloc(acr30ctx)");
    goto acr30_open_out;
  }

  bzero(acr30ctx, (sizeof *acr30ctx));
  acr30ctx->fd = -1;

  acr30ctx->debug = debug;

  if ((acr30ctx->fd = open(dev, O_RDWR)) < 0) {
    xerr_warn("open(%s)", dev);
    goto acr30_open_out;
  }

  if (tcgetattr(acr30ctx->fd, &t) < 0) {
    xerr_warn("tcgetattr()");
    goto acr30_open_out;
  }

  cfmakeraw(&t);
  cfsetspeed(&t, B9600);
  t.c_cc[VTIME] = ACR30_TMOUT_READ;
  t.c_cc[VMIN] = 0;
  /* t.c_cflag = CS8|CREAD|CRTSCTS|HUPCL; */

  if (tcsetattr(acr30ctx->fd, TCSANOW, &t) < 0) {
    xerr_warn("tcsetattr()");
    goto acr30_open_out;
  }

  usleep(ACR30_OPEN_DELAY);

  /*
   * reset on open may have failed due to trash in the input buffer or
   * the serial driver misses the first few bytes when after the
   * open() to the ACR30S i/o port (PL2303 driver on Mac 10.5).
   *
   * power down the SC, flush the buffer, get the card status, reset
   * again.
   *
   */

  if (acr30ctx->debug)
    xerr_warnx("Power cycling ACR30");

  if (acr30_powerdown(acr30ctx) < 0) {
    xerr_warnx("acr30_powerdown(): failed.");
    goto acr30_open_out;
  }

  if (acr30_flush(acr30ctx) < 0) {
    xerr_warnx("acr30_flush(): failed.");
    goto acr30_open_out;
  }

  if (acr30_reset(acr30ctx) < 0) {
    xerr_warnx("acr30_reset(): failed.");
    goto acr30_open_out;
  }

  if (acr30_get_acr_stat(acr30ctx) < 0) {
    xerr_warnx("acr30_get_acr_stat(): failed.");
    goto acr30_open_out;
  }

  if (acr30_reset(acr30ctx) < 0) {
    xerr_warnx("acr30_reset(): failed.");
    goto acr30_open_out;
  }

  /* wait for card to be inserted */
  while (!acr30ctx->card_inserted) {

    usleep(ACR30_INSERT_DELAY);

    if (acr30_get_acr_stat(acr30ctx) < 0) {
      xerr_warnx("acr30_get_acr_stat(): failed.");
      goto acr30_open_out;
    }

    if (acr30_reset(acr30ctx) < 0) {
      xerr_warnx("acr30_reset(): failed.");
      goto acr30_open_out;
    }

  } /* card not inserted */

  ret = 0; /* success */

acr30_open_out:

  if (ret == -1) {

    if (acr30ctx) {

      if (acr30ctx->fd != -1)
        close(acr30ctx->fd);

      free (acr30ctx);

      acr30ctx = (struct acr30_ctx*)0L;

    } /* acr30ctx */

  } /* ret == -1 */

  return acr30ctx;

} /* acr30_open */

/* 
 * function: acr30_close()
 *
 * free context for acr30_ctx created with acr30_open.  Close serial
 * port.
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_close(struct acr30_ctx *acr30ctx)
{
  if (acr30ctx) {

    if (acr30ctx->fd != -1)
      close(acr30ctx->fd);

    free (acr30ctx);

    return 0;

  } /* acr30ctx */

  xerr_warnx("acr30_close(): *acr30ctx == 0L");

  return -1;

} /* acr30_close */

/* 
 * function: acr30_reset()
 *
 * reset SC reader
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_reset(struct acr30_ctx *acr30ctx)
{
  int r, i;

  acr30ctx->tx.header = ACR30_HEADER_START;
  acr30ctx->tx.instruction = ACR30_CMD_RESET;
  acr30ctx->tx.data_len = 0;

  acr30_tx_encode(&acr30ctx->tx);

#ifdef ACR30_DEBUG
  if (acr30ctx->debug)
    acr30_comm_debug(acr30ctx, 1);
#endif /* ACR30_DEBUG */

  if (write(acr30ctx->fd, acr30ctx->tx.encoded, acr30ctx->tx.encoded_len) < 0) {
    xerr_warn("write()");
    return -1;
  }

  usleep(ACR30_RESET_DELAY);

  /* reset can take a while... */
  for (i = 0; i < 2; ++i) {

    /* load decode buffer with 1 or more responses */
    if (acr30_read(acr30ctx) < 0) {
      xerr_warnx("acr30_read(): failed.");
      close(acr30ctx->fd);
      return -1;
    }

#ifdef ACR30_DEBUG
    if (acr30ctx->debug)
      acr30_comm_debug(acr30ctx, 0);
#endif /* ACR30_DEBUG */

    if ((r = acr30_process_resp(acr30ctx)) < 0) {
      xerr_warnx("acr30_process_resp(): failed.");
      return -1;
    }

    if (r == 1) {
      xerr_warnx("acr30_process_resp(): nothing to decode buf_len=%d",
        acr30ctx->buf_len);
      continue;
    }

    /* this is not fatal */
    if (acr30_checksw1sw2(&acr30ctx->rx, 0x90, 0x00, acr30ctx->debug) < 0) {

      return 1;

    } else {

      if (acr30ctx->rx.data_len > ACR30_ATR_LEN)
        xerr_errx(1, "fatal: acr30ctx->rx.data_len > ACR30_ATR_LEN");

      bcopy(acr30ctx->rx.data, acr30ctx->ATR, acr30ctx->rx.data_len);
      acr30ctx->ATR_len = acr30ctx->rx.data_len;

      /* display ATR */
      if (acr30ctx->debug) {
        acr30_ATR(acr30ctx);
      }

      return 0;

    } /* got reply */

  } /* for RESET retry */

  xerr_warnx("Timeout waiting for RESET");
  return -1;
  
} /* acr30_reset */

/* 
 * function: acr30_get_acr_stat()
 *
 * issue GET_ACR_STAT.  Update card_inserted flag
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_get_acr_stat(struct acr30_ctx *acr30ctx)
{
  int r;

  acr30ctx->tx.header = ACR30_HEADER_START;
  acr30ctx->tx.instruction = ACR30_CMD_GET_ACR_STAT;
  acr30ctx->tx.data_len = 0;

  acr30_tx_encode(&acr30ctx->tx);

#ifdef ACR30_DEBUG
  if (acr30ctx->debug)
    acr30_comm_debug(acr30ctx, 1);
#endif /* ACR30_DEBUG */

  if (write(acr30ctx->fd, acr30ctx->tx.encoded, acr30ctx->tx.encoded_len) < 0) {
    xerr_warn("write()");
    return -1;
  }

  usleep(ACR30_STAT_DELAY);

  /* load decode buffer with 1 or more responses */
  if (acr30_read(acr30ctx) < 0) {
    xerr_warnx("acr30_read(): failed.");
    close(acr30ctx->fd);
    return -1;
  }

#ifdef ACR30_DEBUG
  if (acr30ctx->debug)
    acr30_comm_debug(acr30ctx, 0);
#endif /* ACR30_DEBUG */

  if ((r = acr30_process_resp(acr30ctx)) < 0) {
    xerr_warnx("acr30_process_resp(): failed.");
    return -1;
  }

  if (r == 1) {
    xerr_warnx("acr30_process_resp(): nothing to decode buf_len=%d",
      acr30ctx->buf_len);
    return -1;
  }

  if (acr30_checksw1sw2(&acr30ctx->rx, 0x90, 0x00, acr30ctx->debug) < 0) {

    xerr_warnx("Unexpected reply to ACR_GET_STAT");
    return -1;

  } else {

    if (acr30ctx->rx.data_len > ACR30_STAT_LEN)
      xerr_errx(1, "fatal: acr30ctx->rx.data_len > ACR30_STAT_LEN");

    bcopy(acr30ctx->rx.data, acr30ctx->stat, acr30ctx->rx.data_len);
    acr30ctx->stat_len = acr30ctx->rx.data_len;


    if (acr30ctx->stat_len != ACR30_STAT_LEN) {
      xerr_warnx("Unable to decode ACR30_STAT buffer, len=%d",
        acr30ctx->stat_len);

    } else {

      if (acr30ctx->stat[ACR30_STAT_C_STAT] & ACR30_STAT_FLAG_CARD_INSERTED)
        acr30ctx->card_inserted = 1;

    }

    return 0;

  } /* got reply */

  xerr_warnx("Timeout waiting for GET_ACR_STAT");
  return -1;
  
} /* acr30_get_acr_stat */

/* 
 * function: acr30_powerdown()
 *
 * power down SC in reader
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_powerdown(struct acr30_ctx *acr30ctx)
{
  acr30ctx->tx.header = ACR30_HEADER_START;
  acr30ctx->tx.instruction = ACR30_CMD_POWER_OFF;
  acr30ctx->tx.data_len = 0;

  acr30_tx_encode(&acr30ctx->tx);

#ifdef ACR30_DEBUG
  if (acr30ctx->debug)
    acr30_comm_debug(acr30ctx, 1);
#endif /* ACR30_DEBUG */

  if (write(acr30ctx->fd, acr30ctx->tx.encoded, acr30ctx->tx.encoded_len) < 0) {
    xerr_warn("write()");
    return -1;
  }

  return 0;

} /* acr30_powerdown */

/* 
 * function: acr30_transaction()
 *
 * perform ACR30 transaction.
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *  udelay   - delay between transaction send and looking for reply
 *  SW1,SW2  - expected return code from ACR30.  Failure will be returned
 *             if SW1SW2 do not match the transaction.
 *  le       - length of data expected in reply.  Set to 255 to ignore.
 *             Failure will be returned if le does not match transaction.
 *
 * Data will be encoded as part of the transaction.
 *
 * Example for sending MCU command:
 *
 *  SW1 = 0x00
 *  SW2 = 0x00
 *  udelay = 10000
 *  le = 1
 *
 *  acr30ctx->tx.header = ACR30_HEADER_START;
 *  acr30ctx->tx.instruction = ACR30_CMD_MCU;
 *  acr30ctx->tx.data_len = buf_len
 *  acr30ctx->tx_buf = buf
 *
 * where buf is :
 *
 *  i = 0;
 *
 *  buf[i++] = CLA
 *  buf[i++] = INS
 *  buf[i++] = P1
 *  buf[i++] = P2
 *  buf[i++] = LC
 *  buf[i++] = <data>
 *  buf[i++] = LE
 *
 *  buf_len = i;
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_transaction(struct acr30_ctx *acr30ctx, useconds_t udelay,
  u_char SW1, u_char SW2, u_char le)
{

  int r;

  /* encode bitstram */
  acr30_tx_encode(&acr30ctx->tx);

#ifdef ACR30_DEBUG
  if (acr30ctx->debug)
    acr30_comm_debug(acr30ctx, 1);
#endif /* ACR30_DEBUG */

  if (write(acr30ctx->fd, acr30ctx->tx.encoded, acr30ctx->tx.encoded_len) < 0) {
    xerr_warn("write()");
    return -1;
  }

  usleep(udelay);

  /* load decode buffer with 1 or more responses */
  if (acr30_read(acr30ctx) < 0) {
    xerr_warnx("acr30_read(): failed.");
    return -1;
  }

#ifdef ACR30_DEBUG
  if (acr30ctx->debug)
    acr30_comm_debug(acr30ctx, 0);
#endif /* ACR30_DEBUG */

  if ((r = acr30_process_resp(acr30ctx)) < 0) {
    xerr_warnx("acr30_process_resp(): failed.");
    return -1;
  }

  if (r == 1) {
    xerr_warnx("acr30_process_resp(): nothing to decode buf_len=%d",
      acr30ctx->buf_len);
    return -1;
  }

  /* check the reader return codes */
  if (acr30_checksw1sw2(&acr30ctx->rx, SW1, SW2, acr30ctx->debug) < 0) {
    return -1;
  }

  /* verify data format (data + SW1SW2) le=255=unknown */
  if (le == 255) {

    if (acr30ctx->rx.data_len < 2) {
      xerr_warnx("rx.data_len=%d < 2.", acr30ctx->rx.data_len);
      return -1;
    }

  } else if ((acr30ctx->rx.data_len != 2) &&
            (acr30ctx->rx.data_len != (le+2))) {
      xerr_warnx("rx.data_len=%d not %d", acr30ctx->rx.data_len, (le+2));
      return -1;

  } /* rx.data_len check */

  return 0;

} /* acr30_transaction */
 
/* 
 * function: acr30_tx_encode()
 *
 * Encode data in acr30_tx* for presentation to ACR30S
 *
 * Extended length transactions (> 255) are not supported
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * set:
 *  acr30_tx->header
 *  acr30_tx->instruction
 *  acr30_tx->data_len
 *  acr30_tx->data
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_tx_encode(struct acr30_tx *acr30_tx)
{
  int i;

  acr30_tx->encoded[0] = ASCII_STX;

  acr30_tx->encoded[1] = chr_hex_l(acr30_tx->header);
  acr30_tx->encoded[2] = chr_hex_r(acr30_tx->header);

  acr30_tx->encoded[3] = chr_hex_l(acr30_tx->instruction);
  acr30_tx->encoded[4] = chr_hex_r(acr30_tx->instruction);

  /* length limited to < 255, not protocol
   * allows extended data length, not implemented
   */
  acr30_tx->encoded[5] = chr_hex_l(acr30_tx->data_len);
  acr30_tx->encoded[6] = chr_hex_r(acr30_tx->data_len);

  acr30_tx->csum = 0;

  for (i = 0; i < acr30_tx->data_len; ++i) {
    acr30_tx->encoded[i*2+7] = chr_hex_l(acr30_tx->data[i]);
    acr30_tx->encoded[i*2+8] = chr_hex_r(acr30_tx->data[i]);
    acr30_tx->csum ^= acr30_tx->data[i];
  }

  acr30_tx->csum ^= (acr30_tx->header ^ acr30_tx->instruction ^\
    acr30_tx->data_len);

  acr30_tx->encoded[i*2+7] = chr_hex_l(acr30_tx->csum);
  acr30_tx->encoded[i*2+8] = chr_hex_r(acr30_tx->csum);
  acr30_tx->encoded[i*2+9] = ASCII_ETX;

  acr30_tx->encoded_len = i*2+10;

  return 0;

} /* acr30_tx_encode */

/*
 * function: acr30_checksw1sw2()
 *
 * Check response from ACR30.
 *
 * arguments:
 *  acr30_rx  - receive structure filled in acr30_read() & acr30_process_resp()
 *  SW1       - expected value of SW1
 *  SW2       - expected value of SW2
 *  verbose   - set true to display status of failed check with xerr_warnx
 *
 * returns: 0  - success - SW1 and SW2 matched ACR30 reply
 *          <0 - failure - SW1 or SW2 did not match ACR30 reply
 *  
 */
int acr30_checksw1sw2(struct acr30_rx *rx, u_char SW1, u_char SW2, int verbose)
{
  if ((rx->SW1 == SW1) && (rx->SW2 == SW2)) {
    return 0; /* good */
  }

  xerr_warnx("response: SW1=%2.2X,SW2=%2.2X expecting: SW1=%2.2X, SW2=%2.2X",
    (int)rx->SW1, (int)rx->SW2, (int)SW1, (int)SW2);

  if ((rx->SW1 == 0x60) && (rx->SW2 == 0x02))
    xerr_info("No card in reader.");

  if ((rx->SW1 == 0x60) && (rx->SW2 == 0x04))
    xerr_info("Card not powered up.");

  if ((rx->SW1 == 0x60) && (rx->SW2 == 0x20))
    xerr_info("Card failure.");

  if ((rx->SW1 == 0x60) && (rx->SW2 == 0x22))
    xerr_info("Short circuit at card connector.");

  if ((rx->SW1 == 0x67) && (rx->SW2 == 0x12))
    xerr_info("APDU aborted.");

  return -1; /* fail */

} /* acr30_checksw1sw2 */

/*
 * function: acr30_rx_decode()
 *
 * Decode response from ACR30.  The ACR30 encodes each byte as two
 * ASCII hex digits + start, end, and error packet bytes.  Decode
 * response into binary.  Verify checksum, consume decoded bytes.
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_rx_decode(struct acr30_ctx *acr30ctx)
{
  int r_pos, w_pos, i, flag_etx;
  u_char decoded, csum;

  /* i  rx
   * ----------
   * 0  0x01
   * 1  header
   * 2  header    
   * 3  SW1
   * 4  SW1
   * 5  SW2
   * 6  SW2
   * 7  data_len (1)
   * 8  data_len (1)
   * 9  data
   * 10 data
   * 11 csum
   * 12 csum
   *
   * buf_len = 13
   */

  /* consume leading trash in response bytes */
  while (1) {

    /* complete response? */
    flag_etx = 0;

    /* transmission error? */
    if ((acr30ctx->buf_len == 2) && (acr30ctx->buf[0] == ASCII_ENQ) &&
      (acr30ctx->buf[1] == ASCII_ENQ)) {
      xerr_warnx("acr30_rx_decode(): transmission error");
      return -2;
    }

    /* sanity check */
    if (acr30ctx->buf_len > ACR30_DECODE_MAX) {
      xerr_warnx("acr30_rx_decode(): buf_len=%d > ACR30_DECODE_MAX=%d",
        acr30ctx->buf_len, ACR30_DECODE_MAX);
      return -1;
    }

    /* sanity check */
    if (acr30ctx->buf_len < ACR30_DECODE_MIN) {
      xerr_warnx("acr30_rx_decode(): buf_len=%d < ACR30_DECODE_MIN=%d",
        acr30ctx->buf_len, ACR30_DECODE_MIN);
      return -1;
    }

    /* response must begin with ASCII_STX */
    if (acr30ctx->buf[0] != ASCII_STX) {
      if (acr30ctx->debug)
        xerr_warnx("acr30_rx_decode(): buf[0]=%2.2X, expecting %2.2X",
        (int)acr30ctx->buf[0], (int)ASCII_STX);

      /* consume bytes until STX then retry */
      for (i = 0; i < acr30ctx->buf_len; ++i)
        if (acr30ctx->buf[i] == ASCII_STX)
          break;
      acr30ctx->buf_len -= i;

      /* anything left? */
      if (acr30ctx->buf_len < 1) {
        xerr_warnx("acr30_rx_decode(): underrun");
        return -1;
      }

      if (acr30ctx->debug)
        xerr_warnx("Skipped %d bytes, %d remaining", i, acr30ctx->buf_len);

      bcopy(acr30ctx->buf+i, acr30ctx->buf, acr30ctx->buf_len);

      continue; /* again */

    } else {

      /* ready to start decode */
      break;

    }

  } /* while consuming leading garbage */

  r_pos = 1; /* read position */
  w_pos = 0; /* write position */

  /* read two bytes in ASCII, convert to 1 byte of binary */
  for (; r_pos < acr30ctx->buf_len; r_pos += 2) {

    /* complete response? */
    if (acr30ctx->buf[r_pos] == ASCII_ETX) {
      flag_etx = 1;
      break;
    }

    /* expecting ASCII 0-9, A-F) */
    for (i = 0; i < 2; ++i) {

      /* valid? */
      if (chr_ishex(acr30ctx->buf[r_pos+i])) {
        xerr_warnx("acr30_rx_decode(): buf[%d]=%2.2X, not HEX.", r_pos+1,
          (int)acr30ctx->buf[r_pos+i]);
          return -1;
      }

      if (i == 0) {
        decoded = (chr_hex_decode(acr30ctx->buf[r_pos+i])<<4);
      } else {
        decoded |= chr_hex_decode(acr30ctx->buf[r_pos+i]);
      }

    } /* foreach 2 bytes in decode buffer */

    switch (r_pos) {

      case 1:
        acr30ctx->rx.header = decoded;
        break;

      case 3:
        acr30ctx->rx.SW1 = decoded;
        break;

      case 5:
        acr30ctx->rx.SW2 = decoded;
        break;

      case 7:
        acr30ctx->rx.data_len = decoded;
        break;

      default: /* data followed by checksum */
        if (w_pos == acr30ctx->rx.data_len) { /* checksum follows data */
          acr30ctx->rx.csum = decoded;
        } else {
          if (w_pos >= ACR30_MAX_DLEN) { /* never */
            xerr_errx(1, "acr30_rx_decode(): fatal, w_pos >= ACR30_MAX_DLEN.");
          }
          if (w_pos >= acr30ctx->rx.data_len) { /* only on corrupted rx */
            xerr_errx(1,
              "acr30_rx_decode(): fatal, w_pos >= acr30ctx->rx.data_len.");
          }
          acr30ctx->rx.data[w_pos++] = decoded;
        }
        break;

    } /* switch */

  } /* decode reply */

  if (!flag_etx) {
    xerr_warnx(
      "acr30_rx_decode(): incomplete response buf_len=%d", acr30ctx->buf_len);
    return -1;
  }

  /* validate checksum */
  csum = 0;
  csum ^= acr30ctx->rx.header;
  csum ^= acr30ctx->rx.SW1;
  csum ^= acr30ctx->rx.SW2;
  csum ^= acr30ctx->rx.data_len;

  for (i = 0; i < acr30ctx->rx.data_len; ++i) {
    csum ^= acr30ctx->rx.data[i];
  }

  if (csum != acr30ctx->rx.csum) {
    xerr_warnx("acr30_rx_decode(): Checksum failure, csum=%2.2X,rx_csum=%x",
      csum, acr30ctx->rx.csum);
      return -1;
  }

  /* consume bytes decoded */
  acr30ctx->buf_len -= (r_pos+1);
  bcopy(acr30ctx->buf+r_pos+1, acr30ctx->buf, acr30ctx->buf_len);

  /* return bytes left */
  return acr30ctx->buf_len;

} /* acr30_rx_decode */

/*
 * function: acr30_read()
 *
 * Read upto buf length bytes from fd.  Last byte(s) must be ETX or ENQ ENQ
 * timeout after ACR30_TMOUT_READ microseconds.  Warn if a full response is
 * not read with one syscall as this implies the delay after sending the
 * SC command should be increased.
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_read(struct acr30_ctx *acr30ctx)
{
  int n, bytes_left;

  while (1) {

    /* bytes left in read buffer */
    bytes_left = (ACR30_READ_BUF_LEN - acr30ctx->buf_len);

    /* buffer full? */
    if (bytes_left == 0) {
      xerr_warnx("acr30_read(): read buffer full ");
      return -1;
    }

    /* read bytes at buf[buf_len] */
    if ((n = read(acr30ctx->fd, acr30ctx->buf+acr30ctx->buf_len,
      bytes_left)) < 0) {
      xerr_warn("acr30_read(): read()");
      return -1;
    }

    /* timeout? */
    if (n == 0) {
      xerr_warnx("acr30_read(): timeout");
      return -1;
    }

    acr30ctx->buf_len += n;

    /* complete response when character is ETX */
    if (acr30ctx->buf[acr30ctx->buf_len-1] == ASCII_ETX)
      return 0;

    /* complete response when last 2 chars are ENQ ENQ -- xmit error */
    if ((acr30ctx->buf_len >= 2) &&
        (acr30ctx->buf[acr30ctx->buf_len-1] == ASCII_ETX) &&
      (acr30ctx->buf[acr30ctx->buf_len-2] == ASCII_ETX)) {
      return 0;
    }

    if (acr30ctx->debug)
      xerr_warnx("read()=%d, increase cmd timeout.", n);

  } /* forever */

  return -1; /* never */

} /* acr30_read */

/*
 * function: acr30_process_resp()
 *
 * process response to ACR30 command, handle async generated responses.
 *
 * Picks off common responses such as CARD_INSERTED and updates internal
 * state flags.  Leave anything else to application.
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_process_resp(struct acr30_ctx *acr30ctx)
{
  int n, next;

  next = 0;

  /* while more responses to decode */
  while (acr30ctx->buf_len) {

    /* decode */
    if ((n = acr30_rx_decode(acr30ctx)) < 0) {
      xerr_warnx("acr30_rx_decode(): failed.");
      return -1;
    }

    /*
     * The ACR30 can send messages such as card inserted async,
     * handle internally
     */

    /*
     * powerup reset:  SW1=0xFF, SW2=0x00
     * card inserted:  SW1=0xFF, SW2=0x01
     * card removed:   SW1=0xFF, SW2=0x02
     */

    /* power up reset */
    if ((acr30ctx->rx.SW1 == 0xFF) && (acr30ctx->rx.SW2 == 0x00)) {
      acr30ctx->reset = 1;
      continue; /* again */
    }

    /* card inserted */
    if ((acr30ctx->rx.SW1 == 0xFF) && (acr30ctx->rx.SW2 == 0x01)) {
      acr30ctx->card_inserted = 1;
      if (acr30ctx->debug)
        xerr_warnx("Card inserted.");
      continue; /* again */
    }

    /* card removed */
    if ((acr30ctx->rx.SW1 == 0xFF) && (acr30ctx->rx.SW2 == 0x02)) {
      acr30ctx->card_inserted = 0;
      if (acr30ctx->debug)
        xerr_warnx("Card removed.");
      continue; /* again */
    }

    /* anything else is handled by the application */
    return 0;

  } /* while more messages to decode */

  /* no application level decoded messages */
  return 1;

} /* acr30_process_resp */

#define CHKLEN(I,MAX)\
  if (I >= MAX)\
    xerr_errx(1, "acr30_comm_debug(): fatal, fmt_buf overrun.");

/*
 * function: acr30_ATR()
 *
 * decode and display ATR as printable ASCII.  Non printable
 * bytes are displayed as HEX.
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
void acr30_ATR(struct acr30_ctx *acr30ctx)
{
  int i, j, buf_len;
  char fmt_buf[DBG_FMT_BUF_LEN+1];
  u_char *buf;
  j = 0;

  buf = acr30ctx->ATR;
  buf_len = acr30ctx->ATR_len;

  for (i = 0; i < buf_len; ++i) {

    if (isprint((int)buf[i])) {
      fmt_buf[j++] = buf[i]; CHKLEN(j,DBG_FMT_BUF_LEN);
    } else {
      fmt_buf[j++] = '0'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = 'x'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = chr_hex_l(buf[i]); CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = chr_hex_r(buf[i]); CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = ' '; CHKLEN(j,DBG_FMT_BUF_LEN);
    }
  } /* for */

  xerr_info("ATR(): %s", fmt_buf);

} /* acr30_ATR */

/*
 * function: acr30_comm_debug()
 *
 * decode and display ACR30 communications i/o
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
void acr30_comm_debug(struct acr30_ctx *acr30ctx, int txrx)
{
  int i, j, first, buf_len;
  u_char *buf;
  char fmt_buf[DBG_FMT_BUF_LEN+1];

  if (txrx == 1) {
    buf = acr30ctx->tx.encoded;
    buf_len = acr30ctx->tx.encoded_len;
  } else {
    buf = acr30ctx->buf;
    buf_len = acr30ctx->buf_len;
  }

  first = 0;
  j = 0;

  for (i = 0; i < buf_len; ++i) {

    if (buf[i] == 0x2) {

      fmt_buf[j++] = 'S'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = 'T'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = 'X'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = ' '; CHKLEN(j,DBG_FMT_BUF_LEN);

    } else if (buf[i] == 0x3) {

      fmt_buf[j++] = 'E'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = 'T'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = 'X'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = ' '; CHKLEN(j,DBG_FMT_BUF_LEN);

    } else if ( ((buf[i] >= '0') && (buf[i] <= '9')) ||
               ((buf[i] >= 'A') && (buf[i] <= 'F'))) {

      fmt_buf[j++] = buf[i]; CHKLEN(j,DBG_FMT_BUF_LEN);

      if (first == 0){
        first = 1;
      } else {
        first = 0;
        fmt_buf[j++] = ' '; CHKLEN(j,DBG_FMT_BUF_LEN);
      }

    } else {

      fmt_buf[j++] = '0'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = 'x'; CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = chr_hex_l(buf[i]); CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = chr_hex_r(buf[i]); CHKLEN(j,DBG_FMT_BUF_LEN);
      fmt_buf[j++] = ' '; CHKLEN(j,DBG_FMT_BUF_LEN);

    }

  }

  fmt_buf[j] = 0;

  if (txrx == 1)
    xerr_info("acr30_comm_debug(TX): %s", fmt_buf);
  else
    xerr_info("acr30_comm_debug(RX): %s", fmt_buf);

} /* acr30_comm_debug */

/*
 * function: acr30_flush()
 *
 * flush input buffer and serial port input.
 *
 * arguments:
 *  acr30ctx - context allocated with acr30_open()
 *
 * returns: 0  - success
 *          <0 - failure
 *
 */
int acr30_flush(struct acr30_ctx *acr30ctx)
{
  struct termios t;

  acr30ctx->buf_len = 0;

  if (tcgetattr(acr30ctx->fd, &t) < 0) {
    xerr_warn("tcgetattr()");
    return -1;
  }

  if (tcsetattr(acr30ctx->fd, TCSAFLUSH, &t) < 0) {
    xerr_warn("tcsetattr(TCSAFLUSH)");
    return -1;
  }

  return 0;

} /* acr30_flush */
