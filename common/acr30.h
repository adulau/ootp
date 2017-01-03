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
 *      $Id: acr30.h 28 2009-11-29 23:09:09Z maf $
 */

#ifndef ACR30_H
#define ACR30_H

#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>

#define ASCII_SOH 0x01
#define ASCII_STX 0x02
#define ASCII_ETX 0x03
#define ASCII_ENQ 0x05

#define ACR30_STAT_INTERNAL0 0
#define ACR30_STAT_INTERNAL1 1
#define ACR30_STAT_INTERNAL2 2
#define ACR30_STAT_INTERNAL3 3
#define ACR30_STAT_INTERNAL4 4
#define ACR30_STAT_INTERNAL5 5
#define ACR30_STAT_INTERNAL6 6
#define ACR30_STAT_INTERNAL7 7
#define ACR30_STAT_INTERNAL8 8
#define ACR30_STAT_INTERNAL9 9
#define ACR30_STAT_MAX_C     10
#define ACR30_STAT_MAX_R     11
#define ACR30_STAT_C_TYPE0   12
#define ACR30_STAT_C_TYPE1   13
#define ACR30_STAT_C_SEL     14
#define ACR30_STAT_C_STAT    15

#define ACR30_STAT_FLAG_CARD_INSERTED 0x1


/* default serial device */
#define ACR30_IO_DEFAULT "/dev/cuaU0"

/* maximum size of data field, note extended responses >=255 */
#define ACR30_MAX_DLEN 254

/* maximum stored ATR size, must be as large as ACR30_MAX_DLEN */
#define ACR30_ATR_LEN 254

/* size of status message */
#define ACR30_STAT_LEN 16

/* read buffer size */
#define ACR30_READ_BUF_LEN 4096

/* ACR30 commands */
#define ACR30_CMD_GET_ACR_STAT 0x01
#define ACR30_CMD_MCU 0xA0
#define ACR30_CMD_RESET 0x80
#define ACR30_CMD_POWER_OFF 0x81

/* ACR30 response header */
#define ACR30_HEADER_START 0x01

/* delays in useconds (10^-6) */
#define ACR30_OPEN_DELAY    100000
#define ACR30_RESET_DELAY   150000
#define ACR30_STAT_DELAY    150000
#define ACR30_INSERT_DELAY  999999

/* delay in .1 seconds */
#define ACR30_TMOUT_READ 50
 
/* minimum response is header:1 SW1:2 SW2:2 dlen:2 csum:2 */
#define ACR30_DECODE_MIN (1+2+2+2+2)

/*
 * normal response only header:1 SW1:2 SW2:2 dlen:2 data:dlen csum:2
 * where dlen < 255 = 1+2+2+2+254+2.  Hardware has extended response
 * mode where dlen=255 -- not supported here.
 */
#define ACR30_DECODE_MAX (1+2+2+2+254+2)

struct acr30_tx {
  u_char header;
  u_char instruction;
  u_char data_len;
  u_char data[ACR30_MAX_DLEN];
  u_char csum;
    /* 1(STX)
     * 2(header)
     * 2(instruction)
     * 2(data len)
     * data*2
     * 2(checksum)
     */
  u_char encoded[1+2+2+2+2*ACR30_MAX_DLEN+2];
  int encoded_len;
};

struct acr30_rx {
  u_char header;
  u_char SW1;
  u_char SW2;
  u_char data_len;
  u_char data[ACR30_MAX_DLEN];
  u_char csum;
};

struct acr30_ctx {
  int fd;
  int baud;
  struct acr30_tx tx;
  struct acr30_rx rx;
  u_char buf[ACR30_READ_BUF_LEN];
  u_char ATR[ACR30_ATR_LEN];
  u_char stat[ACR30_STAT_LEN];
  int buf_len;
  int ATR_len;
  int stat_len;
  int reset;
  int card_inserted;
  int debug;
};
 
int acr30_tx_encode(struct acr30_tx *tx);
int acr30_rx_decode(struct acr30_ctx *acr30ctx);
struct acr30_ctx *acr30_open(char *dev, int debug);
int acr30_close(struct acr30_ctx *acr30ctx);
int acr30_reset(struct acr30_ctx *acr30ctx);
int acr30_powerdown(struct acr30_ctx *acr30ctx);
int acr30_flush(struct acr30_ctx *acr30ctx);
int acr30_get_acr_stat(struct acr30_ctx *acr30ctx);

int acr30_read(struct acr30_ctx *acr30);
int acr30_process_resp(struct acr30_ctx *acr30ctx);
int acr30_transaction(struct acr30_ctx *acr30ctx, useconds_t udelay,
  u_char SW1, u_char SW2, u_char le);
void acr30_comm_debug(struct acr30_ctx *acr30ctx, int txrx);
void acr30_ATR(struct acr30_ctx *acr30ctx);

int acr30_checksw1sw2(struct acr30_rx *rx, u_char SW1, u_char SW2, int verbose);
void dump_ascii(u_char *buf, int buf_len);

#endif /* ACR30_H */
