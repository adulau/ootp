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
 *      $Id: htsoft-downloader.c 128 2010-06-15 14:25:09Z maf $
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif
#include <termios.h>
#include <unistd.h>
#include "xerr.h"

/* offsets in Intel hex file record (line) */
#define IHEX_OFF_MARK 0
#define IHEX_OFF_RECLEN 1
#define IHEX_OFF_LOAD_OFFSET_HIGH 3
#define IHEX_OFF_LOAD_OFFSET_LOW 5
#define IHEX_OFF_RECTYPE 7
#define IHEX_OFF_DATA 9

/* Intel hex file record types */
#define IHEX_REC_DATA 0x0
#define IHEX_REC_EOF  0x1
#define IHEX_REC_ESAR 0x2
#define IHEX_REC_SSAR 0x3
#define IHEX_REC_ELAR 0x4
#define IHEX_REC_SLAR 0x5

/* htsoft bootloader commands */
#define HTSOFT_V1BL_READ     0xE0
#define HTSOFT_V1BL_RACK     0xE1
#define HTSOFT_V1BL_WRITE    0xE3
#define HTSOFT_V1BL_WOK      0xE4
#define HTSOFT_V1BL_WBAD     0xE5
#define HTSOFT_V1BL_DATA_OK  0xE7
#define HTSOFT_V1BL_DATA_BAD 0xE8
#define HTSOFT_V1BL_IDENT    0xEA
#define HTSOFT_V1BL_IDACK    0xEB
#define HTSOFT_V1BL_DONE     0xED

/* number of times to retry a command */
#define HTSOFT_RETRIES 5

/* default timeout when reading serial port in .1 second increments */
#define HTSOFT_TIMEOUT 25

void help(void);

int htsoft_v1bl_idack(int fd, int verbose);
int htsoft_v1bl_upload(int fd, uint16_t load_offset, uint8_t *buf,
  uint8_t buf_len, int verbose, int max_retries);
int htsoft_v1bl_done(int fd, int verbose, int retries, int ignore_wok_timeout);

int n22b(char *h, u_char *b);
int n2b(char *h, u_char *b);

int main(int argc, char **argv)
{
  extern char *ootp_version;
  struct termios pic_term;
  char lbuf[1024];
  char *c;
  uint8_t h_reclen, h_rectype, tmp_csum, h_load_high, h_load_low;
  uint8_t tmp_high, tmp_low, h_csum;
  uint8_t ld_buf[256], ld_buf_len;
  uint16_t h_load_offset, tmp_load_offset, buf_load_offset;
  int i, r, pic_fd, lineno, lbuf_len, got_eof, pic_tmout, verbose;
  int max_retries, ignore_last_wok_timeout, opt_version;
  char *pic_dev;

  struct option longopts[] = {
    { "serial-device",              1, (void*)0L, 'f'},
    { "help",                       0, (void*)0L, 'h'},
    { "help",                       0, (void*)0L, '?'},
    { "ignore-last-wok-timeout",    0, (void*)0L, 'i'},
    { "retries",                    1, (void*)0L, 'r'},
    { "pic-timeout",                1, (void*)0L, 't'},
    { "verbose",                    0, (void*)0L, 'v'},
    { "version",                    0, &opt_version, 1},
    { 0, 0, 0, 0},
  };

  xerr_setid(argv[0]);
  lineno = 0;
  ld_buf_len = 0;
  got_eof = 0;
  pic_dev = "/dev/cuaU0";
  pic_tmout = HTSOFT_TIMEOUT;
  verbose = 0;
  max_retries = HTSOFT_RETRIES;
  h_load_offset = 0;
  buf_load_offset = 0;
  ignore_last_wok_timeout = 0;
  opt_version = 0;

  while ((i = getopt_long(argc, argv, "f:h?ir:t:v:", longopts,
    (int*)0L)) != -1) {

    switch (i) {

      case 'f':
        pic_dev = optarg;
        break;

      case 'h':
      case '?':
        help();
        exit(0);
        break; /* notreached */

      case 'i':
        ignore_last_wok_timeout = 1;
        break;

      case 'r':
        max_retries = atoi(optarg);
        break;

      case 't':
        pic_tmout = atoi(optarg);
        break;

      case 'v':
        verbose = atoi(optarg);
        break;

      case 0:
        if (opt_version) {
          printf("%s\n", ootp_version);
          exit(0);
        }

      default:
        xerr_errx(1, "getopt_long(): fatal.");
        break; /* not reached */

    } /* switch */

  } /* while getopt_long() */

  /* open and setup serial communications port */
  if ((pic_fd = open(pic_dev, O_RDWR)) < 0)
    xerr_err(1, "open(%s)", pic_dev);

  if (tcgetattr(pic_fd, &pic_term) < 0)
    xerr_err(1, "tcgetattr(%s)", pic_dev);

  cfmakeraw(&pic_term);
  cfsetspeed(&pic_term, B9600);
  pic_term.c_cc[VTIME] = pic_tmout;
  pic_term.c_cc[VMIN] = 0;
  /* pic_term.c_cflag = CS8|CREAD|CRTSCTS|HUPCL; */

  if (tcsetattr(pic_fd, TCSANOW, &pic_term) < 0)
    xerr_err(1, "tcgetattr(%s)", pic_dev);

  /* search for bootloader */
  htsoft_v1bl_idack(pic_fd, verbose);

  /* foreach line in HEX file */
  while (!feof(stdin)) {

    ++ lineno;

    /*
     * Intel Hexadecimal Object File Format Specification
     * Rev A, January 6, 1988
     *
     * record_mark reclen load_offset rectype info/data chksum   CR      NULL
     *  1-byte      1-byte  2-bytes    1-byte  n-bytes   1-byte  1-byte   1
     *
     * Each byte is presented in ASCII HEX format (2 bytes per byte)
     *
     * max size of record where reclen is 255 bytes:
     *  1 + (1 + 2 + 1 + 255 + 1)*2 + 1 + 1 = 523
     *
     *
     * Record Types:
     *   00  Data Record
     *   01  End of File Record
     *   02  Extended Segment Address Record
     *   03  Start Segment Address Record
     *   04  Extended Linear Address Record
     *   05  Start Linear Address Record
     *
     * 02, 03, 04 are not applicable
     * 05 sets the upper 16 bits of the load address and is not applicable
     *    if set to other than 0 for the PIC 16F877
     *
     * 01 indicates the end of file and must be present
     * 00 indicates bytes to be loaded into the PIC at load_offset address.
     *
     */

    fgets(lbuf, sizeof(lbuf), stdin);

    /* EOF? */
    if (feof(stdin))
      break;

    if (got_eof)
      xerr_warnx("line %d: warning, data beyond EOF.", lineno);

    /* check: record begins with : */
    if (lbuf[IHEX_OFF_MARK] != ':')
      xerr_errx(1, "line %d: fatal, record must begin with :", lineno);

    /* check: record ends with CR or LF and valid HEX chars */
    for (c = lbuf+1, lbuf_len = 1; *c && *c != '\r' && *c != '\n';
      ++c, ++lbuf_len) {

      if (*c >= '0' && *c <= '9')
        continue;

      if (*c >= 'a' && *c <= 'f')
        continue;

      if (*c >= 'A' && *c <= 'F')
        continue;

      xerr_errx(1, "line %d: fatal, non HEX character.", lineno);

    }
    if ((*c != '\r') && (*c != '\n'))
      xerr_errx(1, "line %d: fatal, no CR or LF.", lineno);

    /* CR is no longer needed */
    *c = 0;

    /* decode reclen field */
    if (n22b(&lbuf[IHEX_OFF_RECLEN], &h_reclen) < 0)
      xerr_errx(1, "n22b(): fatal");

    /* sanity check record length */
    if (((h_reclen+1+2+1+1)*2+1) != lbuf_len)
      xerr_errx(1, "line %d: fatal, length check failure (%d!=%d).", lineno,
        (h_reclen+1+2+1+1)*2+1, lbuf_len); 

    /* compute csum */
    for (tmp_csum = 0, i = 1; i < (h_reclen+1+2+1)*2; i += 2) {
      n22b(&lbuf[i], &tmp_low);
      tmp_csum += tmp_low;
    }

    /* stored csum */
    n22b(&lbuf[i], &h_csum);

    /* verify csum */
    if (((256 - tmp_csum)&0xFF) != h_csum)
      xerr_warnx("line %d: warning, checksum=%2.2x fail expecting %2.2x.",
        lineno, h_csum, (256-tmp_csum)&0xFF);

    /* grab record type */
    n22b(&lbuf[IHEX_OFF_RECTYPE], &h_rectype);

    switch (h_rectype) {

      case IHEX_REC_EOF :
        got_eof = 1;
        break;

      case IHEX_REC_ESAR:
        xerr_errx(1, "line %d: fatal, ESAR record not supported.",
          lineno);
        break;

      case IHEX_REC_SSAR:
        xerr_errx(1, "line %d: fatal, SSAR record not supported.",
          lineno);
        break;

      case IHEX_REC_SLAR:
        xerr_errx(1, "line %d: fatal, SLAR record not supported.",
          lineno);
        break;

      case IHEX_REC_ELAR:
        n22b(&lbuf[IHEX_OFF_DATA], &tmp_high);
        n22b(&lbuf[IHEX_OFF_DATA+2], &tmp_low);
        if (tmp_high || tmp_low) 
          xerr_errx(1, "line %d: fatal, non 0 ELAR record not supported.",
            lineno);
        break;

      case IHEX_REC_DATA:
        /* decode 16 bit load address */
        n22b(&lbuf[IHEX_OFF_LOAD_OFFSET_HIGH], &h_load_high);
        n22b(&lbuf[IHEX_OFF_LOAD_OFFSET_LOW], &h_load_low);

        /* expected load address if linear */
        tmp_load_offset = buf_load_offset + ld_buf_len;

        /* new load address */
        h_load_offset = (uint16_t)h_load_high<<8 | h_load_low;

        /*
         * if the new load address is not linear (ie memory hole)
         * then force a upload bytes in buffer -- this will only
         * occurr when less than 32 bytes remain to be uploaded.
         */
        if (tmp_load_offset != h_load_offset) {

          if (verbose >= 2)
          printf(
            "buf_load_offset=%d tmp_load_offset=%d h_load_offset=%d line=%d\n",
            buf_load_offset, tmp_load_offset, h_load_offset, lineno);

          /* if bytes to send */
          if (ld_buf_len) {

            if ((r = htsoft_v1bl_upload(pic_fd, buf_load_offset, ld_buf,
              ld_buf_len, verbose, max_retries)) < 0)
              xerr_errx(1, "line %d: fatal htsoft_v1bl_upload() failed.");

              ld_buf_len -= r;
          }

          /* sanity */
          if (ld_buf_len)
            xerr_errx(1, "fatal: ld_buf_len=%d != 0", ld_buf_len);

          /* load offset of next bytes is cur + num bytes written */
          buf_load_offset = h_load_offset;

        }

        /* store next record */
        for (i = 0; i < h_reclen; ++i) {
          n22b(&lbuf[IHEX_OFF_DATA+(i<<1)], &tmp_low);
          ld_buf[ld_buf_len++] = tmp_low;
        }

        break;

      default:
        xerr_errx(1, "line %d: fatal, unknown record type 0x%2.2X.", lineno,
          (int)h_rectype);
        break;

    } /* switch */

    /* 32 bytes (optimal) or EOF + some bytes to initiate upload to PIC */
    while (1) {

      /*
       * if there are at least 32 bytes then upload to PIC
       * if EOF then force upload
       */
      if ((got_eof && ld_buf_len) || (ld_buf_len >= 32)) {

        if ((r = htsoft_v1bl_upload(pic_fd, buf_load_offset, ld_buf,
          ld_buf_len, verbose, max_retries)) < 0)
          xerr_errx(1, "line %d: fatal htsoft_v1bl_upload() failed.", lineno);

        /* move trailing bytes to start of buffer */
        bcopy(&ld_buf[r], ld_buf, ld_buf_len - r);
        ld_buf_len -= r;

        /* load offset of next bytes is cur + num bytes written */
        buf_load_offset += r;

      } else {

        break;

      }

    } /* while */

  } /* !feof(stdin) */

  if (!got_eof)
    xerr_warnx("Warning: Short file, no EOF.");
 
  if (htsoft_v1bl_done(pic_fd, verbose, max_retries,
    ignore_last_wok_timeout) < 0)
    xerr_errx(1, "htsoft_v1bl_done(): failed");

  close(pic_fd);

  exit(0);

} /* main */

/*
 * function: n2b()
 *
 * convert ASCII hex nybble to binary byte 
 *
 * *h input ASCII
 * *b output binary
 *
 * returns  0 success
 *         <0 failure
 *
 */
int n2b(char *h, u_char *b)
{
  *b = 0;

  if (*h >= '0' && *h <= '9')
    *b = *h - '0';
  else if (*h >= 'a' && *h <= 'f')
    *b = *h - 'a' + 10;
  else if (*h >= 'A' && *h <= 'F')
    *b = *h - 'A' + 10;
  else 
    return -1; /* fail */

  return 0; /* success */

} /* n2b */

/*
 * function: n2b()
 *
 * convert 2 ASCII hex nybbles to binary byte 
 *
 * *h input ASCII
 * *b output binary
 *
 * returns  0 success
 *         <0 failure
 *
 */
int n22b(char *h, u_char *b)
{
  u_char b1, b2;

  if (n2b(h, &b1) < 0)
    return -1; /* fail */

  ++h;

  if (n2b(h, &b2) < 0)
    return -1; /* fail */

  *b = (b1<<4)|b2;

  return 0; /* success */

} /* n22b */

/*
 * function: htsoft_v1bl_idack
 *
 * search for htsoft v1 PIC bootloader on fd.
 * IDENT is sent until IDACK is returned.  Other bytes are ignored.
 *
 * function will not return until IDACK is received.
 *
 * fd      - serial com port
 * verbose - verbosity level
 *
 * returns  0 success
 *         <0 failure
 *
 */
int htsoft_v1bl_idack(int fd, int verbose)
{
  uint8_t t,r;
  int n;

  if (verbose) {
    printf("Waiting for bootloader..");
    fflush(stdout);
  }

  t = HTSOFT_V1BL_IDENT;

  for (;;) {

    if (verbose) {
      printf(".");
      fflush(stdout);
    }

    if (write(fd, &t, 1) < 0)
      xerr_err(1, "write()");

    if ((n = read(fd, &r, 1)) < 0)
      xerr_err(1, "read()");

    /* timeout? */
    if (n == 0)
      continue;

    if ((n == 1) && (r == HTSOFT_V1BL_IDACK))
      break;

    /* unknown */
    if (verbose >= 2) {
      printf("%2.2X", (int)r);
      fflush(stdout);
    } else if (verbose >= 1) {
      printf("T");
      fflush(stdout);
    }

  } /* forever */

  if (verbose) {
    printf("\n");
    fflush(stdout);
  }

  return 0;

} /* htsoft_v1bl_idack */

/*
 * function: htsoft_v1bl_upload
 *
 * upload buf_len bytes from buf on fd at load offset load_offset.
 * Retry block max_retries times.  Indicate progress/debugging with
 * verbose level.  htsoft_v1bl_idack() must be called before this
 * function and htsoft_v1bl_done() must be called after the last block
 *
 * The PIC downloader firmware has a maximum receive buffer size of
 * 32 bytes, if more than 32 bytes are available only the first 32 are
 * sent.  The caller is responsible for send buffer management when
 * more than 32 bytes or an odd number of bytes are requested.
 * When an odd number of bytes is available to send, the last byte
 * is not sent as it can not be swapped.
 * 
 * fd          - serial com port
 * load_offset - program address for bufer
 *               note load offset is sent >> 1 as the PIC uses two bytes
 *               per word.
 * buf         - send buffer.  Note the PIC expects the two bytes in each
 *               word swapped from the hex file order.
 * buf_len     - number of bytes to send.
 *
 * verbose     - verbosity level
 *
 * max_retries - maximum number of times to resend a block
 *
 * returns <0 failure
 *         >0 bytes sent successfully
 *
 */
int htsoft_v1bl_upload(int fd, uint16_t load_offset, uint8_t *buf,
  uint8_t buf_len, int verbose, int max_retries)
{
  uint8_t bytes_to_send, setup_buf[5], send_buf[32], r1, r2, csum;
  int n, i, retries, good_write;

  bytes_to_send = (buf_len >= 32) ? 32 : buf_len;

  /*
   * each PIC word is two bytes
   * The hex file is byte oriented a word could potentially span
   * two hex records...
   *
   */
  if (bytes_to_send & 0x1) {
    xerr_errx(1, "bytes_to_send is odd...");
    bytes_to_send &= 0xFE;
  }

  /* compute checksum */
  for (i = 0, csum = 0; i < bytes_to_send; ++i)
    csum += buf[i];

  if (verbose >= 2) {
    printf("\nupload block: load_offset=0x%4.4X bytes_to_send=%d\n",
    load_offset, (int)bytes_to_send);
  }

  /* each word on a PIC is two bytes in the hex file */
  load_offset = load_offset >>1;

  setup_buf[0] = HTSOFT_V1BL_WRITE;
  setup_buf[1] = (load_offset & 0xFF00) >> 8;
  setup_buf[2] = (load_offset & 0x00FF);
  setup_buf[3] = bytes_to_send;
  setup_buf[4] = csum;

  /* reverse byte order */
  for (i = 0; i < bytes_to_send; i += 2) {
    send_buf[i] = buf[i+1];
    send_buf[i+1] = buf[i];
  }

  good_write = 0;

  for (retries = 0; retries < max_retries; ++ retries) {

    if (verbose) {
      printf("D");
      fflush(stdout);
    }

    /* setup data block */
    if (write(fd, setup_buf, 5) < 0)
      xerr_err(1, "write()");

    if (verbose >= 2)
      printf("write: cmd=%2.2X load=%2.2X%2.2X bytes=%2.2X csum=%2.2X\n",
        (int)setup_buf[0], (int)setup_buf[1], (int)setup_buf[2],
        (int)setup_buf[3], (int)setup_buf[4]);

    /* data block */
    if (write(fd, send_buf, bytes_to_send) < 0)
      xerr_err(1, "write()");

    if (verbose >= 2) {
      printf("write: data=");
      for (i = 0; i < bytes_to_send; ++i)
        printf("%2.2X", send_buf[i]);
      printf("\n");
    }

    /* get reply */
    if ((n = read(fd, &r1, 1)) < 0)
      xerr_err(1, "read()");

    /* timeout? */
    if (n == 0)
      xerr_errx(1, "Timeout waiting on DATA_{BAD,OK}.");

    /* bad data, retry? */
    if (r1 == HTSOFT_V1BL_DATA_BAD) {
      if (verbose) {
        printf("x");
        fflush(stdout);
      }
      continue;
    }

    /* unknown reply? */
    if (r1 != HTSOFT_V1BL_DATA_OK)
      xerr_errx(1, "Unexpected reply 0x%2.2X, not DATA_{BAD,OK}.", (int)r1);

    /* get reply */
    if ((n = read(fd, &r2, 1)) < 0)
      xerr_err(1, "read()");

    /* timeout? */
    if (n == 0)
      xerr_errx(1, "Timeout waiting on {WOK,WBAD}.");

    /* write bad, retry? */
    if (r2 == HTSOFT_V1BL_WBAD) {
      if (verbose) {
        printf("X");
        fflush(stdout);
      }
      continue;
    }

    /* data accepted? */
    if (r2 == HTSOFT_V1BL_WOK) {
      good_write = 1;
      break;
    }

    xerr_errx(1, "Unexpected reply 0x%2.2X, not {WOK,WBAD}", (int)r2);

  } /* DATA header */

  if (!good_write)
    xerr_errx(1, "Retries exceeded in data block write.");

  return bytes_to_send;

} /* htsoft_v1bl_upload */

/*
 * function: htsoft_v1bl_done
 *
 * send the "done" command on fd and wait for WOK (success).
 *
 * function will not return until WOK is received.
 *
 * fd                 - serial com port
 * verbose            - verbosity level
 * retries            - number of retries
 * ignore_wok_timeout - ignore last WOK -- some devices do not send this
 *
 * returns  0 success
 *         <0 failure
 *
 */
int htsoft_v1bl_done(int fd, int verbose, int retries, int ignore_wok_timeout)
{
  uint8_t t,r;
  int n, good_write, i, timeout;

  t = HTSOFT_V1BL_DONE;
  good_write = 0;
  timeout = 0;

  for (i = 0; i < retries; ++i) {

    if (verbose) {
      printf("w");
      fflush(stdout);
    }

    if (write(fd, &t, 1) < 0)
      xerr_err(1, "write()");

    if ((n = read(fd, &r, 1)) < 0)
      xerr_err(1, "read()");

    /* some devices may not send this */
    if (ignore_wok_timeout && n == 0) {
      timeout = 1;
      good_write = 1;
      break;
    }

    /* timeout? */
    if (n == 0)
      continue;

    if ((n == 1) && (r == HTSOFT_V1BL_WOK)) {
      good_write = 1;
      break;
    }

    /* unknown */
    if (verbose >= 2) {
      printf("DONE: reply=%2.2X, expecting %2.2X", (int)r,
        (int)HTSOFT_V1BL_WOK);
      fflush(stdout);
    } else if (verbose >= 1) {
      printf("T");
      fflush(stdout);
    }

  } /* forever */

  if (verbose && good_write) {
    printf("F\n");
    fflush(stdout);
  }

  if (verbose && !good_write)
    printf("PIC reset failed.\n");
  else if (verbose && good_write && ignore_wok_timeout && timeout)
    printf("PIC reset sent, ignored last WOK timeout.\n");
  else
    printf("PIC reset complete.\n");

  if (good_write)
    return 0; /* success */
  else
    return -1; /* fail */

} /* htsoft_v1bl_done */

void help(void)
{
  fprintf(stderr,
    "htsoft-downloader [-hi?v] [-f serial_device] [-r retries]\n");
  fprintf(stderr,
    "                         [-t timeout (.1 second/timeout)] [-v verbose_level]\n");
} /* help */

