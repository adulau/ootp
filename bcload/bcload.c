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
 * Ported from ZeitControl bcload.bas and download.bas sample source
 *
 *      $Id: bcload.c 90 2009-12-28 02:44:52Z maf $
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include "scr.h"
#include "sccmd.h"
#include "str.h"
#include "xerr.h"
#include "otpsc.h"
#include "otplib.h"

#if defined(__FreeBSD__)
#include <sys/endian.h>
#endif

#if defined(__DARWIN_UNIX03)
#include <sys/_endian.h>
#endif

#define BZS(A) bzero(A, sizeof A);

#define SWAP32(x) x = \
         ((((x)&0xff)<<24) |\
         (((x)&0xff00)<<8) |\
         (((x)&0xff0000)>>8) |\
         (((x)>>24)&0xff));

#define SWAP16(x) x = \
    ( (((x)&0xff)<<8) | (((x)&0xff00)>>8) );

static int debug;

void help(void);

struct bcimg {
  char *fname;
  uint8_t *img_buf, *img_cur, *img_end;
  struct stat img_stat;
  int verbose;
}; /* bcimg */

void bcimg_open(struct bcimg *bcimg, char *fname, int verbose);
void bcimg_close(struct bcimg *bcimg);
int bcimg_eof(struct bcimg *bcimg);
void bcimg_read_byte(struct bcimg *bcimg, uint8_t *dat);
void bcimg_read_int(struct bcimg *bcimg, uint16_t *dat);
void bcimg_read_long(struct bcimg *bcimg, int32_t *dat);
void bcimg_read_section_name(struct bcimg *bcimg, uint8_t *sname);
void bcimg_read_string(struct bcimg *bcimg, uint8_t **dat, uint32_t len);
void bcimg_skip_to_section(struct bcimg *bcimg, char *section);
void bcimg_read_version_section(struct bcimg *bcimg);
void bcimg_check_card_type(struct bcimg *bcimg, uint8_t *sc_version,
  uint8_t sc_version_len);
void bcimg_read_eeprom_section(struct bcimg *bcimg, uint16_t *img_EEAddr,
  uint16_t *img_EELen);

int main(int argc, char **argv)
{
  struct scr_ctx *scrctx;
  struct bcimg bcimg;
  uint32_t chunk_start, bytes_left, chunk_working;
  int32_t sectionLength;
  uint16_t EEStart, EELen, EEChunkSize, img_EEAddr, img_EELen;
  uint16_t chunk_start_word;
  uint16_t img_nWrites, img_nCRCs, img_EELoadAddr;
  uint16_t img_EECRCAddr, img_EECRCLen, img_EECRC, img_SCCRC;
  uint8_t img_state, *img_pgmdata, img_EELoadLen, sname[4];
  uint8_t sc_EEStart[2], sc_EELen[2], sc_EEAddr[2];
  uint8_t sc_state, sc_version[256], sc_version_len, sc_CRC[2];
  int i, r;
  int list_readers, verbose, paranoid, force_test;
  char *reader, *endptr, *c, *img_fname;

  /* init xerr */
  xerr_setid(argv[0]);

  force_test = 0;
  paranoid = 1;
  debug = 0;
  verbose = 0;
  reader = (char*)0L;
  list_readers = 0; /* no */
  scrctx = (struct scr_ctx*)0L;
  img_fname = "HOTPC.IMG";
  bzero(&bcimg, sizeof bcimg);

  while ((i = getopt(argc, argv, "d:f:hlpr:tv?")) != -1) {

    switch (i) {

      case 'd':
        debug = strtoul(optarg, &endptr, 0);
        if (*endptr)
          xerr_errx(1, "strtoul(%s): failed at %c.", optarg, *endptr);
        break;

      case 'f':
        img_fname = optarg;
        break;

      case 'h':
      case '?':
        help();
        exit(0);
        break; /* notreached */

      case 'l':
        list_readers = 1;
        break;

      case 'p':
        paranoid = 0;
        break;

      case 'r':
        reader = optarg;
        break;

      case 't':
        force_test = 1;
        break;

      case 'v':
        verbose = 1;
        break;

    } /* switch */

  } /* while getopt() */

  /* create Smart Card context */
  if (!(scrctx = scr_ctx_new(SCR_READER_EMBEDDED_ACR30S|SCR_READER_PCSC,
    debug))) {
    xerr_errx(1, "scr_ctx_new(): failed");
  }

  /* list availabls SC readers? */
  if (list_readers) {

    for (i = 0; i < scrctx->num_readers; ++i)
      printf("%s\n", scrctx->readers[i]);

    goto main_out;

  }

  /* connect to selected SC reader */
  if (scr_ctx_connect(scrctx, reader) < 0)
    xerr_errx(1, "scr_ctx_connect(): failed");

  /* Get current state of SC */
  if ((r = sccmd_BCGetState(scrctx, &sc_state, sc_version,
    &sc_version_len)) < 0)
    xerr_errx(1, "sccmd_BCGetState(): failed.");

  if (r)
    xerr_errx(1, "sccmd_BCGetState(): fatal.");

  /*
   * Enahnced cards have version length of 2, others have an ASCII string.
   * 
   * Only support hardware on hand.
   *
   */
  if (sc_version_len != 2)
    xerr_errx(1, "Firmware loader locked to enhanced cards.");

  /*
   * all cards with major version 3 are probably okay, be paranoid
   * here to avoid bricking hardware 
   */
  if ((sc_version[0] != 0x3) || (sc_version[1] != 0x9))
    xerr_errx(1, "Firmware loader locked to ZC3.9 cards.");

  if (sc_state == BC_ESTATE_NEW)
    c = BC_STATE_NEW_STR;
  else if (sc_state == BC_ESTATE_LOAD)
    c = BC_STATE_LOAD_STR;
  else if (sc_state == BC_ESTATE_TEST)
    c = BC_STATE_TEST_STR;
  else if (sc_state == BC_ESTATE_RUN)
    c = BC_STATE_RUN_STR;
  else
    c = "fatal";

  if (verbose)
    printf("Card/State: ZC%X.%X %s\n", (int)sc_version[0],
      (int)sc_version[1], c);

  /* a card in state RUN can not be programmed */
  if (sc_state == BC_ESTATE_RUN)
    xerr_errx(1, "Card in state run, not programmable.");

  /*
   * The CLEAR EEPROM command must be split into chunks that the card can
   * process within its time-out, which is 1.6 seconds if the minor version
   * is 1, 2, 3, or 5, otherwise 12.8 seconds
   *
   */

   if ((sc_version_len == 2) &&
     ((sc_version[1] <= 3) || (sc_version[1] == 5)))
     EEChunkSize = 0x0400;
   else
     EEChunkSize = 0x2000;

   if (verbose)
     printf("EEChunkSize=%2.2" PRIx16 "\n", EEChunkSize);

  /* all bcimg_* functions will exit on failure */

  /* open and read image file to memory, perform sanity checks */
  bcimg_open(&bcimg, img_fname, verbose);

  /* skip to VERS section */
  bcimg_skip_to_section(&bcimg, "VERS");

  /* process version information */
  bcimg_read_version_section(&bcimg);

  /* skip to VMTP section */
  bcimg_skip_to_section(&bcimg, "VMTP");

  /* verify image file can be downloaded to card */
  bcimg_check_card_type(&bcimg, sc_version, sc_version_len);

  /* skip to EEPR section */
  bcimg_skip_to_section(&bcimg, "EEPR");

  /* set enhanced card to LOAD state */
  sc_state = BC_ESTATE_LOAD;

  if ((r = sccmd_BCSetState(scrctx, sc_state)) < 0)
    xerr_errx(1, "sccmd_BCSetState(): failed.");

  if (r)
    xerr_errx(1, "sccmd_BCSetState(): fatal.");

  if (verbose)
    printf("BCSetState: load\n");

  /* reset SC */
  if (scr_ctx_reset(scrctx) < 0)
    xerr_errx(1, "scr_ctx_reset(): failed.");

  if (verbose)
    printf("SC: Reset\n");

  /* get SC EEProm size */
  if ((r = sccmd_BCEEPromSize(scrctx, sc_EEStart, sc_EELen)) < 0)
    xerr_errx(1, "sccmd_BCEEPromSize(): failed.");

  if (r)
    xerr_errx(1, "sccmd_BCEEPromSize(): fatal.");

  EEStart = ((uint16_t)sc_EEStart[0]<<8) | sc_EEStart[1];
  EELen = ((uint16_t)sc_EELen[0]<<8) | sc_EELen[1];

  if (verbose)
    printf("EEStart=%2.2" PRIx16 ",EELen=%2.2" PRIx16 "\n", EEStart, EELen);

  /* read the EEPROM section of the image file */
  bcimg_read_eeprom_section(&bcimg, &img_EEAddr, &img_EELen);

  if (verbose)
    printf("imgAddr=%2.2" PRIx16 ",imgLen=%2.2" PRIx16 "\n",
    img_EEAddr, img_EELen);

  if ((img_EEAddr != EEStart) || (img_EELen != EELen))
    xerr_errx(1, "EEProm image area on SC and image file mismatch.");

  /*
   * erase EEProm on SC.  Break work into chunks if necessary.
   */

  chunk_start = img_EEAddr;
  chunk_start_word = chunk_start & 0x0000FFFF;
  bytes_left = img_EELen;

  while (bytes_left) {

    chunk_working = bytes_left;

    if (chunk_working > EEChunkSize)
      chunk_working = EEChunkSize;

    if (verbose)
      printf("Clear: addr=%2.2" PRIx16 ",len=%2.2" PRIx32 "\n",
        chunk_start_word, chunk_working);

    sc_EEAddr[0] = (chunk_start_word&0xFF00)>>8;
    sc_EEAddr[1] = (chunk_start_word&0x00FF);
    sc_EELen[0] = (chunk_working&0xFF00)>>8;
    sc_EELen[1] = (chunk_working&0x00FF);

    if ((r = sccmd_BCClearEEProm(scrctx, sc_EEAddr, sc_EELen)) < 0)
      xerr_errx(1, "sccmd_BCClearEEprom(): failed.");

    if (r)
      xerr_errx(1, "sccmd_BCClearEEProm(): fatal.");

    if (verbose)
      printf("BCClearEEProm: success\n");

    chunk_start += chunk_working;
    bytes_left -= chunk_working;
    chunk_start_word = chunk_start & 0x0000FFFF;

  } /* erase flash */

  /* reset SC */
  if (scr_ctx_reset(scrctx) < 0)
    xerr_errx(1, "scr_ctx_reset(): failed.");

  if (verbose)
    printf("SC: Reset\n");

  /* skip to LOAD section */
  bcimg_skip_to_section(&bcimg, "LOAD");
  bcimg_read_section_name(&bcimg, sname);

  /* LOAD section length */
  bcimg_read_long(&bcimg, &sectionLength);

  if (sectionLength < 5)
    xerr_errx(1, "Fatal: LOAD sectionLength < 5");

  /* state of card after programming */
  bcimg_read_byte(&bcimg, &img_state);
  -- sectionLength;

  /* number of writes to download image */
  bcimg_read_int(&bcimg, &img_nWrites);
  sectionLength -= 2;

  /* number of sections to compute CRC on */
  bcimg_read_int(&bcimg, &img_nCRCs);
  sectionLength -= 2;

  /*
   * program the image in chunks set by image file 
   */
  while (img_nWrites != 0) {

    img_nWrites -= 1;

    bcimg_read_int(&bcimg, &img_EELoadAddr);
    bcimg_read_byte(&bcimg, &img_EELoadLen);

    if (sectionLength < (img_EELoadLen+3))
      xerr_errx(1, "Fatal: LOAD/writing sectionLength=%" PRId32 \
        " < img_EELoadLen+3=%" PRId8, sectionLength, img_EELoadLen+3);

    sectionLength -= (img_EELoadLen+3);

    bcimg_read_string(&bcimg, &img_pgmdata, (uint32_t)img_EELoadLen);

    sc_EEAddr[0] = (img_EELoadAddr&0xFF00)>>8;
    sc_EEAddr[1] = (img_EELoadAddr&0x00FF);
    sc_EELen[0] = img_EELoadLen;

    if (verbose)
      printf("EEWRITE: nWrites=%" PRIu16 ",addr=%" PRIx16 ",len=%" PRIx8 "\n",
        img_nWrites, img_EELoadAddr, img_EELoadLen);

    if ((r = sccmd_BCWriteEEProm(scrctx, sc_EEAddr, sc_EELen,
      img_pgmdata)) < 0)
      xerr_errx(1, "sccmd_BCWriteEEProm(): failed.");

    if (r)
      xerr_errx(1, "sccmd_BCWriteEEProm(): fatal.");

  } /* img_nWrites */

  /*
   * get CRC's of image file and compare to those computed by the SC
   */
  while (img_nCRCs != 0) {

    img_nCRCs -= 1;

    if (sectionLength < 6)
      xerr_errx(1, "Fatal: LOAD/CRC sectionLength < 6");

    sectionLength -= 6;

    bcimg_read_int(&bcimg, &img_EECRCAddr);
    bcimg_read_int(&bcimg, &img_EECRCLen);

    bcimg_read_int(&bcimg, &img_EECRC);

    if (verbose)
      printf("EECRC: nWrites=%" PRIu16",addr=%2.2" PRIx16 ",len=%2.2" PRIx16 ",imgCRC=%2.2" PRIx16 "\n",
        img_nCRCs, img_EECRCAddr, img_EECRCLen, img_EECRC);

    sc_EEAddr[0] = (img_EECRCAddr&0xFF00)>>8;
    sc_EEAddr[1] = (img_EECRCAddr&0x00FF);

    sc_EELen[0] = (img_EECRCLen&0xFF00)>>8;
    sc_EELen[1] = (img_EECRCLen&0x00FF);

    if ((r = sccmd_BCEEPromCRC(scrctx, sc_EEAddr, sc_EELen, sc_CRC)) < 0)
      xerr_errx(1, "sccmd_BCEEPromCRC(): failed.");

    img_SCCRC = (uint16_t)sc_CRC[0]<<8 | sc_CRC[1];

    if (r)
      xerr_errx(1, "sccmd_BCEEPromCRC(): fatal.");

    if (verbose)
      printf("EECRC: SCCRC=%" PRIx16 "\n", img_SCCRC);

    if (img_SCCRC != img_EECRC)
      xerr_errx(1, "CRC: failed.");


  } /* img_nCRCs */

  /* all bytes in image file should be consumed */
  if (!bcimg_eof(&bcimg))
    xerr_errx(1, "Fatal, trailing bytes after EEProm CRC.");

  /* force card more to TEST via command line? */
  if (force_test)
    sc_state = BC_ESTATE_TEST;
  else
    sc_state = img_state;

  /* set SC state */
  if ((r = sccmd_BCSetState(scrctx, sc_state)) < 0)
    xerr_errx(1, "sccmd_BCSetState(): failed.");

  if (r)
    xerr_errx(1, "sccmd_BCSetState(): fatal.");

  if (verbose) {

    if (sc_state == BC_ESTATE_NEW)
      c = BC_STATE_NEW_STR;
    else if (sc_state == BC_ESTATE_LOAD)
      c = BC_STATE_LOAD_STR;
    else if (sc_state == BC_ESTATE_TEST)
      c = BC_STATE_TEST_STR;
    else if (sc_state == BC_ESTATE_RUN)
      c = BC_STATE_RUN_STR;
    else
      c = "fatal";

    printf("BCSetState: %s\n", c);

  }

  /* reset SC one last time */
  if (scr_ctx_reset(scrctx) < 0)
    xerr_errx(1, "scr_ctx_reset(): failed.");

  if (verbose)
    printf("SC: Reset\n");

main_out:

  scr_ctx_free(scrctx);
  bcimg_close(&bcimg);

  exit (0);

} /* main */

void help(void)
{
  fprintf(stderr, "bcload [hlptv?] [-d debug_level] [-f fname] [-r reader]\n");
  fprintf(stderr, "        -h : help\n");
  fprintf(stderr, "        -l : list SC readers\n");
  fprintf(stderr, "        -t : force to TEST state\n");
} /* help */

void bcimg_open(struct bcimg *bcimg, char *fname, int verbose)
{
  int32_t fileLength;
  int fd, n;

  bzero(bcimg, sizeof *bcimg);

  bcimg->verbose = verbose;

  n = strlen(fname);

  if (!(bcimg->fname = (char*)malloc(n+1)))
    xerr_err(1, "malloc(%s)", fname);

  strcpy(bcimg->fname, fname);

  if (stat(fname, &bcimg->img_stat) < 0)
    xerr_err(1, "stat(%s)", bcimg->fname);

  if (!(bcimg->img_buf = (uint8_t*)malloc(bcimg->img_stat.st_size)))
    xerr_err(1, "malloc(%" PRId64 ")", (int64_t)bcimg->img_stat.st_size);

  if ((fd = open(bcimg->fname, O_RDONLY)) < 0)
    xerr_err(1, "open(%s)", bcimg->fname);

  if (read(fd, bcimg->img_buf, bcimg->img_stat.st_size) !=
    bcimg->img_stat.st_size)
    xerr_err(1, "read(%s)", bcimg->fname);

  if (close(fd) < 0)
    xerr_err(1, "close(%s)", bcimg->fname);

  bcimg->img_cur = bcimg->img_buf;
  bcimg->img_end = bcimg->img_cur + bcimg->img_stat.st_size;

  /* check signature */
  if (bcmp(bcimg->img_cur, "ZCIF", 4) && bcmp(bcimg->img_cur, "ZCDF", 4))
    xerr_errx(1, "%s: signature failed", bcimg->fname);

  /* consume signature */
  bcimg->img_cur += 4;

  /* read file length */
  bcimg_read_long(bcimg, &fileLength);

  if ((fileLength+4+4) != bcimg->img_stat.st_size)
    xerr_errx(1, "%s: stored size %" PRIu32 " != file size %" PRIu64,
      bcimg->fname, fileLength+4+4, (uint64_t)bcimg->img_stat.st_size);

} /* bcimg_open */

void bcimg_close(struct bcimg *bcimg)
{

  if (!bcimg)
    xerr_errx(1, "bcimg invalid");

  if (bcimg->fname)
    free (bcimg->fname);
  if (bcimg->img_buf)
    free (bcimg->img_buf);

} /* bcimg_close */

int bcimg_eof(struct bcimg *bcimg)
{
  if (bcimg->img_cur == bcimg->img_end)
    return 1;
  return 0;
} /* bcimg_eof */

void bcimg_read_section_name(struct bcimg *bcimg, uint8_t *sname)
{
  if (bcimg->img_cur+4 > bcimg->img_end)
    xerr_errx(1, "bcimg_read_section_name(): seek past EOF");
  sname[0] = *bcimg->img_cur++;
  sname[1] = *bcimg->img_cur++;
  sname[2] = *bcimg->img_cur++;
  sname[3] = *bcimg->img_cur++;
} /* bcimg_read_section_name */

void bcimg_read_byte(struct bcimg *bcimg, uint8_t *dat)
{
  if (bcimg->img_cur > bcimg->img_end)
    xerr_errx(1, "bcimg_read_byte(): seek past EOF");
  *dat = *bcimg->img_cur++;
} /* bcimg_readbyte */

void bcimg_read_int(struct bcimg *bcimg, uint16_t *dat)
{
  if (bcimg->img_cur+2 > bcimg->img_end)
    xerr_errx(1, "bcimg_read_int(): seek past EOF");
  *dat = (uint16_t)*(bcimg->img_cur)<<8 | *(bcimg->img_cur+1);
  bcimg->img_cur += 2;
#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP16(*dat)
#endif
} /* bcimg_read_int */

void bcimg_read_long(struct bcimg *bcimg, int32_t *dat)
{
  if (bcimg->img_cur+4 > bcimg->img_end)
    xerr_errx(1, "bcimg_read_long(): seek past EOF");
  *dat = (uint32_t)*(bcimg->img_cur)<<24 | (uint32_t)*(bcimg->img_cur+1)<<16 |
         (uint32_t)*(bcimg->img_cur+2)<<8 | *(bcimg->img_cur+3);
  bcimg->img_cur += 4;
#if BYTE_ORDER == LITTLE_ENDIAN
  SWAP32(*dat)
#endif
} /* bcimg_read_long */

void bcimg_read_string(struct bcimg *bcimg, uint8_t **dat, uint32_t len)
{
  if (bcimg->img_cur+len > bcimg->img_end)
    xerr_errx(1, "bcimg_read_string(): seek past EOF");
  *dat = bcimg->img_cur;
  bcimg->img_cur += len;
} /* bcimg_read_string */

void bcimg_skip_to_section(struct bcimg *bcimg, char *section)
{
  int32_t sectionLength;

  while (1) {

    if (bcimg->img_cur+4 > bcimg->img_end)
      xerr_errx(1, "bcimg_skip_to_section(): seek past EOF @ name.");

    /* requested section? */
    if (!bcmp(bcimg->img_cur, section, 4))
      return; 

    if (bcimg->verbose)
      printf("Skipping section %c%c%c%c\n",
        *bcimg->img_cur, *(bcimg->img_cur+1), *(bcimg->img_cur+2),
        *(bcimg->img_cur+3));

    /* skip to section length */
    bcimg->img_cur += 4;

    if (bcimg->img_cur+4 > bcimg->img_end)
      xerr_errx(1, "bcimg_skip_to_section(): seek past EOF @ len.");

    /* section length */
    bcimg_read_long(bcimg, &sectionLength);

    if (bcimg->img_cur+sectionLength > bcimg->img_end)
      xerr_errx(1, "bcimg_skip_to_section(): seek past EOF @ len.");

    bcimg->img_cur += sectionLength;

  } /* skipping sections */
  
} /* bcimg_skip_to_section */

void bcimg_read_version_section(struct bcimg *bcimg)
{
  int32_t sectionLength;
  uint8_t *version;

  /* skip "VERS" */
  bcimg->img_cur += 4;

  bcimg_read_long(bcimg, &sectionLength);

  if (sectionLength == 2)
    xerr_errx(1, "bcimg_read_version_section(): Obsolete image file.");

  if (sectionLength != 4)
    xerr_errx(1, "bcimg_read_version_section(): Bad image file.");

  bcimg_read_string(bcimg, &version, 4);

  /*
   * first two bytes are version of compiler which created file.
   * Must be greater than 5.07
   */
  if ((version[0] < 5) || ((version[0] == 5) && (version[1] < 7)))
    xerr_errx(1, "bcimg_read_version_section(): Obselete image file.");

  /*
   * next two bytes are version number of oldest software that
   * can read the image file.  Must be > 5.22
   */
  if ((version[2] > 5) || ((version[2] == 5) && (version[3] > 71)))
    xerr_errx(1, "bcimg_read_version_section(): Untested image file version.");

} /* bcimg_read_version_section */

void bcimg_check_card_type(struct bcimg *bcimg, uint8_t *sc_version,
  uint8_t sc_version_len)
{
  int32_t sectionLength;
  uint8_t *imgCardType;

  /* skip "VMTP" */
  bcimg->img_cur += 4;

  bcimg_read_long(bcimg, &sectionLength);

  bcimg_read_string(bcimg, &imgCardType, sectionLength);

  if (imgCardType[0] == 0)
    xerr_errx(1,
      "bcimg_check_card_type(): Error, Image contains terminal program");

  if ((sc_version_len == 2) && (sectionLength == 2) &&
    (sc_version[0] == imgCardType[0]) &&
    (sc_version[1] == imgCardType[1]))
    return; /* success */

  xerr_errx(1, "bcimg_check_card_type(): Image and SC do not match.");

} /* bcimg_check_card_type */

void bcimg_read_eeprom_section(struct bcimg *bcimg, uint16_t *img_EEAddr,
  uint16_t *img_EELen)
{
  int32_t sectionLength;

  /* skip "EEPR" */
  bcimg->img_cur += 4;

  bcimg_read_long(bcimg, &sectionLength);

  if (sectionLength < 4)
    xerr_errx(1, "read_eeprom_section(): sectionLength < 4");

  bcimg_read_int(bcimg, img_EEAddr);
  bcimg_read_int(bcimg, img_EELen);

  sectionLength -= 4;

  /* skip to next section */
  if ((bcimg->img_cur + sectionLength) > bcimg->img_end)
    xerr_errx(1, "bcimg_read_eeprom_section(): seek past EOF @ skip.");

  bcimg->img_cur += sectionLength;

} /* bcimg_read_eeprom_section */

