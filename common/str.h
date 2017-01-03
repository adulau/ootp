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
 *      $Id: str.h 85 2009-12-28 00:05:02Z maf $
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#define u_int unsigned int
#define u_char unsigned char

int chr_ishex(char d);
char chr_hex_l(u_char h);
char chr_hex_r(u_char h);
u_char chr_hex_decode(char h);
int str_hex_dump(char *buf, u_char *b, size_t n);
int str_hex_decode(char *in, size_t in_len, u_char *out, size_t out_len);
void str_ftoc(char *buf, char *f, size_t n);
int str_input(const char *prompt, char *buf, size_t buf_size, int flags);
int str_safe(char *input, size_t len);
int str_uint32toa(char *s, uint32_t u);

char *str_lookup8(char *list[], uint8_t id, uint8_t min, uint8_t max);

char *str_flag8(char *list[], uint8_t flags, uint8_t bits, char *tmpbuf,
  size_t tmpbuf_size);

int str_setflag8(char *list[], uint8_t *flags, char *s, uint8_t min,
  uint8_t max);

int str_find8(char *list[], uint8_t *id, char *s, uint8_t min, uint8_t max);

#define STR_FLAGS_ECHO_OFF 0x1

#define STR_UINT32_LEN     11  /* 2^32-1=4294967295 + NULL = 11 bytes */


