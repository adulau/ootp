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
 *      $Id: str.c 15 2009-11-26 18:29:41Z maf $
 */

#include <termios.h>
#if HAVE_STRINGS_H
 #include <strings.h>
#endif
#if HAVE_STRING_H
  #include <string.h>
#endif
#include <stdio.h>
#include "str.h"

/*
 * function: chr_hex_l()
 *
 * convert ASCII hex left digit to binary
 *
 * arguments:
 *  h - 8 bit value to convert
 *
 * example, i = 15:
 *   i = chr_hex_r(0xF0)
 *
 * returns binary representation of left ASCII hex character h
 *
 */ 
char chr_hex_l(u_char h)
{
  u_char t;
  t = ((h&0xF0)>>4);
  if (t > 9)
    return (t-10) + 'A';
  return t + '0';
} /* chr_hex_l */

/*
 * function: chr_hex_r()
 *
 * convert ASCII hex right digit to binary
 *
 * example, i = 0:
 *   i = chr_hex_r(0xF0)
 *
 * arguments:
 *  h - 8 bit value to convert
 *
 * returns binary representation of right ASCII hex character h
 *
 */ 
char chr_hex_r(u_char h)
{
  u_char t;
  t = (h&0x0F);
  if (t > 9)
    return (t-10) + 'A';
  return t + '0';
} /* chr_hex_r */

/*
 * function: chr_hex_decode()
 *
 * convert 4 bit ASCII hex to binary
 *
 * example, i = 15
 *   i = chr_hex_decode('F');
 *
 * returns binary representation of ASCII hex character h (0..15)
 *         or 0xFF on error
 *
 */
u_char chr_hex_decode(char h)
{

  if ((h >= '0') && (h <= '9'))
    return h - '0';

  if ((h >= 'A') && (h <= 'F'))
    return h - 'A' + 10;

  if ((h >= 'a') && (h <= 'f'))
    return h - 'a' + 10;

  /* fatal */
  return 0xFF;

} /* chr_hex_decode */

/*
 * function: chr_ishex()
 *
 * example, i = 0
 *   i = ishex('F')
 * example, i = -1
 *   i = ishex('g')
 *
 * returns:
 *    0  d is ASCII hex character
 *   -1  d is not ASCII hex character
 *
 */
int chr_ishex(char d)
{
  if ((d >= '0') && (d <= '9'))
    return 0;
  if ((d >= 'A') && (d <= 'F'))
    return 0;
  if ((d >= 'a') && (d <= 'f'))
    return 0;
  return -1;
} /* chr_ishex */

/*
 * function: str_hex_dump()
 *    
 * dumps n bytes of b into buf as hex digits
 * caller is responsible for allocating buf
 * each input byte translates to two bytes in output buffer + 1 null terminator
 *
 * arguments:
 *  buf - output buffer (allocated by caller)
 *  b   - bit stream to decode
 *  n   - length of b in bytes
 * 
 */
void str_hex_dump(char *buf, u_char *b, size_t n)
{
  int i, j;
  for (i = 0, j = 0; i < n; ++i) {
    buf[j++] = chr_hex_l(*b);
    buf[j++] = chr_hex_r(*b++);
  }
  buf[j] = 0;
}

/*
 * function: str_hex_decode()
 * 
 * decode max of in_len bytes from in as hex, store result in out.
 * out is out_len bytes
 *
 * arguments:
 *  in      - null terminated character string to decode.
 *  in_len  - max hex digits to decode (may be > strlen(in)
 *  out     - decoded bits
 *  out_len - length of out buffer
 *
 * returns: <0 error (non hex digit encountered)
 *           0 successful decode
 *
 */
int str_hex_decode(char *in, size_t in_len, u_char *out, size_t out_len)
{ 
  int i, l;
  unsigned char v, odd;

  bzero(out, out_len);
  l = strlen(in);
  odd = 0;
  out += out_len-1;

  if (l > in_len)
    return -1;

  in += l-1;

  for (i = 0; i < l; ++i) {

    if (*in >= '0' && *in <= '9')
      v = *in - '0';
    else if (*in >= 'a' && *in <= 'f')
      v = *in - 'a' + 10;
    else if (*in >= 'A' && *in <= 'F')
      v = *in - 'A' + 10;
    else return -1;

    if (!odd) {
      *out |= v;
    } else {
      *out |= v<<4;
      --out;
    }

    --in;
    odd = odd ? 0 : 1;

  }

  return 0;

} /* str_hex_decode */

/*
 * function: str_ftoc()
 * 
 * convert fixed length string to null terminated C string.
 * a fixed length string may not have terminating null if it
 * is the max length
 *
 * arguments:
 *  buf - null terminated output buffer (allocated by caller, min n+1 bytes)
 *  f   - fixed length string
 *  n   - max length of f in bytes
 *
 */
void str_ftoc(char *buf, char *f, size_t n)
{
  int i;
  for (i = 0; i < n; ++i)
    if (!(buf[i] = f[i]))
      break;
  buf[i] = 0;
} /* str_ftoc */

/*
 * function: str_input()
 * 
 * input a string of maximum length buf_size-1 characters from stdin,
 * null terminate unless input has overflowed.
 * 
 *
 * arguments:
 *  prompt   - user prompt
 *  buf      - input buffer (allocated by caller)
 *  buf_size - size in bytes of input buffer
 *  flags    - STR_FLAGS_*
 *             STR_ECHO_OFF - disable echo
 *
 * returns: < 0 fatal error
 *          0   success
 *          -2  not all input read, buffer too short
 *
 */
int str_input(const char *prompt, char *buf, size_t buf_size, int flags)
{
  struct termios t;
  int i, r, ret;
  char c;

  ret = -1; /* fail */

  /* sanity check */
  if (buf_size <= 1)
    return -1;

  /* change tty mode? */
  if (flags & STR_FLAGS_ECHO_OFF) {

    if (tcgetattr(STDIN_FILENO, &t) < 0)
      return -1;

    t.c_lflag &= ~ECHO;

  }

  printf("%s", prompt); fflush(stdout);

  i = 0;

  while (1) {

    /* get 1 char */
    if ((r = read(STDIN_FILENO, &c, 1)) < 0)
      goto str_input_out;

    /* EOF? */
    if (r == 0) {
      buf[i] = 0;
      break;
    }

    /* \n */ 
    if (c == '\n') {
      buf[i] = 0;
      break;
    }

    /* copy input to buf, check overflow */
    if ((i+1) == buf_size) {
      ret = -2;
      buf[i] = 0;
      goto str_input_out;
    } else {
      buf[i++] = c;
    }

  } /* forever */

  ret = 0; /* success */

str_input_out:

  /* restore tty? */
  if (flags & STR_FLAGS_ECHO_OFF) {

    if (tcgetattr(STDIN_FILENO, &t) < 0)
      return -1;

    t.c_lflag |= ECHO;

  }

  return ret;

} /* str_input */

/*
 * function: str_safe
 *
 * Ensure length of string is not > len
 * note n is the length of the string
 * where n+1 bytes are required to store
 * it with trailing null.
 *
 * Ensure string is limited to [a-zA-Z0-9.]
 *
 * First invalid character is set to 0.
 *
 * returns "safe" string
 *
 */
int str_safe(char *input, size_t len)
{
  size_t n;
  int ret;

  ret = 0; /* success */

  n = strlen(input);

  /* bounds verification */
  if (n > len) {
    input[len] = 0;
    ret = -1;
  }

  for (n = 0; n < len; ++n) {

    /* a-z */
    if ((input[n] >= 'a') && (input[n] <= 'z'))
      continue;

    /* A-Z */
    if ((input[n] >= 'A') && (input[n] <= 'Z'))
      continue;

    /* 0-9 */
    if ((input[n] >= '0') && (input[n] <= '9'))
      continue;

    /* . */
    if (input[n] == '.')
      continue;

    /* unsafe */

    input[n] = 0;
    ret = -1;
    break;

  } /* for each byte in input */

  return ret;

} /* str_safe */

#ifdef STR_EXAMPLE

#include <stdio.h>
#include "str.h"

main()
{
  char buf[1024];
  unsigned char b[4];
  int i;

  i = str_input("prompt: ", buf, 2, STR_FLAGS_ECHO_OFF);
  printf("i=%d\n", i);
  printf("buf=%s\n", buf);

  b[0] = 0x1A;
  b[1] = 0x2B;
  b[2] = 0x3C;
  b[3] = 0x4D;
  str_hex_dump(buf, b, 4);
  printf("%s\n", buf);

  b[0] = 'A';
  b[1] = 'B';
  b[2] = 0;

  str_ftoc(buf, b, 4);
  printf("%s\n", buf);

  b[0] = 'A';
  b[1] = 'B';
  b[2] = 'C';
  b[3] = 'D';

  str_ftoc(buf, b, 4);
  printf("%s\n", buf);

}

#endif /* STR_EXAMPLE */