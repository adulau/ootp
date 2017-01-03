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
 *      $Id: main.c 89 2009-12-28 01:35:00Z maf $
 */

#include <htc.h>
#include "r2sdk.h"
#include "spi.h"
#include "delay.h"

/*
 */
#define NO_CALC

/*
 * HI-TECH C version 9.x does not use a long jump for its startup code.
 * This is a problem since the bootloader in the PARII expects this.
 * 
 * With the use of --codeoffset=4 and the following assembler we get the
 * 8.x behavior (albeit with an extra goto)
 * 
 * Note this is hardcoded to jump to 0x04.  If interrupts are used the startup
 * code may go elsewhere.
 * 
 */
#asm 
psect reserved,class=CODE, delta=2
CLRF  0x03
MOVLW  0x0 
MOVWF  0xA
GOTO  0x04; Jump to startup
#endasm

/* also defined in otpsc.h */
#define SC_GETHOSTNAME_CLA            0x80
#define SC_GETHOTP_CLA                0x80
#define SC_SETPIN_CLA                 0x80
#define SC_TESTPIN_CLA                0x80
#define SC_GETHOTPCOUNT32_CLA         0x80
#define SC_GETHOTPHOST_CLA            0x80
#define SC_GETHOTPHOSTCOUNT32_CLA     0x80
#define SC_GETSPYRUSEEBLOCK_CLA       0x80

#define SC_GETHOSTNAME_INS            0x44
#define SC_GETHOTP_INS                0x46
#define SC_SETPIN_INS                 0x4C
#define SC_TESTPIN_INS                0x4E
#define SC_GETHOTPCOUNT32_INS         0x58
#define SC_GETHOTPHOST_INS            0x5A
#define SC_GETHOTPHOSTCOUNT32_INS     0x5C
#define SC_GETSPYRUSEEBLOCK_INS       0xA2

U8 protocol = 0x03;
RESP_INFO  *Resp;
bank1 U8  Buf[72];      /* Spyrus I/O buffer */
bank2 U8  dbuf[2][16];  /* two current hostnames for menu */
bank2 U8  obuf[2];      /* option buffer for menu items */

U8 myPIN[5];            /* PIN */
U8 newPIN[5];           /* newPIN if set */

U8 sc_cmdLen;           /* SC command length */
U8 sc_idx;              /* SC host index */

/*
 * sc_count and sc_countp must be in same bank or C compiler will
 * generate incorrect code
 */
bank2 U32 sc_count;     /* SC host count */
bank2 U8 *sc_countp;    /* byte pointer to sc_count */

/* menu vars */
U8 menu_active;         /* # of active menu items */
U8 menu_cursor;         /* menu cursor position (top/bottom) */
U8 menu_idx;            /* index of menu */

U8 ml_flags;            /* flags for main loop */

U8 short_d0;            /* shortcut digit 0 */
U8 key;                 /* key input */
U8 key_num;             /* key number (ASCII 0..9) */

/* scratch bytes */
U8 scratch_buf5[5];

/* size of initialization data for EEProm */
#define EE_INIT_SIZE 224

/* size of EEProm */
#define EE_SIZE 256

/* number of 16 byte blocks in EEProm */
#define EE_BLOCKS 16

/* number of bytes in a block */
#define EE_BLOCK_SIZE 16
#define EE_BLOCK_SIZE_SHIFT 4 /* 2^4=16 */

/* EE Memory Map */
#define EE_MAGIC_ADDR          0
#define EE_READER_KEY_ADDR     3
#define EE_CALC_MSG_ADDR       8
#define EE_L1GREET_ADDR        20
#define EE_L2GREET_ADDR        32
#define EE_L1MAIN_ADDR         44
#define EE_L2MAIN_ADDR         56
#define EE_CHALLENGE_ADDR      68
#define EE_L1LOCKED_ADDR       80
#define EE_L2LOCKED_ADDR       92
#define EE_L1ACCESS_DENY_ADDR  104
#define EE_L2ACCESS_DENY_ADDR  116
#define EE_NOHOSTS_ADDR        128
#define EE_L1NEWPIN_ADDR       140
#define EE_L2NEWPIN_ADDR       152
#define EE_L3NEWPIN_ADDR       164
#define EE_PINCHANGED_ADDR     176
#define EE_NOCARD_ADDR         188
#define EE_TRYHARDER_ADDR      200

#define EE_MAGIC_LEN           3
#define EE_READER_KEY_LEN      5
#define EE_CALC_MSG_LEN        12
#define EE_L1GREET_LEN         12
#define EE_L2GREET_LEN         12
#define EE_L1MAIN_LEN          12
#define EE_L2MAIN_LEN          12
#define EE_CHALLENGE_LEN       12
#define EE_L1LOCKED_LEN        12
#define EE_L2LOCKED_LEN        12
#define EE_L1ACCESS_DENY_LEN   12
#define EE_L2ACCESS_DENY_LEN   12
#define EE_NOHOSTS_LEN         12
#define EE_L1NEWPIN_LEN        12
#define EE_L2NEWPIN_LEN        12
#define EE_L3NEWPIN_LEN        12
#define EE_PINCHANGED_LEN      12
#define EE_NOCARD_LEN          12
#define EE_TRYHARDER_LEN       12

/* EEInit */
const U8 EEDefault[] = {

  0x6d,0x61,0x66,0x30,0x30,0x30,0x30,0x30,
  0x4f,0x41,0x52,0x6e,0x65,0x74,0x3a,0x32,

  0x30,0x30,0x39,0x20,0x20,0x20,0x20,0x4f,
  0x41,0x52,0x6e,0x65,0x74,0x20,0x20,0x20,

  0x50,0x49,0x4e,0x3a,0x20,0x20,0x20,0x20,
  0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x4f,

  0x41,0x52,0x6e,0x65,0x74,0x20,0x20,0x20,
  0x20,0x20,0x56,0x65,0x72,0x69,0x66,0x69,

  0x65,0x64,0x20,0x20,0x43,0x68,0x61,0x6c,
  0x6c,0x65,0x6e,0x67,0x65,0x3a,0x20,0x20,

  0x31,0x30,0x20,0x46,0x61,0x69,0x6c,0x75,
  0x72,0x65,0x73,0x20,0x43,0x61,0x72,0x64,

  0x20,0x4c,0x6f,0x63,0x6b,0x65,0x64,0x20,
  0x20,0x20,0x20,0x41,0x63,0x63,0x65,0x73,

  0x73,0x20,0x20,0x20,0x20,0x20,0x20,0x44,
  0x65,0x6e,0x69,0x65,0x64,0x20,0x20,0x20,

  0x20,0x20,0x4e,0x6f,0x20,0x48,0x6f,0x73,
  0x74,0x73,0x20,0x20,0x53,0x65,0x74,0x20,

  0x4e,0x65,0x77,0x20,0x50,0x49,0x4e,0x20,
  0x4e,0x65,0x77,0x50,0x49,0x4e,0x3a,0x20,

  0x20,0x20,0x20,0x20,0x41,0x67,0x61,0x69,
  0x6e,0x3a,0x20,0x20,0x20,0x20,0x20,0x20,

  0x50,0x49,0x4e,0x20,0x43,0x68,0x61,0x6e,
  0x67,0x65,0x64,0x20,0x4e,0x6f,0x20,0x43,

  0x61,0x72,0x64,0x20,0x20,0x20,0x20,0x20,
  0x54,0x72,0x79,0x20,0x48,0x61,0x72,0x64,

  0x65,0x72,0x20,0x20,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

};

const U8 VERSION[] = {
/* record length */
  0x0C,\
/* Serial # */
  0x0A, 'm', 'a', 'f', ' ', 'H', 'O', 'T', 'P', ' ', ' ',\
/* AE kernel version / program access (unused) */
  0x14, 0x22, 0x33
};

U8 getPIN(U8 *dest, U8 pos);
void getCount(void);
U8 dispHOTP(U8 fmt);

U8 hexdigit(U8 d);

U8 SCTransact(void);
void cmdSCTestPIN(void);
void cmdSCSetPIN(void);
void cmdSCGetHOTPHostCount32(void);
void cmdSCGetHOTPCount32(void);
void cmdCsum(void);
void cmdSCGetSpyrusEEBlock(U8 i);

U8 doSCGetHostname(U8 idx, U8 row);

void powerdown(void);
void msg_powerdown(void);

void menuUpdateCursor(void);
void menuUpdate(void);
void menuInit(void);

void keyGet(void);
void keyDecodeNumber(void);

void EEInit(void);
U8 EELen(U8 addr, U8 len);

#define FLAGS_SCREEN0_UPDATE 0x01   /* initial screen update? */
#define FLAGS_INPUT_COUNT    0x02   /* input count before HOTP? */
#define FLAGS_MENU_SHORT_D0  0x04   /* menu shortcut digit 0 */
#define FLAGS_MENU_ACTIVE    0x08   /* menu is active */

#define HOSTNAME_FLAG_MASK      0x80   /* high bit set */
#define HOSTNAME_POS_CHALLENGE  0x00   /* require challenge input */
#define HOSTNAME_POS_READERKEY  1      /* require reader key */
#define HOSTNAME_POS_FMT        2      /* format, 0=hex, 1=decimal */
#define HOSTNAME_POS_FMT3       8      /* 0000=HEX40,   0001=HEX40   */
#define HOSTNAME_POS_FMT2       9      /* 0010=DEC31.6  0011=DEC31.7 */
#define HOSTNAME_POS_FMT1       10     /* 0100=DEC31.8  0101=DEC31.9 */
#define HOSTNAME_POS_FMT0       11     /* 0110=DEC31.10 0111=DHEX40  */

#define OPTION_FLAG_CHALLENGE 0x01  /* option set to request challenge */
#define OPTION_FLAG_FMT       0x02  /* option to format HOTP */

int main(void)
{
  U8 i, c, j, addr, fmt;

  /* init */
  Resp = (RESP_INFO*)Buf;
  r2_init();
  sc_countp = (U8*)&sc_count;

  i = ServiceQuery();

  /* initialize EEProm if not set */
  EEInit();

  if (i == SQ_CALC) {
#ifndef NO_CALC
    DoCalc(&Resp->data[2]);
    Str2Lcd(0,0,&Resp->data[2]);
#else
    EE2LCD(0, 0, EE_CALC_MSG_ADDR, EE_CALC_MSG_LEN);
    msg_powerdown();
#endif /* NO_CALC */
  } /* SQ_CALC */

  if (i == SQ_FW_VERSION) {
    for (i = 0; i < 0x0E; ++i)
      Buf[i] = VERSION[i];
    snd_cmd(FIRMWARE_INFO, 0x0E, Buf);
    get_resp(Resp);
  }

  /* anything to do? */
  if (i != SQ_CARD_KEY)
    powerdown();

  ClearLcd();

  /* get valid PIN */
  while (1) {

    /* initial greeting */
    EE2LCD(0, 0, EE_L1GREET_ADDR, EE_L1GREET_LEN);
    EE2LCD(1, 0, EE_L2GREET_ADDR, EE_L2GREET_LEN);

    /* Get PIN */
    i = getPIN(myPIN,4);

    /* magic sequence to load EEProm */
    if (i == 1) {

      scratch_buf5[2] = 0;
      ClearLcd();
      Str2Lcd(0, 0, "EEWrite");

      /* foreach block */
      for (i = 0; i < EE_BLOCKS; ++i) {

        cmdSCGetSpyrusEEBlock(i);

        if (SCTransact() != 0)
          powerdown();

       /*
        * 2 byte resp (2)      : 0,1
        * NAD,PCB,LEN (3)      : 2,3,4
        * idx (1)              : 5
        * eeData (16)          : 6..21
        */

        scratch_buf5[0] = hexdigit(i>>4);
        scratch_buf5[1] = hexdigit(i&0x0F);
        Str2Lcd(1, 0, scratch_buf5);

        /* foreach byte in the block */
        for (j = 0; j < EE_BLOCK_SIZE; ++j) {

          c = Buf[6+j];
          addr = (i<<EE_BLOCK_SIZE_SHIFT) + j;

          EEPROM_WRITE(addr, c);

        } /* j */

        /* signal last block */
        if (Buf[5] & 0x80)
          break;

      } /* i */

      /* wait for last write to complete */
      while (WR)
        continue;

      ClearLcd();
      continue;

    } /* load EEProm */

    /* Test PIN command */
    cmdSCTestPIN();

    /* Initiate smart card transaction */
    if (SCTransact() == 0)
      break; /* success */

  } /* getPIN */

  /* initialize for main screen input */
  menuInit();

  /* main key loop */
  while (1) {

    if (ml_flags & FLAGS_SCREEN0_UPDATE) {
      EE2LCD(0, 0, EE_L1MAIN_ADDR, EE_L1MAIN_LEN);
      EE2LCD(1, 0, EE_L2MAIN_ADDR, EE_L2MAIN_LEN);
      ml_flags &= ~FLAGS_SCREEN0_UPDATE;
    }

    keyGet();

/****** GET COUNT BEFORE HOTP */
    if (key == RAW_POUND) {

      /* toggle need_challenge */
      if (ml_flags & FLAGS_INPUT_COUNT)
        ml_flags &= ~FLAGS_INPUT_COUNT;
      else
        ml_flags |= FLAGS_INPUT_COUNT;
      continue;
   
    } /* RAW_POUND */

/****** SCROLL MENU DOWN ****/
    if (key == RAW_DOWN) {

      /* menu active yet? */
      if (!(ml_flags & FLAGS_MENU_ACTIVE)) { /* no */

        /* get first two hostnames */
        menu_active = doSCGetHostname(0,0);
        menu_active += doSCGetHostname(1,1);
        menu_idx += menu_active;

        /* no hosts on card then nothing to do */
        if (menu_active == 0) {
          EE2LCD(0, 0, EE_NOHOSTS_ADDR, EE_NOHOSTS_LEN);
          msg_powerdown();
        }

        /* display menu */
        menuUpdate();

        ml_flags |= FLAGS_MENU_ACTIVE;

      } else { /* yes */

        if (menu_cursor == 0) {
          if (menu_active == 2) {
            menu_cursor = 1;
            menuUpdateCursor();
          }
        } else {
          i = doSCGetHostname(menu_idx, 0);
          if (i) {
            i += doSCGetHostname(menu_idx+1, 1);
            menu_active = i;
            menu_idx += menu_active;
            menu_cursor = 0;
            menuUpdate();
          }
        }
      } /* else */

      /* next input */
      continue;

    } /* RAW_DOWN */

/****** SCROLL MENU UP ****/
    if (key == RAW_UP) {

      /* not valid until host menu active */
      if (!(ml_flags & FLAGS_MENU_ACTIVE)) { /* no */
        Beep(1);
        continue;
      }

      if (menu_cursor == 1) {
        menu_cursor = 0;
        menuUpdateCursor();
      } else {
        if (menu_idx > 2) {
          menu_idx = menu_idx - menu_active;
          doSCGetHostname(menu_idx-2,0);
          doSCGetHostname(menu_idx-1,1);
          menu_active = 2;
          menu_cursor = 1;
          menuUpdate();
        }
      }
      continue;
    } /* RAW_UP */

/****** MENU ENTER ****/
    if (key == RAW_ENTER) {

      /* host menu active? */
      if (!(ml_flags & FLAGS_MENU_ACTIVE)) { /* no */

        /* index is first digit input or 0 if no digits input */
        sc_idx = short_d0;

        goto enter_shortcut;

      } /* host menu not active yet */ 

      /* index on smart card */
      sc_idx = menu_idx - menu_active + menu_cursor;

      /* challenge input? */
      if ((obuf[menu_cursor] & OPTION_FLAG_CHALLENGE) ||
        (ml_flags & FLAGS_INPUT_COUNT))
        getCount();

      /* GetHOTPCount32 command */
      cmdSCGetHOTPCount32();

      /* initiate SC transaction */
      if (SCTransact() == 0) {

       /*
        * 2 byte resp (2)      : 0,1
        * NAD,PCB,LEN (3)      : 2,3,4
        * idx (1)              : 5
        * PIN (5)              : 6,7,8,9,10
        * count (4)            : 11,12,13,14
        * HOTP (5)             : 15,16,17,18,19
        */

        /* display hostname on top */
        for (i = 0; i < 12; ++i)
          dbuf[0][i] = dbuf[menu_cursor][i+3];
        dbuf[0][12] = 0;

        /* Binary/Hex HOTP format */
        (obuf[menu_cursor] & OPTION_FLAG_FMT) ? fmt = 1 : fmt = 0;

        /* display HOTP and maybe cycle to next system */
        if (dispHOTP(fmt)) {

          ClearLcd();
          sc_idx ++;
          goto enter_shortcut;

        } /* dispHOTP() */

      } else {

        /* Failure */
        Str2Lcd(0,0,"GHPC32:fail");
        msg_powerdown();

      } /* SC transaction */

      /* start back to main screen */
      menuInit();

      /* next input */
      continue;

    } /* RAW_ENTER */

/****** CHANGE PIN ****/
    if (key == RAW_STAR) {

      while (1) {

        ClearLcd();
        EE2LCD(0, 0, EE_L1NEWPIN_ADDR, EE_L1NEWPIN_LEN);
        EE2LCD(1, 0, EE_L2NEWPIN_ADDR, EE_L2NEWPIN_LEN);

        i = EELen(EE_L2NEWPIN_ADDR, EE_L2NEWPIN_LEN);
        getPIN(newPIN, i);
         
        /* minimal checking, all digits equal not permitted */
        if ((newPIN[0] == newPIN[1]) &&
            (newPIN[1] == newPIN[2]) &&
            (newPIN[2] == newPIN[3]) &&
            (newPIN[3] == newPIN[4])) {
    
          ClearLcd();
          EE2LCD(0, 0, EE_TRYHARDER_ADDR, EE_TRYHARDER_LEN);
          Beep(2);
          keyGet();
          continue;
        }
         
        EE2LCD(1, 0, EE_L3NEWPIN_ADDR, EE_L3NEWPIN_LEN); 

        i = EELen(EE_L3NEWPIN_ADDR, EE_L3NEWPIN_LEN);
        getPIN(scratch_buf5, i);
          
        /* make sure user entered it correctly */
        if ((newPIN[0] == scratch_buf5[0]) &&
            (newPIN[1] == scratch_buf5[1]) &&
            (newPIN[2] == scratch_buf5[2]) &&
            (newPIN[3] == scratch_buf5[3]) &&
            (newPIN[4] == scratch_buf5[4]))
          break; /* have valid new pin */

        /* two did not match */
        Beep(2);

      } /* get new pin */

      /* Set PIN command */
      cmdSCSetPIN();

      /* Initiate smart card transaction */
      if (SCTransact() == 0) {
        /* success */
        ClearLcd();
        EE2LCD(0, 0, EE_PINCHANGED_ADDR, EE_PINCHANGED_LEN);
        myPIN[0] = newPIN[0]; myPIN[1] = newPIN[1];
        myPIN[2] = newPIN[2]; myPIN[3] = newPIN[3];
        myPIN[4] = newPIN[4];
      } else {
        /* Failure */
        Str2Lcd(0,0,"SetPIN:fail");
        msg_powerdown();
      }

      /* go back to initial screen */
      ml_flags |= FLAGS_SCREEN0_UPDATE;

      /* any key to continue */
      keyGet();

      /* success / next input */
      continue;

    } /* RAW_STAR / CHANGE_PIN */

/***** CLEAN INPUT DIGITS */

    if (key == RAW_CANCEL) {

      short_d0 = 0;
      ml_flags &= ~FLAGS_MENU_SHORT_D0;
      continue;

    } /* RAW_CANCEL */

/****** MENU SHORTCUT WITH DIGIT ENTRY ***** */

    /*
     * require two digit host index
     */

    /* convert raw keypress to 0..9 */
    keyDecodeNumber();

    /* any keys input not 0..9 are no longer valid */
    if (!key_num) {
      Beep(1);
      continue;
    }

    /* first digit? */
    if (!(ml_flags & FLAGS_MENU_SHORT_D0)) {

      /* store first digit */
      short_d0 = key_num - '0';

      /* first digit input success */
      ml_flags |= FLAGS_MENU_SHORT_D0;

    } else {

      /* 2nd digit triggers HOTP generation */

      /* sc_idx = short_d0*10+d1 */
      sc_idx = short_d0 <<3;
      sc_idx += short_d0;
      sc_idx += short_d0;
      sc_idx += (key_num - '0');

enter_shortcut:

      /* the next sequential HOTP can be selected with the down arrow */
      while (1) {

        /* input count first? */
        if (ml_flags & FLAGS_INPUT_COUNT)
          getCount();

        /* GetHOTPHostCount32 command */
        cmdSCGetHOTPHostCount32();

        /* initiate SC transaction */
        if (SCTransact() == 0) {

         /*
          * 2 byte resp (2)      : 0,1
          * NAD,PCB,LEN (3)      : 2,3,4
          * idx (1)              : 5
          * PIN (5)              : 6,7,8,9,10
          * count (4)            : 11,12,13,14
          * HOTP (5)             : 15,16,17,18,19
          * HostName(12)         : 20..31
          */

          /* skip display for empty hostname */
          if (Buf[20] != 0) {

            /* display hostname on top */
            for (i = 0; i < 12; ++i)
              dbuf[0][i] = (Buf[20+i]&0x7F);
            dbuf[0][12] = 0;

            /* Binary/Hex HOTP format */
            (Buf[20+HOSTNAME_POS_FMT] & HOSTNAME_FLAG_MASK) ? fmt = 1 : fmt = 0;

            /* display HOTP and maybe cycle to next system */
            if(dispHOTP(fmt)) {

              sc_idx ++;
              ClearLcd();
              continue;

            } else {

              break; /* done */

            }
            

          } else {

            Str2Lcd(0,0,"GHPHC32:empt");

            /* fatal */
            msg_powerdown();

          } /* hostname not empty */
            

        } else {

          /* Failure */
          Str2Lcd(0,0,"GHPHC32:fail");

          /* fatal */
          msg_powerdown();

        } /* SC transaction */

      } /* while 1 */

      /* initialize for main screen input */
      menuInit();

    } /* digit */

    /* next input */
    continue;

  } /* main key loop */

  powerdown();
  
}  /* main */

void getCount(void)
{
  U32 tmp32u;
  U8 pos;

  /* prime loop */
  key = RAW_CANCEL;

  /* LCD output string */
  scratch_buf5[1] = 0;

  /* init to 0 */
  sc_count = 0;

  while (1) {

    if (key == RAW_CANCEL) {
      ClearLcd();
      EE2LCD(0, 0, EE_CHALLENGE_ADDR, EE_CHALLENGE_LEN);
      sc_count = 0;
      pos = 0;
      goto next_key;
    }

    /* done? */
    if (key == RAW_ENTER)
      break;

    keyDecodeNumber();

    /* only accept digits */
    if (key_num == 0) {
      Beep(1);
      goto next_key;
    }

    /* 2^32-1 is 10 digits */
    if (pos >= 10) {
      Beep(1);
      goto next_key;
    }

    scratch_buf5[0] = key_num;
    Str2Lcd(1,pos,scratch_buf5);

    /* drop leading 0's */
    if ((pos == 0) && (key_num == '0'))
      goto next_key;

    /* ignore potential overflow from user input, not meaningful */
    tmp32u = (sc_count<<3); /* *8 */
    tmp32u += (sc_count<<1); /* +*2 or *10 */
    tmp32u += (key_num - '0'); /* + new digit */

    sc_count = tmp32u;

    ++pos;

next_key:
    keyGet();

  } /* get count input */

} /* getCount */

/*
 * function: getPIN()
 * 
 * Get PIN from user.
 *   dest = 0 Store in myPIN
 *   dest = 1 Store in newPIN
 * 
 * return 0 good
 *        1 fail
 */
U8 getPIN(U8 *dest, U8 pos)
{
  U8 i;
  
  i = 0;
 
  while (1) {
    
    /* get a single key */
    keyGet();
    
    /* Enter is valid when 5 digits have been entered */
    if (key == RAW_ENTER && i == 5)
      break;

    if ((key == RAW_POUND) && (i == 1) &&
      (dest[0] == '3'))
      return 1;
 
    /* Clear entry */     
    if (key == RAW_CANCEL) {
      Str2Lcd(1,pos,"     ");
      i = 0;
      continue;
    }
    
    /* convert keycode to ASCII */
    keyDecodeNumber();

    /* else if pin not full and valid digit */
    if (i < 5 && key_num) {
      Str2Lcd(1,i+pos,"*");
      dest[i++] = key_num;
    } else {
      Beep(1);
    }

  } /* while */

  return 0;

} /* get_pin */

void keyGet(void)
{
  if (GetRawKey(Resp))
    powerdown();
  key = *Resp->data;
} /* keyGet */

/*
 * function: keyDecodeNumber()
 * 
 * decode ASCII code for Spyrus keycode 0..9
 * else 0
 */
void keyDecodeNumber (void)
{
  if (key == RAW0)
    key_num = '0';
  else if (key == RAW1)
    key_num = '1';
  else if (key == RAW2)
    key_num = '2';
  else if (key == RAW3)
    key_num = '3';
  else if (key == RAW4)
    key_num = '4';
  else if (key == RAW5)
    key_num = '5';
  else if (key == RAW6)
    key_num = '6';
  else if (key == RAW7)
    key_num = '7';
  else if (key == RAW8)
    key_num = '8';
  else if (key == RAW9)
    key_num = '9';
  else
    key_num = 0;
} /* keyDecodeNumber */

/*
 * function: hexdigit()
 * 
 * return a hex digit in ASCII
 */
U8 hexdigit(U8 d)
{
  if (d < 10)
    return d + '0';
  return d + 'A' - 10;
} /* hexdigit */

/*
 * function: cmdCsum()
 * 
 * perform ISO checksum calculation on Buf
 */
void cmdCsum(void)
{
  U8 k, l;
  l = 29+sc_cmdLen;
  for (k = 30; k < l; ++k)
    Buf[l] = Buf[l] ^ Buf[k];
} /* cmdCsum */

void cmdSCTestPIN(void)
{
  Buf[30] = 0x00;           /* NAD */
  Buf[31] = 0x00;           /* PCB */
  Buf[32] = 0x0B;           /* LEN */
  Buf[33] = SC_TESTPIN_CLA; /* CLA */
  Buf[34] = SC_TESTPIN_INS; /* INS */
  Buf[35] = 0x00;           /* P1 */
  Buf[36] = 0x00;           /* P2 */
  Buf[37] = 0x05;           /* DATA LEN */
  Buf[38] = myPIN[0];       /* PIN[0] */
  Buf[39] = myPIN[1];       /* PIN[1] */
  Buf[40] = myPIN[2];       /* PIN[2] */
  Buf[41] = myPIN[3];       /* PIN[3] */
  Buf[42] = myPIN[4];       /* PIN[4] */
  Buf[43] = 0x05;           /* Expected response size */
  Buf[44] = 0;              /* CSUM */
  sc_cmdLen = (44-30) + 1;
  cmdCsum();
} /* cmdSCTestPIN */

void cmdSCSetPIN(void)
{
  Buf[30] = 0x00;           /* NAD */
  Buf[31] = 0x00;           /* PCB */
  Buf[32] = 0x10;           /* LEN */
  Buf[33] = SC_SETPIN_CLA;  /* CLA */
  Buf[34] = SC_SETPIN_INS;  /* INS */
  Buf[35] = 0x00;           /* P1 */
  Buf[36] = 0x00;           /* P2 */
  Buf[37] = 0x0A;           /* DATA LEN */
  Buf[38] = myPIN[0];       /* PIN */
  Buf[39] = myPIN[1];       /* PIN */
  Buf[40] = myPIN[2];       /* PIN */
  Buf[41] = myPIN[3];       /* PIN */
  Buf[42] = myPIN[4];       /* PIN */
  Buf[43] = newPIN[0];      /* newPIN */
  Buf[44] = newPIN[1];      /* newPIN */
  Buf[45] = newPIN[2];      /* newPIN */
  Buf[46] = newPIN[3];      /* newPIN */
  Buf[47] = newPIN[4];      /* newPIN */
  Buf[48] = 0x0A;           /* Expected response size */
  Buf[49] = 0;              /* CSUM */
  sc_cmdLen = (49-30) + 1;  /* DATA_LEN + 4 */
  cmdCsum();
} /* cmdSCSetPIN */

void cmdSCGetHOTPHostCount32(void)
{
  U8 i;

  Buf[30] = 0x00;                      /* NAD */
  Buf[31] = 0x00;                      /* PCB */
  Buf[32] = 21;                        /* LEN (DATA_LEN + 6) */
  Buf[33] = SC_GETHOTPHOSTCOUNT32_CLA; /* CLA */
  Buf[34] = SC_GETHOTPHOSTCOUNT32_INS; /* INS */
  Buf[35] = 0x00;                      /* P1 */
  Buf[36] = 0x00;                      /* P2 */
  Buf[37] = 15;                        /* DATA LEN 1+5+4+5+0 */
  Buf[38] = sc_idx;                    /* Index */
  Buf[39] = myPIN[0];                  /* PIN[0] */
  Buf[40] = myPIN[1];                  /* PIN[1] */
  Buf[41] = myPIN[2];                  /* PIN[2] */
  Buf[42] = myPIN[3];                  /* PIN[3] */
  Buf[43] = myPIN[4];                  /* PIN[4] */
  Buf[44] = sc_countp[3];              /* COUNT */
  Buf[45] = sc_countp[2];              /* COUNT */
  Buf[46] = sc_countp[1];              /* COUNT */
  Buf[47] = sc_countp[0];              /* COUNT */
  /* 48..52                            /* ReaderPIN */
  Buf[53] = 27;                        /* Expected response size 1+5+4+5+12*/
  Buf[54] = 0;                         /* CSUM */
  sc_cmdLen = (54-30) + 1;             /* DATA_LEN + 4 */
  for (i = 0; i < EE_READER_KEY_LEN; ++i)
    Buf[48+i] = EEPROM_READ(EE_READER_KEY_ADDR+i);
  cmdCsum();
} /* cmdSCGetHOTPHostCount32 */

void cmdSCGetHOTPCount32(void)
{
  U8 i;

  Buf[30] = 0x00;                      /* NAD */
  Buf[31] = 0x00;                      /* PCB */
  Buf[32] = 21;                        /* LEN (DATA_LEN + 6) */
  Buf[33] = SC_GETHOTPCOUNT32_CLA;     /* CLA */
  Buf[34] = SC_GETHOTPCOUNT32_INS;     /* INS */
  Buf[35] = 0x00;                      /* P1 */
  Buf[36] = 0x00;                      /* P2 */
  Buf[37] = 15;                        /* DATA LEN 1+5+4+5 */
  Buf[38] = sc_idx;                    /* Index */
  Buf[39] = myPIN[0];                  /* PIN[0] */
  Buf[40] = myPIN[1];                  /* PIN[1] */
  Buf[41] = myPIN[2];                  /* PIN[2] */
  Buf[42] = myPIN[3];                  /* PIN[3] */
  Buf[43] = myPIN[4];                  /* PIN[4] */
  Buf[44] = sc_countp[3];              /* COUNT */
  Buf[45] = sc_countp[2];              /* COUNT */
  Buf[46] = sc_countp[1];              /* COUNT */
  Buf[47] = sc_countp[0];              /* COUNT */
  /* 48..52                            /* ReaderPIN */
  Buf[53] = 15;                        /* Expected response size 1+5+4+5*/
  Buf[54] = 0;                         /* CSUM */
  sc_cmdLen = (54-30) + 1;             /* DATA_LEN + 4 */
  for (i = 0; i < EE_READER_KEY_LEN; ++i)
    Buf[48+i] = EEPROM_READ(EE_READER_KEY_ADDR+i);
  cmdCsum();
} /* cmdSCGetHOTPCount32 */

void cmdSCGetSpyrusEEBlock(U8 i)
{
  Buf[30] = 0x00;                    /* NAD */
  Buf[31] = 0x00;                    /* PCB */
  Buf[32] = 7;                       /* LEN DATA_LEN + 6)*/
  Buf[33] = SC_GETSPYRUSEEBLOCK_CLA; /* CLA */
  Buf[34] = SC_GETSPYRUSEEBLOCK_INS; /* INS */
  Buf[35] = 0x00;                    /* P1 */
  Buf[36] = 0x00;                    /* P2 */
  Buf[37] = 1;                       /* DATA LEN 1 */
  Buf[38] = i;                       /* index */
  Buf[39] = 17;                      /* Expected response size 1+16 */
  Buf[40] = 0;                       /* CSUM */
  sc_cmdLen = (40-30) + 1;
  cmdCsum();
} /* cmdSCGetSpyrusEEBlock */

/*
 * function: SCTransact()
 * 
 * return codes:
 *   0 : success
 *   1 : no card
 *   2 : access denied
 *   9 : fatal (will not return)
 */
U8 SCTransact(void)
{
  U8 r, x1, x2;
  
  if (CardPowerOn(Resp)) {
    ClearLcd();
    EE2LCD(0, 0, EE_NOCARD_ADDR, EE_NOCARD_LEN);
    CardPowerOff();
    r = 1; /* no card */
    goto SCTransact_err2;
  }
  
  r = SendRawCmd(ICC_CMD, sc_cmdLen, &Buf[30], Resp);

  CardPowerOff();

  /* fatal error? bail with CLA,INS */
  if ((r != BLOCK_RESP) || (Resp->len < 3)) {
    x1 = Buf[33]; /* CLA */
    x2 = Buf[34]; /* INS */
    r = 9; /* fatal error */
    ClearLcd();
    Str2Lcd(0,0,"Err CLA:INS");
    goto SCTransact_err;
  }

  x1 = Resp->data[Resp->len - 3]; /* SW1 */
  x2 = Resp->data[Resp->len - 2]; /* SW2 */
    
  if (x1 == 0x90 && x2 == 0x00)
    return 0; /* success */

  ClearLcd();

  if (x1 == 0x66 && x2 == 0xC7) {
    EE2LCD(0, 0, EE_L1LOCKED_ADDR, EE_L1LOCKED_LEN);
    EE2LCD(1, 0, EE_L2LOCKED_ADDR, EE_L1LOCKED_LEN);
    r = 9; /* fatal error */
    goto SCTransact_err2;
  }
    
  if (x1 == 0x69 && x2 == 0xC2) {
    EE2LCD(0, 0, EE_L1ACCESS_DENY_ADDR, EE_L1ACCESS_DENY_LEN);
    EE2LCD(1, 0, EE_L2ACCESS_DENY_ADDR, EE_L2ACCESS_DENY_LEN);
    r = 2; /* access denied */
    goto SCTransact_err2;
  }

  Str2Lcd(0,0,"Err SW1:SW2");

  /* error */
SCTransact_err:
  scratch_buf5[0] = hexdigit(x1>>4);
  scratch_buf5[1] = hexdigit(x1 & 0x0F);
  scratch_buf5[2] = hexdigit(x2>>4);
  scratch_buf5[3] = hexdigit(x2 & 0x0F);
  scratch_buf5[4] = 0;
  Str2Lcd(1,0,scratch_buf5);

  /* get any key */
SCTransact_err2:
  keyGet();

  ClearLcd();

  /* return other than fatal */
  if (r != 9)
    return r;

  powerdown();

  return r; /* unused */

} /* SCTransact */

/*
 * function: doSCGetHostname()
 *
 * grab a single hostname with index i from the card. store in dbuf position j
 *
 * returns 1 if hostname is retrieved, else 0.
 */
U8 doSCGetHostname(U8 idx, U8 row)
{
  U8 k;

  Buf[30] = 0x00;               /* NAD */
  Buf[31] = 0x00;               /* PCB */
  Buf[32] = 12;                 /* LEN  DATA_LEN + 6 */
  Buf[33] = SC_GETHOSTNAME_CLA; /* CLA */
  Buf[34] = SC_GETHOSTNAME_INS; /* INS */
  Buf[35] = 0x00;               /* P1 */
  Buf[36] = 0x00;               /* P2 */
  Buf[37] = 6;                  /* DATA LEN (1+5) */
  Buf[38] = idx;                /* index */
  Buf[39] = myPIN[0];           /* PIN[0] */
  Buf[40] = myPIN[1];           /* PIN[1] */
  Buf[41] = myPIN[2];           /* PIN[2] */
  Buf[42] = myPIN[3];           /* PIN[3] */
  Buf[43] = myPIN[4];           /* PIN[4] */
  Buf[44] = 18;                 /* Expected response size 1+5+12 */
  Buf[45] = 0;                  /* CSUM */
  sc_cmdLen = (45-30) + 1;      /* DATA_LEN + 4 */
  cmdCsum();

  /*
   * 2 byte resp (2)      : 0,1
   * NAD,PCB,LEN (3)      : 2,3,4
   * idx (1)              : 5
   * PIN (5)              : 6,7,8,9,10
   * HostName(12)         : 11,12,13,14,15,16,17,18,19,20,21,22
   */

  if (SCTransact() == 0) {

    /* success */

    /* high bit set on first character signals challenge required */
    if (Buf[11+HOSTNAME_POS_CHALLENGE] & HOSTNAME_FLAG_MASK)
      obuf[row] = OPTION_FLAG_CHALLENGE;
    else
      obuf[row] = 0;

    if (Buf[11+HOSTNAME_POS_FMT] & HOSTNAME_FLAG_MASK)
      obuf[row] |= OPTION_FLAG_FMT;

    /* empty hostname is last */
    if (Buf[11] == 0)
      return 0;

    /* copy hostname to display buffer */
    for (k = 3; k < 15; ++k)
      dbuf[row][k] = (Buf[k+8] & 0x7F);

    dbuf[row][0] = hexdigit(idx>>4);
    dbuf[row][1] = hexdigit(idx&0x0F);
    dbuf[row][2] = ':';

    dbuf[row][12] = 0;

    return 1;

  } else {

    Str2Lcd(0,0,"GHN:fail");
    msg_powerdown();

  }

  return 0; /* notreached */

} /* doSCGetHostname */

void msg_powerdown(void)
{
  GetRawKey(Resp);
  DeactivateRdr();
} /* off */

void powerdown(void)
{
  DeactivateRdr();
}

void menuUpdate(void)
{   
  ClearLcd();
  
  Str2Lcd(0,0,&dbuf[0][0]);
  if (menu_active == 2)
    Str2Lcd(1,0,&dbuf[1][0]);
  
  menuUpdateCursor();
  
} /* menuUpdate() */

/*
 * function: menuUpdateCursor()
 *
 * Update menu_cursor based on menu_cursor variable
 */
void menuUpdateCursor(void)
{

  if (menu_cursor == 0) {
    Str2Lcd(0,2,">");
    if (menu_active == 2)
      Str2Lcd(1,2,":");
  } else {
    Str2Lcd(0,2,":");
    if (menu_active == 2)
      Str2Lcd(1,2,">");
  }
  
} /* menuUpdateCursor() */

U8 dispHOTP(U8 fmt)
{
  U8 i, j, c;
  U32 u32;
  char *s;


  if (fmt == 0) { /* HEX */
    for (i = 0, j = 0; i < 5; ++i) {
      c = Buf[15+i];
      dbuf[1][j++] = hexdigit(c>>4);
      dbuf[1][j++] = hexdigit(c&0x0F);
    }
    dbuf[1][j] = 0;
  } else { /* decimal */

    s = (char*)&u32;

    s[3] = Buf[15];
    s[2] = Buf[16];
    s[1] = Buf[17];
    s[0] = Buf[18];

    s = Buf; /* starts at Buf+1 */

    do {
      *++s = u32 % 10 + '0';
    } while ((u32 /= 10) > 0);

    for (i = 0; s != Buf; --s, ++i)
      dbuf[1][i] = *s;
    dbuf[1][i] = 0;

  }

  /*
   * note the following code will not compile properly.  certain
   * bits are Xor'd
   * .X.X.X.X.X  (X is nybble with flipped bit)
   * 74bfe44b40  (generated)
   * 73BCE44D4C  (correct)
   *
   * for (i = 0, j = 0; i < 5; ++i) {
   *  c = Buf[15+i] >> 4;
   *  dbuf[1][j++] = hexdigit(c);
   *  c = Buf[15+i] &0x0F
   *  dbuf[1][j++] = hexdigit(c);
   * }
   */

  /* display hostname and HOTP */
  ClearLcd();
  Str2Lcd(0,0,&dbuf[0][0]);
  Str2Lcd(1,1,&dbuf[1][0]);

  /* any key to continue ~ 10 seconds each, jump out on a key */
  for (i = 0, j = 0; i < 3; ++i) {
    if (!GetRawKey(Resp)) {
      j = 1;
      break;
    }
  }

  if (j == 1) {
    key = *Resp->data;
    if (key == RAW_DOWN)
      return 1; /* again */
    else
      return 0;
  }

  /* timeout */
  powerdown();

  return 0; /* unreached */

} /* dispHOTP */

void menuInit(void)
{
  /* initial input screen / no menu activated yet */
  ml_flags = FLAGS_SCREEN0_UPDATE;

  /* smart card index */
  sc_idx = 0;
  
  /* menu cursor */
  menu_cursor = 0;

  /* SC HOTP count is 0 (default ) */
  sc_count = 0;

  /* first digit if hit enter with host menu not enabled */
  short_d0 = 0;

  /* menu index */
  menu_idx = 0;

} /* menuInit() */

void EEInit(void)
{
  U8 i, c, match;

  match = 0;

  /* Check if EEProm is initialized */
  for (i = EE_MAGIC_ADDR; i < EE_MAGIC_LEN; ++i) {

    c = EEDefault[i];

    if (EEPROM_READ(i) == c)
      ++match;

  }

  /* initialized? */
  if (match == 3)
    return;

  /* no, copy in default data */
  for (i = 0; i < EE_INIT_SIZE; ++i) {
    c = EEDefault[i];
    EEPROM_WRITE(i, c);
  }

  /* wait for last write to complete */
  while (WR)
    continue;

} /* EEInit */

U8 EELen(U8 addr, U8 len)
{
  U8 i, c;

  for (i = 0; i < len; ++i) {
    c = EEPROM_READ(addr);
    if ((c == 0) || (c == ' '))
      break;
    ++addr;
  }

  /* max hpos of LCD */
  if (i > 11)
    i = 11;

  return i;

} /* EELen */

