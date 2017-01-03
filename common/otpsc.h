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
 *      $Id: otpsc.h 86 2009-12-28 00:05:24Z maf $
 */

/* highest supported index */
#define SC_INDEX_MAX 99

/* highest supported count */
#define SC_COUNT_MAX 0xFFFF
#define SC_COUNT32_MAX 0xFFFFFFFF
 
#define SC_HOSTNAME_LEN      12
#define SC_ADMINKEY_LEN      20
#define SC_HOTPKEY_LEN       20
#define SC_PIN_LEN           5
#define SC_COUNT_LEN         2
#define SC_COUNT32_LEN       4
#define SC_INDEX_LEN         1
#define SC_ADMINMODE_LEN     1
#define SC_VERSION_LEN       1
#define SC_HOTP_LEN          5
#define SC_CAPABILITIES_LEN  4
#define SC_SPYRUSEEBLOCK_LEN 16
#define SC_SPYRUSEEIDX_LEN   1
#define SC_READERKEY_LEN     5

#define SC_ADMIN_ENABLE  1
#define SC_ADMIN_DISABLE 0

#define SC_BALANCECARD_DISABLE 0xFF
#define SC_READERKEY_DEFAULT "00000"

#define SC_PIN_DEFAULT "28165"
#define SC_ADMINKEY_DEFAULT "\x00\x01\x02"

#define SC_SETHOST_CLA                0x80
#define SC_GETHOST_CLA                0x80
#define SC_GETHOSTNAME_CLA            0x80
#define SC_GETHOTP_CLA                0x80
#define SC_SETADMINMODE_CLA           0x80
#define SC_SETBALANCECARDINDEX_CLA    0x80
#define SC_SETPIN_CLA                 0x80
#define SC_TESTPIN_CLA                0x80
#define SC_GETVERSION_CLA             0x80
#define SC_SETADMINKEY_CLA            0x80
#define SC_SETHOST32_CLA              0x80
#define SC_GETHOST32_CLA              0x80
#define SC_GETHOTPCOUNT32_CLA         0x80
#define SC_GETHOTPHOST_CLA            0x80
#define SC_GETHOTPHOSTCOUNT32_CLA     0x80
#define SC_GETCAPABILITIES_CLA        0x80
#define SC_SETREADERKEY_CLA           0x80
#define SC_CLEARALL_CLA               0x80
#define SC_SETSPYRUSEEBLOCK_CLA       0x80
#define SC_GETSPYRUSEEBLOCK_CLA       0x80

#define SC_BCGETSTATE_CLA             0xC0
#define SC_BCEEPROMSIZE_CLA           0xC0
#define SC_BCCLEAREEPROM_CLA          0xC0
#define SC_BCWRITEEEPROM_CLA          0xC0
#define SC_BCREADEEPROM_CLA           0xC0
#define SC_BCEEPROMCRC_CLA            0xC0
#define SC_BCSETSTATE_CLA             0xC0

#define SC_SETHOST_INS                0x40
#define SC_GETHOST_INS                0x42
#define SC_GETHOSTNAME_INS            0x44
#define SC_GETHOTP_INS                0x46
#define SC_SETADMINMODE_INS           0x48
#define SC_SETBALANCECARDINDEX_INS    0x4A
#define SC_SETPIN_INS                 0x4C
#define SC_TESTPIN_INS                0x4E
#define SC_GETVERSION_INS             0x50
#define SC_SETADMINKEY_INS            0x52
#define SC_SETHOST32_INS              0x54
#define SC_GETHOST32_INS              0x56
#define SC_GETHOTPCOUNT32_INS         0x58
#define SC_GETHOTPHOST_INS            0x5A
#define SC_GETHOTPHOSTCOUNT32_INS     0x5C
#define SC_CLEARALL_INS               0x5E
#define SC_SETREADERKEY_INS           0x60
#define SC_GETCAPABILITIES_INS        0x90
#define SC_SETSPYRUSEEBLOCK_INS       0xA0
#define SC_GETSPYRUSEEBLOCK_INS       0xA2


#define SC_SETHOST_V1_INS             0x10
#define SC_GETHOST_V1_INS             0x11
#define SC_GETHOSTNAME_V1_INS         0x12
#define SC_GETHOTP_V1_INS             0x13
#define SC_SETADMINMODE_V1_INS        0x14
#define SC_SETBALANCECARDINDEX_V1_INS 0x15
#define SC_SETPIN_V1_INS              0x16
#define SC_TESTPIN_V1_INS             0x17
#define SC_GETVERSION_V1_INS          0x18
#define SC_SETADMINKEY_V1_INS         0x19

#define SC_BCGETSTATE_INS             0x00
#define SC_BCEEPROMSIZE_INS           0x02
#define SC_BCCLEAREEPROM_INS          0x04
#define SC_BCWRITEEEPROM_INS          0x06
#define SC_BCREADEEPROM_INS           0x08
#define SC_BCEEPROMCRC_INS            0x0A
#define SC_BCSETSTATE_INS             0x0C

#define SC_SETHOST_DELAY              900000
#define SC_GETHOST_DELAY              900000
#define SC_GETHOSTNAME_DELAY          900000
#define SC_GETHOTP_DELAY              1100000
#define SC_SETADMINMODE_DELAY         900000
#define SC_SETBALANCECARDINDEX_DELAY  120000
#define SC_SETPIN_DELAY               220000
#define SC_TESTPIN_DELAY              210000
#define SC_GETVERSION_DELAY           120000
#define SC_SETADMINKEY_DELAY          900000
#define SC_GETHOST32_DELAY            900000
#define SC_GETHOTPHOST_DELAY          1200000
#define SC_GETHOTPCOUNT32_DELAY       1200000
#define SC_GETHOTPHOSTCOUNT32_DELAY   1300000
#define SC_SETHOST32_DELAY            1000000
#define SC_GETCAPABILITIES_DELAY      120000
#define SC_SETREADERKEY_DELAY         220000
#define SC_CLEARALL_DELAY             20000000
#define SC_SETSPYRUSEEBLOCK_DELAY     1000000
#define SC_GETSPYRUSEEBLOCK_DELAY     1000000

#define SC_BCGETSTATE_DELAY           900000
#define SC_BCEEPROMSIZE_DELAY         900000
#define SC_BCCLEAREEPROM_DELAY        1800000
#define SC_BCWRITEEEPROM_DELAY        900000
#define SC_BCREADEEPROM_DELAY         900000
#define SC_BCEEPROMCRC_DELAY          2800000
#define SC_BCSETSTATE_DELAY           900000

#define SC_PRDISPLAY_CAP              0x00000001
#define SC_SETHOST_CAP                0x00000002
#define SC_GETHOST_CAP                0x00000004
#define SC_GETHOSTNAME_CAP            0x00000008
#define SC_GETHOTP_CAP                0x00000010
#define SC_SETADMINMODE_CAP           0x00000020
#define SC_SETBALANCECARDINDEX_CAP    0x00000040
#define SC_SETPIN_CAP                 0x00000080
#define SC_TESTPIN_CAP                0x00000100
#define SC_GETVERSION_CAP             0x00000200
#define SC_SETADMINKEY_CAP            0x00000400
#define SC_SETHOST32_CAP              0x00000800
#define SC_GETHOST32_CAP              0x00001000
#define SC_GETHOTPCOUNT32_CAP         0x00002000
#define SC_GETHOTPHOST_CAP            0x00004000
#define SC_GETHOTPHOSTCOUNT32_CAP     0x00008000
#define SC_CLEARALL_CAP               0x00010000
#define SC_SETREADERKEY_CAP           0x00020000
#define SC_GETCAPABILITIES_CAP        0x80000000

#define SC_PRDISPLAY_STR              "PRDisplay"
#define SC_SETHOST_STR                "SetHost"
#define SC_GETHOST_STR                "GetHost"
#define SC_GETHOSTNAME_STR            "GetHostName"
#define SC_GETHOTP_STR                "GetHOT"
#define SC_SETADMINMODE_STR           "SetAdminMode"
#define SC_SETBALANCECARDINDEX_STR    "SetBalanceCardIndex"
#define SC_SETPIN_STR                 "SetPIN"
#define SC_TESTPIN_STR                "TestPIN"
#define SC_GETVERSION_STR             "GetVersion"
#define SC_SETADMINKEY_STR            "SetAdminKey"
#define SC_SETHOST32_STR              "SetHost32"
#define SC_GETHOST32_STR              "GetHost32"
#define SC_GETHOTPCOUNT32_STR         "GetHOTPCount32"
#define SC_GETHOTPHOST_STR            "GetHOTPHost"
#define SC_GETHOTPHOSTCOUNT32_STR     "GetHOTPHostCount32"
#define SC_CLEARALL_STR               "ClearAll"
#define SC_SETREADERKEY_STR           "SetReaderPIN"
#define SC_GETCAPABILITIES_STR        "GetCapabilities"

#define BC_ESTATE_NEW                  0x00
#define BC_ESTATE_LOAD                 0x01
#define BC_ESTATE_TEST                 0x02
#define BC_ESTATE_RUN                  0x03

#define BC_STATE_NEW_STR               "new"
#define BC_STATE_LOAD_STR              "load"
#define BC_STATE_TEST_STR              "test"
#define BC_STATE_RUN_STR               "run"

#define HOSTNAME_FLAG_MASK      0x80   /* high bit set */
#define HOSTNAME_POS_CHALLENGE  0x00   /* require challenge input */
#define HOSTNAME_POS_READERKEY  1      /* require reader key */
#define HOSTNAME_POS_FMT        2      /* format, 0=hex, 1=decimal */
#define HOSTNAME_POS_FMT3       8      /* 0000=HEX40,   0001=HEX40   */
#define HOSTNAME_POS_FMT2       9      /* 0010=DEC31.6  0011=DEC31.7 */
#define HOSTNAME_POS_FMT1       10     /* 0100=DEC31.8  0101=DEC31.9 */
#define HOSTNAME_POS_FMT0       11     /* 0110=DEC31.10 0111=DHEX40  */


