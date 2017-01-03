'
' Copyright (c) 2005,2006 Mark Fullmer
' Copyright (c) 2009 Mark Fullmer and the Ohio State University
' All rights reserved.
'
' Redistribution and use in source and binary forms, with or without
' modification, are permitted provided that the following conditions
' are met:
' 1. Redistributions of source code must retain the above copyright
'    notice, this list of conditions and the following disclaimer.
' 2. Redistributions in binary form must reproduce the above copyright
'    notice, this list of conditions and the following disclaimer in the
'    documentation and/or other materials provided with the distribution.
'
' THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
' ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
' IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
' ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
' FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
' DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
' OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
' HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
' LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
' OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
' SUCH DAMAGE.
'
'      $Id: HOTPC.BAS 92 2009-12-28 02:45:54Z maf $
'
#include "sha-1.def"
#include "preader.def"
#include "AlgID.DEF"
#include "Commands.def"
#include "hotp.def"

' Disable filesystem
#files 0

Option Explicit

' number of keys/hosts - max 254.  255 is reserved.  Index is 8 bits.
Const HOTPNum = 50

' HOTPCodeVersion notes:
'                 Rev 1 - first production version - feb 2006
'                 Rev 2 - disable AdminMode on first usage - safety net
'                         if left on by mistake.
'                 Rev 3 - Count32 Commands
'                       - conditional compile Commands
'                       - Get/Set/Test naming standardize
'                 Rev 4 - release of Rev3
'                 Rev 5 - renumber Commands, readerKey, getCapabilities
'                       - ClearALL, checkReaderKey
'                 Rev 6 - release Rev5
'                 Rev 7 - dynamic truncate, decimal HOTP, readerKeyFailCount
'                         reset in ClearAll, HOTPCommon, move stack vars
'                         to global, reorg balance reader code
'                         naming consistency, default 50 systems
'                 Rev 8 - release Rev7

' 20 byte scratch area addressable as 5 32bit vars
public str20 as String*20
public tmpb1 as Long at str20
public tmpb2 as Long at str20+4
public tmpb3 as Long at str20+8
public tmpb4 as Long at str20+12
public tmpb5 as Long at str20+16

' 32 bit HOTPCount stored 64 bits.  Top 32 bits always 0
public Count64 as String*8
public Count64low as Long at Count64+4

' Truncated 4 or 5 byte HOTP
public HOTPTruncated as String*5

' HOTPTruncated aliases for 31 bit decimal formats
public u32 as Long at HOTPTruncated
public u32b0 as Byte at u32
public u32b1 as Byte at u32+1
public u32b2 as Byte at u32+2
public u32b3 as Byte at u32+3

' HOTP Format
public HOTPfmt as Byte

' Code version
Const HOTPCodeVersion = 8

' Capabilities (conditionally compiled in functions)
eeprom Capabilities as Long = CAPSETHOST + CAPGETHOST + CAPGETHOSTNAME + _
                             CAPGETHOTP + CAPSETADMINMODE + _
                             CAPSETBALANCECARDINDEX + CAPSETPIN + _
                             CAPTESTPIN + CAPGETVERSION + _
                             CAPSETADMINKEY + CAPSETHOST32 + _
                             CAPGETHOST32 + CAPGETHOTPCOUNT32 + _
                             CAPGETHOTPHOST + CAPGETHOTPHOSTCOUNT32 + _
                             CAPPRDISPLAY + CAPCLEARALL + CAPSETREADERKEY

' Default PIN
Const DefaultPIN = "28165"

' Default Admin Key
eeprom AdminKey as String*20 = "00000000000000000000"

' HOTPK and its derivatives
' default Key "00000000000000000000"
' KeyI is Key XOR input pad (0x36)
' IPAD44 is 0x36 repeated 44 times
' KeyO is Key XOR output pad (0x5c)
' OPAD44 is 0x5c repeated 44 times.

' Note that only the I and O versions of the keys
' are stored -- which is all that's needed.
' An alternative implementation could choose to store
' the key and compute the I and O versions at run time
' this would use less EEPROM space at the cost of more
' CPU cycles (and less battery life) to compute a HOTP

eeprom HOTPKeyI(HOTPNum) as String*20 = &H06,&H06,&H06,&H06,&H06,&H06,&H06, _
                                        &H06,&H06,&H06,&H06,&H06,&H06,&H06, _
                                        &H06,&H06,&H06,&H06,&H06,&H06


eeprom HOTPKeyO(HOTPNum) as String*20 = &H6C,&H6C,&H6C,&H6C,&H6C,&H6C,&H6C, _
                                        &H6C,&H6C,&H6C,&H6C,&H6C,&H6C,&H6C, _
                                        &H6C,&H6C,&H6C,&H6C,&H6C,&H6C

' system hostname
eeprom HOTPHost(HOTPNum) as String*12

' system count
eeprom HOTPCount32(HOTPNum) as Long


' Input pad
eeprom IPAD44 as String*44 = &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36, _
                             &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36, _
                             &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36, _
                             &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36, _
                             &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36


' Output pad
eeprom OPAD44 as String*44 = &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C, _
                             &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C, _
                             &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C, _
                             &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C, _
                             &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C

' Temporary message digest (inner)
eeprom eestr20 as String*20

' PIN - used to deter unauthorized use
eeprom PIN as String*5 = DefaultPIN

' Reader Key.  Weak authentication for reader
eeprom readerKey as String*5 = "00000"

' The balance card can only use one of the host definitions.
eeprom BalanceCardIndex = 255 ' Disabled

' if AdminMode is not set some Commands require a valid PIN to work.
eeprom AdminMode as Byte = 1

' Keep track of PIN failures
eeprom PINFailCount as Byte = 0
eeprom readerKeyFailCount as Byte = 0
Const MaxPINFail = 10
Const MaxReaderKeyFail = 2

declare Sub Truncate(Idx as Byte)

declare Sub HOTPCommon(ReadOnly Idx as Byte, ReadOnly Count as Long, _
  ReadOnly myPIN as String*5, ReadOnly readerKey as String*5)

declare Function CheckReaderKey(ReadOnly Idx as Byte, _
  ReadOnly myKey as String*5) as Byte

declare Function CheckPIN(ReadOnly myPIN as String*5) as Byte

declare Function CheckAdmin() as Byte

declare Function CheckIndex(Idx as Byte) as Byte


' Common HOTP generation code
Sub HOTPCommon(ReadOnly Idx as Byte, ReadOnly Count32 as Long, _
  ReadOnly myPIN as String*5, ReadOnly readerKey as String*5)

  ' disable admin mode on first use.
  if (AdminMode = 1) then
    AdminMode = 0
  end if
 
  ' don't allow operations with default pin
  if myPIN = DefaultPIN then
    SW1SW2 = swAccessDenied
    Exit
  end if
 
  ' Check reader access
  if CheckReaderKey(Idx, readerKey) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if
 
  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  end if

  ' when Count32 == 0, use stored count
  if Count32 <> 0 then
    Count64low = Count32
  else
    Count64low = HOTPCount32(Idx)
  end if

  Call ShaStart()
  Call ShaAppend(HOTPKeyI(Idx))
  Call ShaAppend(IPAD44)
  Call ShaAppend(Count64)
  str20 = ShaEnd()
 
  Call ShaStart()
  Call ShaAppend(HOTPKeyO(Idx))
  Call ShaAppend(OPAD44)
  Call ShaAppend(str20)
  str20 = ShaEnd()
 
  Disable OverflowCheck
  HOTPCount32(Idx) = Count64low + 1
  Enable OverflowCheck

  ' Set HOTPTruncated
  Call Truncate(Idx)

End Sub ' HOTPCommon

' Convert 160 bit String to 4 or 5 Bytes and format for reader
Sub Truncate(Idx as Byte)
  private offset as Byte

  HOTPfmt = 0

  if (asc(HOTPHost(Idx)(12)) AND &H80) then
    HOTPfmt = 1
  end if

  if (asc(HOTPHost(Idx)(11)) AND &H80) then
    HOTPfmt = HOTPfmt or 2
  end if

  if (asc(HOTPHost(Idx)(10)) AND &H80) then
    HOTPfmt = HOTPfmt or 4
  end if

' future?
'  if (asc(HOTPHost(Idx)(9)) AND &H80) then
'    HOTPfmt = HOTPfmt or 8
'  end if

' not suport on ZC3.9 card
'  HOTPfmt = (asc(HOTPHost(Idx)(12)) AND &H80) SHRL 7
'  HOTPfmt = fmt OR ((asc(HOTPHost(Idx)(11)) AND &H80) SHRL 6)
'  HOTPfmt = fmt OR ((asc(HOTPHost(Idx)(10)) AND &H80) SHRL 5)
'  HOTPfmt = fmt OR ((asc(HOTPHost(Idx)(9)) AND &H80) SHRL 4)

  if (HOTPfmt = FMTHEX40) or (HOTPfmt = 0) then
    HOTPTruncated = Left$(str20,5)
    Exit Sub
  end if

  offset = asc(str20(20)) and &H0F

  if (HOTPfmt = FMTDHEX40) then
    HOTPTruncated = Mid$(str20,offset+1,5)
    Exit Sub
  end if

  ' u32b0..3 are bytes of u32 alias for HOTPtruncated
  u32b0 = asc(str20(offset+1)) and &H7F
  u32b1 = asc(str20(offset+2))
  u32b2 = asc(str20(offset+3))
  u32b3 = asc(str20(offset+4))

  if (HOTPfmt = FMTDEC316) then
    u32 = u32 mod 1000000
  elseif (HOTPfmt = FMTDEC317) then
    u32 = u32 mod 10000000
  elseif (HOTPfmt = FMTDEC318) then
    u32 = u32 mod 100000000
  elseif (HOTPfmt = FMTDEC319) then
    u32 = u32 mod 1000000000
  ' FMTDEC3110 does not require mod
  end if
    
End Sub ' Truncate

Function CheckPIN(ReadOnly myPIN as String*5) as Byte

  if AdminMode = 1 then
    CheckPIN = 0 ' success
    PINFailCount = 0 ' reset
  else
    if PINFailCount >= MaxPINFail then
      CheckPIN = 2 ' fail
    else
      if myPIN <> PIN then
        CheckPIN = 1 ' fail
        PINFailCount = PINFailCount + 1
      else
        CheckPIN = 0 ' Success
        PINFailCount = 0
      end if
    end if
  end if

End Function ' CheckPIN

Function CheckReaderKey(ReadOnly Idx as Byte, _
  ReadOnly myKey as String*5) as Byte

  if (Asc(HOTPHost(Idx)(2)) AND &H80) then
    if myKey <> readerKey then
      readerKeyFailCount = readerKeyFailCount + 1
      if (readerKeyFailCount >= MAXReaderKeyFail) then
        PINFailCount = MaxPINFail ' Lock card
      end if
      CheckReaderKey = 1 ' Fail
    else
      readerKeyFailCount = 0
      CheckReaderKey = 0 ' Success
    end if
  else
    CheckReaderKey = 0 'Success
  end if

End Function ' CheckReaderKey

Function CheckAdmin() as Byte

  if AdminMode <> 1 then
    CheckAdmin = 1 ' fail
  else
    CheckAdmin = 0 ' success
  end if

End Function ' CheckAdmin

Function CheckIndex(Idx as Byte) as Byte

  if Idx > HOTPNum then
    CheckIndex = 1
  else
    CheckIndex = 0
  end if

End Function ' CheckIndex

#ifdef ENABLECSETHOST
Command &H80 &H40 SetHost(Idx as Byte, Count as Integer, _
  HostName as String*12, HOTPKey as String*20)

  if CheckAdmin() <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  End if

  ' store K
  ' HOTPKey(n) = K

  ' store K XOR IPAD
  str20 = HOTPKey
  tmpb1 = tmpb1 xor &H36363636
  tmpb2 = tmpb2 xor &H36363636
  tmpb3 = tmpb3 xor &H36363636
  tmpb4 = tmpb4 xor &H36363636
  tmpb5 = tmpb5 xor &H36363636
  HOTPKeyI(Idx) = str20

  ' store K XOR OPAD
  str20 = HOTPKey
  tmpb1 = tmpb1 xor &H5C5C5C5C
  tmpb2 = tmpb2 xor &H5C5C5C5C
  tmpb3 = tmpb3 xor &H5C5C5C5C
  tmpb4 = tmpb4 xor &H5C5C5C5C
  tmpb5 = tmpb5 xor &H5C5C5C5C
  HOTPKeyO(Idx) = str20

  HOTPCount32(Idx) = Count
  HOTPHost(Idx) = HostName

End Command ' SetHost
#endif 'ENABLECSETHOST

#ifdef ENABLECGETHOST
Command &H80 &H42 GetHost(Idx as Byte, Count as Integer, _
  HostName as String*12, HOTPKey as String*20)

  if CheckAdmin() <> 0 then
    sw1sw2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    sw1sw2 = swDataNotFound
    Exit
  end if

  Count = HOTPCount32(Idx)
  HostName = HOTPHost(Idx)

  ' load K XOR IPAD
  ' could also do this with OPAD...
  str20 = HOTPKeyI(Idx)
  tmpb1 = tmpb1 xor &H36363636
  tmpb2 = tmpb2 xor &H36363636
  tmpb3 = tmpb3 xor &H36363636
  tmpb4 = tmpb4 xor &H36363636
  tmpb5 = tmpb5 xor &H36363636

  HOTPKey = str20

End Command ' GetHost
#endif 'ENABLECGETHOST

#ifdef ENABLECGETHOSTNAME
Command &H80 &H44 GetHostName(Idx as Byte, myPIN as String*5,_
  HostName as String*12)

  if CheckPIN(myPIN) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  end if

  HostName = HOTPHost(Idx)

End Command ' GetHostName
#endif 'ENABLECGETHOSTNAME

#ifdef ENABLECGETHOTP
Command &H80 &H46 GetHOTP(Idx as Byte, myPIN as String*5, HOTP as String*5)

  Call HOTPCommon(Idx, 0, myPIN, HOTP)
  HOTP = HOTPTruncated

End Command ' GetHOTP
#endif 'ENABLECGETHOTP

#ifdef ENABLECSETADMINMODE
Command &H80 &H48 SetAdminMode(Mode as Byte, K as String*20)

  if K <> AdminKey then
    SW1SW2 = swAccessDenied
  else
    AdminMode = Mode
  end if

End Command ' SetAdminMode
#endif 'ENABLECSETADMINMODE

#ifdef ENABLECSETBALANCECARDINDEX
Command &H80 &H4A SetBalanceCardIndex(Idx as Byte)

  if CheckAdmin() <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  else
    BalanceCardIndex = Idx
  end if

End Command ' SetBalanceCardIndex
#endif 'ENABLECSETBALANCECARDINDEX

#ifdef ENABLECSETPIN
Command &H80 &H4C SetPIN(myPIN as String*5, newPIN as String*5)

  if CheckPIN(myPIN) <> 0 then
    SW1SW2 = swAccessDenied
  else
    PIN = newPIN
  end if

End Command ' SetPIN
#endif 'ENABLECSETPIN

#ifdef ENABLECTESTPIN
Command &H80 &H4E TestPIN(myPIN as String*5)
  private t as Byte

  t = CheckPIN(myPIN)

  if t <> 0 then
    if t = 2 then
      SW1SW2 = swBadAuthenticate ' too many tries
    else
      SW1SW2 = swAccessDenied
    end if
  end if

End Command ' TestPIN
#endif 'ENABLECTESTPIN

#ifdef ENABLECGETVERSION
Command &H80 &H50 GetVersion(V as Byte)

  V = HOTPCodeVersion

End Command ' GetVersion
#endif 'ENABLECGETVERSION

#ifdef ENABLECSETADMINKEY
Command &H80 &H52 SetAdminKey(K as String*20)

  if CheckAdmin() <> 0 then
    sw1sw2 = swAccessDenied
    Exit
  end if
  AdminKey = K

End Command ' SetAdminKey
#endif 'ENABLECSETADMINKEY

#ifdef ENABLECSETHOST32
Command &H80 &H54 SetHost32(Idx as Byte, Count32 as Long,_
  HostName as String*12, HOTPKey as String*20)

  if CheckAdmin() <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  End if

  HOTPCount32(Idx) = Count32
  HOTPHost(Idx) = HostName

  ' store K
  ' HOTPKey(n) = K

  ' store K XOR IPAD
  str20 = HOTPKey
  tmpb1 = tmpb1 xor &H36363636
  tmpb2 = tmpb2 xor &H36363636
  tmpb3 = tmpb3 xor &H36363636
  tmpb4 = tmpb4 xor &H36363636
  tmpb5 = tmpb5 xor &H36363636
  HOTPKeyI(Idx) = str20

  ' store K XOR OPAD
  str20 = HOTPKey
  tmpb1 = tmpb1 xor &H5C5C5C5C
  tmpb2 = tmpb2 xor &H5C5C5C5C
  tmpb3 = tmpb3 xor &H5C5C5C5C
  tmpb4 = tmpb4 xor &H5C5C5C5C
  tmpb5 = tmpb5 xor &H5C5C5C5C
  HOTPKeyO(Idx) = str20

End Command ' SetHost32
#endif 'ENABLECSETHOST32

#ifdef ENABLECGETHOST32
Command &H80 &H56 GetHost32(Idx as Byte, Count32 as Long,_
  HostName as String*12, HOTPKey as String*20)

  if CheckAdmin() <> 0 then
    sw1sw2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    sw1sw2 = swDataNotFound
    Exit
  end if

  Count32 = HOTPCount32(Idx)
  HostName = HOTPHost(Idx)

  ' load K XOR IPAD
  ' could also do this with OPAD...
  str20 = HOTPKeyI(Idx)
  tmpb1 = tmpb1 xor &H36363636
  tmpb2 = tmpb2 xor &H36363636
  tmpb3 = tmpb3 xor &H36363636
  tmpb4 = tmpb4 xor &H36363636
  tmpb5 = tmpb5 xor &H36363636

  HOTPKey = str20

End Command ' GetHost32
#endif 'ENABLECGETHOST32

#ifdef ENABLECGETHOTPCOUNT32
Command &H80 &H58 GetHOTPCount32(Idx as Byte, myPIN as String*5,_
  Count32 as Long, HOTP as String*5)

  Call HOTPCommon(Idx, Count32, myPIN, HOTP)
  HOTP = HOTPTruncated

End Command ' GetHOTPCount32
#endif 'ENABE_GETHOTPCOUNT32

#ifdef ENABLECGETHOTPHOST
Command &H80 &H5A GetHOTPHost(Idx as Byte, myPIN as String*5,_
  HOTP as String*5, HostName as String*12)

  Call HOTPCommon(Idx, 0, myPIN, HOTP)
  HOTP = HOTPTruncated
  HostName = HOTPHost(Idx)

End Command ' GetHOTPHost
#endif 'ENABLECGETHOTPHOST

#ifdef ENABLECGETHOTPHOSTCOUNT32
Command &H80 &H5C GetHOTPHostCount32(Idx as Byte, myPIN as String*5,_
  Count32 as Long, HOTP as String*5, HostName as String*12)

  Call HOTPCommon(Idx, Count32, myPIN, readerKey)
  HOTP = HOTPTruncated
  HostName = HOTPHost(Idx)

End Command ' GetHOTPHostCount32
#endif 'ENABLECGETHOTPHOSTCOUNT32

#ifdef ENABLECCLEARALL
Command &H80 &H5E ClearAll()
  private i,j as Integer

  if CheckAdmin() <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  for i = 0 to HOTPNum

    HOTPKeyI(i) = Chr$(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    HOTPKeyO(i) = Chr$(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    HOTPCount32(i) = 0
    HOTPHost(i) = Chr$(0,0,0,0,0,0,0,0,0,0,0,0)
  next i

  BalanceCardIndex = 255

  PINFailCount = 0

  readerKeyFailCount = 0

  AdminMode = 1

  AdminKey = "00000000000000000000"

  PIN = DefaultPIN

End Command ' ClearAll
#endif 'ENABLECCLEARALL

#ifdef ENABLESETREADERKEY
Command &H80 &H60 SetReaderKey(myKey as String*5)

  if CheckAdmin() <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  readerKey = myKey

End Command ' SetReaderKey
#endif 'ENABLECSETREADERKEY

Command &H80 &H90 GetCapabilities(C as Long)

  C = Capabilities

End Command ' GetCapabilities

'
' The balance reader doesn't wait Long for a reponse so the HMAC must be
' computed in steps
'

#ifdef ENABLECPRDISPLAY
Command &HC8 &H00 PRDisplay(RecordNumber as Byte, DataFormat as Byte, _
                            DigitCount as Byte,DecimalPoint as Byte, _
                            Delay as Byte, MoreData as Byte, _
                            Data as String)

  select case RecordNumber

     case 0
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 0
        Delay = 1
        MoreData = PRMoreData

        ' disable admin mode on first use.
        if (AdminMode = 1) then
          AdminMode = 0
        end if

        if BalanceCardIndex = 255 then
          data = "Not Enabled"
          dataFormat = PRAlpha
          Exit Command
        end if

        Count64low = HOTPCount32(BalanceCardIndex)

        ' Display VER8-count
        data = "VER8-" + hex$(Count64low)

        ' start inner hash of HMAC SHA-160(K XOR ipad,text)
        Call ShaStart()
        Call ShaAppend(HOTPKeyI(BalanceCardIndex))

     case 1
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 6
        Delay = 1
        MoreData = PRMoreData
        data = "HOTP"

        Count64low = HOTPcount32(BalanceCardIndex)

        ' inner hash still working
        Call ShaAppend(IPAD44)
        Call ShaAppend(Count64)

      case 2
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 5
        Delay = 1
        MoreData = PRMoreData
        Data = "HOTP"

        ' done with inner hash.  Store temp result in eestr20 while
        ' balance reader resets
        eestr20 = ShaEnd()

      case 3
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 4
        Delay = 1
        MoreData = PRMoreData
        Data = "HOTP"

        ' start outer hash H(K XOR opad, inner)
        Call ShaStart()
        Call ShaAppend(HOTPKeyO(BalanceCardIndex))

     case 4
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 3
        Delay = 1
        MoreData = PRMoreData
        data = "HOTP"

        ' outer still working.
        Call ShaAppend(OPAD44)

      case 5
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 2
        Delay = 1
        MoreData = PRMoreData
        data = "HOTP"

        ' outer still working...
        Call ShaAppend(eestr20)

        ' Increment Count just before displaying result.

        Disable OverflowCheck
        HOTPCount32(BalanceCardIndex) = HOTPCount32(BalanceCardIndex) + 1
        Enable OverflowCheck

      case 6
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 1
        Delay = 1
        MoreData = PRMoreData
        data = "HOTP"

        ' finish with outer
        eestr20 = ShaEnd()

      case 7
        Delay = 10000 / PRDelayUnits ' display 10 seconds
        DecimalPoint = 0
        MoreData = PRNoMoreData
        str20 = eestr20
        ' sets HOTPfmt, HOTPTruncated
        Call Truncate(BalanceCardIndex)

        if (HOTPfmt = 0) or (HOTPfmt = FMTHEX40) or (HOTPfmt = FMTDHEX40) then
          DataFormat = PRHex
          DigitCount = 10
          ' data must be 8 Bytes Long.  3 high order Bytes ignored by reader
          data = "000" + HOTPTruncated
        else
          DataFormat = PRNum
          DigitCount = 10
          ' data must be 4 Bytes Long.
          data = Left$(HOTPTruncated,4)
        end if

      case else
        ' should not happen
        SW1SW2=swDataNotFound
  end select

End Command ' PRDisplay

#endif ' ENABLECPRDISPLAY
