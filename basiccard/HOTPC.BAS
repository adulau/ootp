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
'      $Id: HOTPC.BAS 13 2009-11-26 16:37:03Z maf $
'
#include "sha-1.def"
#include "preader.def"
#include "AlgID.DEF"
#include "commands.def"
#include "hotp.def"

Option Explicit

' number of keys/hosts - max 254.  255 is reserved.  Index is 8 bits.
Const HOTPNum = 85

' HOTPCodeVersion notes:
'                 Rev 1 - first production version - feb 2006
'                 Rev 2 - disable AdminMode on first usage - safety net
'                         if left on by mistake.
'                 Rev 3 - Count32 commands
'                       - conditional compile commands
'                       - Get/Set/Test naming standardize
'                 Rev 4 - release of Rev3
'                 Rev 5 - renumber commands, readerKey, getCapabilities
'                       - ClearALL, checkReaderKey
'                 Rev 6 - release Rev5

' Code version
Const HOTPCodeVersion = 6

' Capabilities (conditionally compiled in functions)
eeprom Capabilities as Long = CAPSETHOST + CAPGETHOST + CAPGETHOSTNAME + _
                             CAPGETHOTP + CAPSETADMINMODE + _
                             CAPSETBALANCECARDINDEX + CAPSETPIN + _
                             CAPTESTPIN + CAPGETVERSION + _
                             CAPSETADMINKEY + CAPSETHOST32 + _
                             CAPGETHOST32 + CAPGETHOTPCOUNT32 + _
                             CAPGETHOTPHOST + CAPGETHOTPHOSTCOUNT32 + _
                             CAPPRDISPLAY + CAPCLEARALL + CAPSETREADERKEY

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

eeprom HOTPKeyI(HOTPNum) as string*20 = &H06,&H06,&H06,&H06,&H06,&H06,&H06, _
                                        &H06,&H06,&H06,&H06,&H06,&H06,&H06, _
                                        &H06,&H06,&H06,&H06,&H06,&H06


eeprom HOTPKeyO(HOTPNum) as string*20 = &H6C,&H6C,&H6C,&H6C,&H6C,&H6C,&H6C, _
                                        &H6C,&H6C,&H6C,&H6C,&H6C,&H6C,&H6C, _
                                        &H6C,&H6C,&H6C,&H6C,&H6C,&H6C

eeprom HOTPHost(HOTPNum) as string*12

eeprom HOTPCount32(HOTPNum) as Long


' Input pad
eeprom IPAD44 as string*44 = &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36, _
                             &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36, _
                             &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36, _
                             &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36, _
                             &H36,&H36,&H36,&H36,&H36,&H36,&H36,&H36


' Output pad
eeprom OPAD44 as string*44 = &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C, _
                             &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C, _
                             &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C, _
                             &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C, _
                             &H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C,&H5C

' Temporary message digest (inner)
eeprom md1 as string*20

' PIN - used to deter unauthorized use
eeprom PIN as string*5 = DefaultPIN

' Reader Key.  Weak authentication for reader
eeprom readerKey as string*5 = "00000"

' The balance card can only use one of the host definitions.
eeprom BalanceCardIndex = 255 ' Disabled

' if AdminMode is not set some commands require a valid PIN to work.
eeprom AdminMode as Byte = 1

' Keep track of PIN failures
eeprom PINFailCount as Byte = 0
eeprom readerKeyFailCount as Byte = 0
Const MaxPINFail = 10
Const MaxReaderKeyFail = 2

Function CheckPIN(myPIN as string*5) as Byte

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
end Function

Function CheckReaderKey(idx as Byte, myKey as String*5) as Byte
  if (Asc(HOTPHost(idx)(2)) AND &H80) then
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
end Function

Function CheckAdmin() as Byte
  if AdminMode <> 1 then
    CheckAdmin = 1 ' fail
  else
    CheckAdmin = 0 ' success
  end if
end Function

Function CheckIndex(Idx as Byte) as Byte
  if Idx > HOTPNum then
    CheckIndex = 1
  else
    CheckIndex = 0
  end if
end function

'
' The balance reader doesn't wait long for a reponse so the HMAC must be
' broken up into steps
'
' HMAC as defined in RFC2104 is H(K XOR opad, H(K XOR ipad, text))
'   where K is the key
'   ipad=0x36
'   opad=0x5c
'   H=SHA-160
'   text=Count
'

#ifdef ENABLEPRDISPLAY
Command &HC8 &H00 PRDisplay(RecordNumber as Byte, DataFormat as Byte, _
                            DigitCount as Byte,DecimalPoint as Byte, _
                            Delay as Byte, MoreData as Byte, _
                            Data as String)

  private str11 as string*11
  private str8 as string*8
  private str4 as string*4 at str8+4
  private low as long at str8+4
  private high as long at str8

  if BalanceCardIndex = 255 then
    data = "Not Enabled"
    dataFormat = PRAlpha
    exit command
  end if

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

        low = HOTPCount32(0)

        ' Display VER1-count
        data = "VER1-" + hex$(low)

        ' start inner hash of HMAC SHA-160(K XOR ipad,text)
        call ShaStart()
        call ShaAppend(HOTPKeyI(0))

     case 1
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 6
        Delay = 1
        MoreData = PRMoreData
        data = "HOTP"

        low = HOTPcount(0)

        ' inner hash still working
        call ShaAppend(IPAD44)
        call ShaAppend(str8)

      case 2
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 5
        Delay = 1
        MoreData = PRMoreData
        Data = "HOTP"

        ' done with inner hash.  Store temp result in md1
        md1 = ShaEnd()

      case 3
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 4
        Delay = 1
        MoreData = PRMoreData
        Data = "HOTP"

        ' start outer hash H(K XOR opad, inner)
        call ShaStart()
        call ShaAppend(HOTPKeyO(0))

     case 4
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 3
        Delay = 1
        MoreData = PRMoreData
        data = "HOTP"

        ' outer still working.
        call ShaAppend(OPAD44)

      case 5
        DataFormat = PRAlpha
        DigitCount = 0
        DecimalPoint = 2
        Delay = 1
        MoreData = PRMoreData
        data = "HOTP"

        ' outer still working...
        call ShaAppend(md1)

        ' Increment Count just before displaying result.

        Disable OverflowCheck
        HOTPCount32(0) = HOTPCount32(0) + 1
        Enable OverflowCheck

      case 6
        DataFormat = PRHex
        DigitCount = 10
        DecimalPoint = 0
        Delay = 10000 / PRDelayUnits ' display 10 seconds
        MoreData = PRNoMoreData

        ' finish with outer, display top 40 bits in hex (no leading 0's).
        str11 = "000" + left$(ShaEnd(),8)
        data = left$(str11,8)

      case else
        ' should not happen
        SW1SW2=swDataNotFound
  end select
End Command
#endif ' ENABLECPRDISPLAY

#ifdef ENABLECSETHOST
command &H80 &H40 SetHost(Idx as Byte, Count as Integer, _
  HostName as String*12, HOTPKey as String*20)

  private tmp as string*20
  private tmpb1 as long at tmp
  private tmpb2 as long at tmp+4
  private tmpb3 as long at tmp+8
  private tmpb4 as long at tmp+12
  private tmpb5 as long at tmp+16

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
  tmp = HOTPKey
  tmpb1 = tmpb1 xor &H36363636
  tmpb2 = tmpb2 xor &H36363636
  tmpb3 = tmpb3 xor &H36363636
  tmpb4 = tmpb4 xor &H36363636
  tmpb5 = tmpb5 xor &H36363636
  HOTPKeyI(idx) = tmp

  ' store K XOR OPAD
  tmp = HOTPKey
  tmpb1 = tmpb1 xor &H5C5C5C5C
  tmpb2 = tmpb2 xor &H5C5C5C5C
  tmpb3 = tmpb3 xor &H5C5C5C5C
  tmpb4 = tmpb4 xor &H5C5C5C5C
  tmpb5 = tmpb5 xor &H5C5C5C5C
  HOTPKeyO(idx) = tmp

  HOTPCount32(Idx) = Count
  HOTPHost(Idx) = HostName

end command
#endif 'ENABLECSETHOST

#ifdef ENABLECGETHOST
' GetHost
command &H80 &H42 GetHost(Idx as Byte, Count as Integer, _
  HostName as String*12, HOTPKey as String*20)

  private tmp as string*20
  private tmpb1 as long at tmp
  private tmpb2 as long at tmp+4
  private tmpb3 as long at tmp+8
  private tmpb4 as long at tmp+12
  private tmpb5 as long at tmp+16

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
  tmp = HOTPKeyI(Idx)
  tmpb1 = tmpb1 xor &H36363636
  tmpb2 = tmpb2 xor &H36363636
  tmpb3 = tmpb3 xor &H36363636
  tmpb4 = tmpb4 xor &H36363636
  tmpb5 = tmpb5 xor &H36363636

  HOTPKey = tmp

end command
#endif 'ENABLECGETHOST

#ifdef ENABLECGETHOSTNAME
command &H80 &H44 GetHostName(Idx as Byte, myPIN as String*5,_
  HostName as String*12)

  if CheckPIN(myPIN) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  end if

  HostName = HOTPHost(idx)

end command
#endif 'ENABLECGETHOSTNAME

#ifdef ENABLECGETHOTP
command &H80 &H46 GetHOTP(Idx as Byte, myPIN as String*5, HOTP as String*5)

  private str8 as string*8
  private low as long at str8+4

  if CheckPIN(myPIN) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

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
  if CheckReaderKey(Idx, HOTP) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  end if

  low = HOTPCount32(idx)

  call ShaStart()
  call ShaAppend(HOTPKeyI(idx))
  call ShaAppend(IPAD44)
  call ShaAppend(str8)
  md1 = ShaEnd()

  call ShaStart()
  call ShaAppend(HOTPKeyO(idx))
  call ShaAppend(OPAD44)
  call ShaAppend(md1)

  Disable OverflowCheck
  HOTPCount32(idx) = low + 1
  Enable OverflowCheck

  HOTP = left$(ShaEnd(),5)

end command
#endif 'ENABLECGETHOTP

#ifdef ENABLECSETADMINMODE
command &H80 &H48 SetAdminMode(Mode as Byte, K as String*20)

  if K <> AdminKey then
    SW1SW2 = swAccessDenied
  else
    AdminMode = Mode
  end if

end command
#endif 'ENABLECSETADMINMODE

#ifdef ENABLECSETBALANCECARDINDEX
command &H80 &H4A SetBalanceCardIndex(Idx as Byte)

  if CheckAdmin() <> 0 then
    SW1SW2 = swAccessDenied
    exit
  else
    BalanceCardIndex = Idx
  end if

end command
#endif 'ENABLECSETBALANCECARDINDEX

#ifdef ENABLECSETPIN
command &H80 &H4C SetPIN(myPIN as String*5, newPIN as String*5)

  if CheckPIN(myPIN) <> 0 then
    SW1SW2 = swAccessDenied
  else
    PIN = newPIN
  end if

end command
#endif 'ENABLECSETPIN

#ifdef ENABLECTESTPIN
command &H80 &H4E TestPIN(myPIN as String*5)
  private t as Byte

  t = CheckPIN(myPIN)

  if t <> 0 then
    if t = 2 then
      SW1SW2 = swBadAuthenticate ' too many tries
    else
      SW1SW2 = swAccessDenied
    end if
  end if

end command
#endif 'ENABLECTESTPIN

#ifdef ENABLECGETVERSION
command &H80 &H50 GetVersion(V as Byte)

  V = HOTPCodeVersion

end command
#endif 'ENABLECGETVERSION

#ifdef ENABLECSETADMINKEY
command &H80 &H52 SetAdminKey(K as String*20)

  if CheckAdmin() <> 0 then
    sw1sw2 = swAccessDenied
    Exit
  end if
  AdminKey = K

end command
#endif 'ENABLECSETADMINKEY

#ifdef ENABLECSETHOST32
command &H80 &H54 SetHost32(Idx as Byte, Count32 as Long,_
  HostName as String*12, HOTPKey as String*20)

  private tmp as string*20
  private tmpb1 as long at tmp
  private tmpb2 as long at tmp+4
  private tmpb3 as long at tmp+8
  private tmpb4 as long at tmp+12
  private tmpb5 as long at tmp+16

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
  tmp = HOTPKey
  tmpb1 = tmpb1 xor &H36363636
  tmpb2 = tmpb2 xor &H36363636
  tmpb3 = tmpb3 xor &H36363636
  tmpb4 = tmpb4 xor &H36363636
  tmpb5 = tmpb5 xor &H36363636
  HOTPKeyI(idx) = tmp

  ' store K XOR OPAD
  tmp = HOTPKey
  tmpb1 = tmpb1 xor &H5C5C5C5C
  tmpb2 = tmpb2 xor &H5C5C5C5C
  tmpb3 = tmpb3 xor &H5C5C5C5C
  tmpb4 = tmpb4 xor &H5C5C5C5C
  tmpb5 = tmpb5 xor &H5C5C5C5C
  HOTPKeyO(idx) = tmp

end command
#endif 'ENABLECSETHOST32

#ifdef ENABLECGETHOST32
command &H80 &H56 GetHost32(Idx as Byte, Count32 as Long,_
  HostName as String*12, HOTPKey as String*20)

  private tmp as string*20
  private tmpb1 as long at tmp
  private tmpb2 as long at tmp+4
  private tmpb3 as long at tmp+8
  private tmpb4 as long at tmp+12
  private tmpb5 as long at tmp+16

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
  tmp = HOTPKeyI(Idx)
  tmpb1 = tmpb1 xor &H36363636
  tmpb2 = tmpb2 xor &H36363636
  tmpb3 = tmpb3 xor &H36363636
  tmpb4 = tmpb4 xor &H36363636
  tmpb5 = tmpb5 xor &H36363636

  HOTPKey = tmp

end command
#endif 'ENABLECGETHOST32

#ifdef ENABLECGETHOTPCOUNT32
command &H80 &H58 GetHOTPCount32(Idx as Byte, myPIN as String*5,_
  Count32 as Long, HOTP as String*5)

  private str8 as string*8
  private low as long at str8+4

  if CheckPIN(myPIN) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

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
  if CheckReaderKey(Idx, HOTP) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  end if

  ' when Count32 == 0, use stored count
  if Count32 <> 0 then
    low = Count32
  else
    low = HOTPCount32(idx)
  end if

  call ShaStart()
  call ShaAppend(HOTPKeyI(idx))
  call ShaAppend(IPAD44)
  call ShaAppend(str8)
  md1 = ShaEnd()

  call ShaStart()
  call ShaAppend(HOTPKeyO(idx))
  call ShaAppend(OPAD44)
  call ShaAppend(md1)

  Disable OverflowCheck
  HOTPCount32(idx) = low + 1
  Enable OverflowCheck

  HOTP = left$(ShaEnd(),5)

end command
#endif 'ENABE_GETHOTPCOUNT32

#ifdef ENABLECGETHOTPHOST
command &H80 &H5A GetHOTPHost(Idx as Byte, myPIN as String*5,_
  HOTP as String*5, HostName as String*12)

  private str8 as string*8
  private low as long at str8+4

  if CheckPIN(myPIN) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

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
  if CheckReaderKey(Idx, HOTP) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  end if

  low = HOTPCount32(idx)

  call ShaStart()
  call ShaAppend(HOTPKeyI(idx))
  call ShaAppend(IPAD44)
  call ShaAppend(str8)
  md1 = ShaEnd()

  call ShaStart()
  call ShaAppend(HOTPKeyO(idx))
  call ShaAppend(OPAD44)
  call ShaAppend(md1)

  Disable OverflowCheck
  HOTPCount32(idx) = low + 1
  Enable OverflowCheck

  HOTP = left$(ShaEnd(),5)
  HostName = HOTPHost(Idx)

end command
#endif 'ENABLECGETHOTPHOST

#ifdef ENABLECGETHOTPHOSTCOUNT32
command &H80 &H5C GetHOTPHostCount32(Idx as Byte, myPIN as String*5,_
  Count32 as Long, HOTP as String*5, HostName as String*12)

  private str8 as string*8
  private low as long at str8+4

  if CheckPIN(myPIN) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

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
  if CheckReaderKey(Idx, HOTP) <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  if CheckIndex(Idx) <> 0 then
    SW1SW2 = swDataNotFound
    Exit
  end if

  ' when Count32 == 0, use stored count
  if Count32 <> 0 then
    low = Count32
  else
    low = HOTPCount32(idx)
  end if

  call ShaStart()
  call ShaAppend(HOTPKeyI(idx))
  call ShaAppend(IPAD44)
  call ShaAppend(str8)
  md1 = ShaEnd()

  call ShaStart()
  call ShaAppend(HOTPKeyO(idx))
  call ShaAppend(OPAD44)
  call ShaAppend(md1)

  Disable OverflowCheck
  HOTPCount32(idx) = low + 1
  Enable OverflowCheck

  HOTP = left$(ShaEnd(),5)
  HostName = HOTPHost(Idx)

end command
#endif 'ENABLECGETHOTPHOSTCOUNT32

#ifdef ENABLECCLEARALL
command &H80 &H5E ClearAll()
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

  AdminMode = 1

  AdminKey = "00000000000000000000"

  PIN = DefaultPIN

end command
#endif 'ENABLECCLEARALL

#ifdef ENABLESETREADERKEY
command &H80 &H60 SetReaderKey(myKey as String*5)

  if CheckAdmin() <> 0 then
    SW1SW2 = swAccessDenied
    Exit
  end if

  readerKey = myKey

end command

#endif 'ENABLECSETREADERKEY


command &H80 &H90 GetCapabilities(C as Long)

  C = Capabilities

end command


