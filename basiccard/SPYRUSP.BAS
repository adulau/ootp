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
'      $Id: SPYRUSP.BAS 13 2009-11-26 16:37:03Z maf $
'

#include "commands.def"

Option Explicit

' number of blocks
Const EEBlocks = 16

' EEProm has 256 bytes organized here into 16 blocks of 16 bytes
' the high bit on EEFlag indicates if the next block is in use
eeprom EEBlock(EEBlocks) as string*16
eeprom EEFlag(EEBlocks) as byte

command &H80 &HA0 SetSpyrusEEBlock(idx as byte, blockData as string*16)
  private idxVal as Byte

  idxVal = idx and &H7F
  EEBlock(idxVal) = blockData
  EEFlag(idxVal) = idx and &H80

end command

command &H80 &HA2 GetSpyrusEEBlock(idx as byte, blockData as string*16)

  if (idx >= EEBlocks) then
    SW1SW2 = swDataNotFound
    exit
  end if

  blockData = EEBlock(idx)
  if (EEFlag(idx) and &H80) then
    idx = idx or &H80
  end if

end command

