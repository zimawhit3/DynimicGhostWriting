#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import json, macros

from typedefs import PPEB, PVOID, BYTE, PBYTE, LARGE_INTEGER, HGEntry, WORD, LIST_ENTRY, PLIST_ENTRY,
                     PLDR_DATA_TABLE_ENTRY, LDR_DATA_TABLE_ENTRY


template `->`*[T](p: T; x: untyped): int =
    cast[int](p) + p.offsetOf(x)
  
func `-->`*(address: int, offset : SomeInteger): BYTE {.inline.} =
    result = cast[PBYTE](address +% offset)[]

func LargeIntToInt64*(Value: LARGE_INTEGER) : int64 =
    result = Value.QuadPart.int64

func alignByteBoundary*(ByteSequence: var seq[Byte]) =
    ## Aligns Byte Sequence to an 8 byte boundary with nop opcodes
    let
        PadByte : byte = 0x90
    while ByteSequence.len() mod 8 != 0:
        ByteSequence.add(PadByte)

func readHexChar*(c: char): byte {.raises: [ValueError], inline.} =
  case c
  of '0'..'9': result = byte(ord(c) - ord('0'))
  of 'a'..'f': result = byte(ord(c) - ord('a') + 10)
  of 'A'..'F': result = byte(ord(c) - ord('A') + 10)
  else:
    raise newException(ValueError, $c & " is not a hexademical character")

iterator next0xPrefix(nodeStr: string): byte =
    var
        index : int = 0
    while index < nodeStr.len():       
        if nodeStr[index] == '0' and nodeStr[index+1] in {'x', 'X'}:
            yield (nodeStr[index+2].readHexChar() shl 4 or nodeStr[index+3].readHexChar())         
            index += 5
            continue
        inc index

func removeNullChars*(s: var string) =
    var
        index : int = 0
    for ch in s:    
        if ord(ch) == 0:
            break
        inc index
    s.setLen(index)

proc gadgetNodes*(Node : JsonNode): iterator(): JsonNode =
    if Node.kind != JArray:
        raise newException(JsonKindError, "Incorrect Node kind " & $Node.kind)
    result = iterator(): JsonNode {.closure.} =
        for gnode in Node.elems:
            yield gnode

proc argNodes*(Node: JsonNode): iterator(): JsonNode =
    if Node.kind != JArray:
        raise newException(JsonKindError, "Incorrect Node kind " & $Node.kind)
    result = iterator(): JsonNode {.closure.} =
        for outernode in Node.elems:
            if outernode.kind != JArray:
                raise newException(JsonKindError, "Incorrect Node kind " & $outernode.kind)
            for innernode in outernode.elems:
                yield innernode

proc getSeqByte*(param1: JsonNode): seq[byte] {.raises: [ValueError] .} =
    if param1 == nil:
        return
    var
        resSeq = newSeq[Byte]()
        jsonStr: string

    if param1.kind == JString:
        jsonStr = param1.getStr()
        for byteVal in jsonStr.next0xPrefix():
            resSeq.add(byteVal)
        result = resSeq
    elif param1.kind == JArray:
        for node in param1.items():
            jsonStr = node.getStr()
            for byteVal in jsonStr.next0xPrefix():
                resSeq.add(byteVal)
        result = resSeq
    else:
        raise newException(ValueError, "Incorrect JsonNode type.")
    
func ToModule*(pCurrentFlink: LIST_ENTRY or PLIST_ENTRY): PLDR_DATA_TABLE_ENTRY =
    result = cast[PLDR_DATA_TABLE_ENTRY](cast[int](pCurrentFlink) -% 0x10)

func ToBuffer*(pCurrentModule: PLDR_DATA_TABLE_ENTRY or LDR_DATA_TABLE_ENTRY): string =
    result = $pCurrentModule.FullDllName.Buffer

func getSyscallWord*(t: array[18, HGEntry], HashCmp: uint64): WORD {.inline.} =
    result = 0
    for Entry in t.items():
        if Entry.Hash == HashCmp:
            result = Entry.Syscall
            return

proc djb2_hash*(pFuncName: string): uint64 =
    var 
        hash : uint64 = 0xDEADC0DEu  # SET HASH
    for c in pFuncName:
        hash = ((hash shl 0x05) + hash) + cast[uint](ord(c))
    result = hash

proc green*(text: string, outfile: File = stdout) =
  outfile.write("\e[32m", text, "\e[0m\n")

proc yellow*(text: string, outfile: File = stdout) =
  outfile.write("\e[33m", text, "\e[0m\n")

proc blue*(text: string, outfile: File = stdout) =
  outfile.write("\e[34m", text, "\e[0m\n")

proc red*(text: string, outfile: File = stdout) =
  outfile.write("\e[31m", text, "\e[0m\n")

proc magenta*(text: string, outfile: File = stdout) =
  outfile.write("\e[35m", text, "\e[0m\n")

{.passC:"-masm=intel".}
func GetPEBAsm64*(): PPEB {.asmNoStackFrame.} =
    asm """
        mov rax, qword ptr gs:[0x60]
        leave
        ret
    """
