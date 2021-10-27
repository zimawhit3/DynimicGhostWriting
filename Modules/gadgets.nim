#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import json, strutils
import winim/[winstr]
import typedefs, utility, pe
from winim/inc/winbase import LoadLibrary, FreeLibrary

iterator resolveModules*(GadgetSequence: seq[Gadget], LoadedModules: var seq[HMODULE]): HMODULE =
    var
        ModuleHandle : HMODULE
    for Gadget in GadgetSequence:
        ModuleHandle = Gadget.ModuleName.GetLocalModule
        if ModuleHandle != 0:
            yield ModuleHandle
        else:
            ModuleHandle = LoadLibrary(+$Gadget.ModuleName)
            if ModuleHandle != 0:
                LoadedModules.add(ModuleHandle)
                yield ModuleHandle

func GetMainStore*(GadgetSequence: seq[Gadget]): Gadget =
    result = nil
    for Gadget in GadgetSequence:
        if Gadget.Type == GadgetType.MainStore:
            result = Gadget
            return

func GetSink*(GadgetSequence: seq[Gadget]): Gadget =
    result = nil
    for Gadget in GadgetSequence:
        if Gadget.Type == GadgetType.Sink:
            result = Gadget
            return

func GetGadgetByName*(GadgetSequence: seq[Gadget], Name: string): Gadget =
    result = nil
    for Gadget in GadgetSequence:
        if Gadget.Name == Name:
            result = Gadget
            return

func allGadgetsFound(GadgetSequence: seq[Gadget]): bool =
    result = true
    for Gadget in GadgetSequence:
        if Gadget.Address == 0:
            result = false
            return

func Unload(LoadedModules: seq[HMODULE]) = 
    for Module in LoadedModules:
        FreeLibrary(Module)

func FindInstruction(pAddr: int, gadget: Gadget): bool =   
    result = true
    for i in 0 ..< gadget.BytePattern.len():
        if (pAddr-->i) != gadget.BytePattern[i]:
            result = false
            return
    gadget.Address = pAddr
    
func InitializeGadgets*(GadgetSequence: seq[Gadget]) =
    var
        LoadedModulesSeq : seq[HMODULE] = newSeq[HMODULE]()

    for Module in GadgetSequence.resolveModules(LoadedModulesSeq):
        var
            BaseOfCode      : int       = Module.GetBaseOfCode
            BaseOfCodeSize  : DWORD     = Module.ImageNtHeader.OptionalHeader.SizeOfCode
            Index           : int       = 0
            CurrentAddress  : int       
        if BaseOfCode == 0 or BaseOfCodeSize == 0:
            debugEcho "[-] BaseOfCode/SizeOfCode is not found..."
            return
        while Index < BaseOfCodeSize:
            if GadgetSequence.allGadgetsFound:
                LoadedModulesSeq.Unload
                return
            CurrentAddress = BaseOfCode +% Index
            for Gadget in GadgetSequence:
                # Gadget already found
                if Gadget.Address != 0:
                    continue
                if FindInstruction(CurrentAddress, Gadget):
                    Index += Gadget.BytePattern.len()
                    continue
            inc Index
    LoadedModulesSeq.Unload

func newGadget*(pattern: seq[byte], gtype: GadgetType, gModule, name: string, vol: bool = true, srcRM, dstRM: Register, address: int = 0): Gadget =
    result = Gadget(
        BytePattern         : pattern, 
        Type                : gtype,
        ModuleName          : gModule,
        Name                : name, 
        Volatile            : vol,
        SourceRegister      : srcRM,
        DestinationRegister : dstRM,
        Address             : address)

func setContext*(node: string, nodeVal: int, ctx: PCONTEXT) {.raises: [ValueError].} =
    
    if node.len() == 0:
        raise newException(ValueError, "Missing string from json node")
    
    case node:
    of "RIP":
        ctx.Rip = nodeVal
    of "RSP":
        ctx.Rsp = nodeVal
    of "RBP":
        ctx.Rbp = nodeVal
    of "RAX":
        ctx.Rax = nodeVal
    of "RBX":
        ctx.Rbx = nodeVal
    of "RCX":
        ctx.Rcx = nodeVal
    of "RDX":
        ctx.Rdx = nodeVal
    of "R8":
        ctx.R8 = nodeVal
    of "R9":
        ctx.R9 = nodeVal
    of "R10":
        ctx.R10 = nodeVal
    of "R11":
        ctx.R11 = nodeVal
    of "R12":
        ctx.R12 = nodeVal
    of "R13":
        ctx.R13 = nodeVal
    of "R14":
        ctx.R14 = nodeVal
    of "R15":
        ctx.R15 = nodeVal
    of "RDI":
        ctx.Rdi = nodeVal
    of "RSI":
        ctx.Rsi = nodeVal
    else:
        raise newException(ValueError, "Missing valid register")

func getRegister*(node: JsonNode): Register =
    var
        nodeStr : string = node.getStr()
    result = parseEnum[Register](nodeStr)

func getGadgetType*(node: JsonNode): GadgetType =
    var
        nodeStr : string = node.getStr()
    result = parseEnum[GadgetType](nodeStr)
