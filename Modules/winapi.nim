#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import winim/[utils, winstr]
import utility, strformat, strutils, os, macros
from winim/inc/winuser import SetLastErrorEx, EnumWindows, WNDENUMPROC, GetWindowThreadProcessId

when not defined(zima):
    from winim/inc/winuser import GetWindowTextLength, GetWindowText, IsWindowVisible

include syscalls

macro hashWrapperProc(x: typed, s: typed): untyped =
    x.expectKind(nnkSym)
    let
        funcdef     = x.getImpl
        procName    = funcdef[0].strVal
        assignments = funcdef[6]
    
    expectKind(assignments[1], nnkAsgn)
    expectIdent(assignments[1][0], "syscallv")
    let
        asgncall    = assignments[1][1]
    expectKind(asgncall, nnkCall)
    expectKind(asgncall[2], nnkUInt64Lit)
    let
        hash        = s.strVal.djb2_hash
        newVal      = newLit(hash)
    asgncall[2] = newVal
    echo fmt"[+] Hashing {procName}! {s.strVal} to {hash}"

iterator processes*(buffer: LPVOID): PSYSTEM_PROCESS_INFORMATION =
    var
        SystemInfo : PSYSTEM_PROCESS_INFORMATION = cast[PSYSTEM_PROCESS_INFORMATION](buffer)
    while SystemInfo.NextEntryOffset:
        yield SystemInfo
        SystemInfo = cast[PSYSTEM_PROCESS_INFORMATION](cast[int](SystemInfo) +% SystemInfo.NextEntryOffset.int)

iterator threads*(processInfo: PSYSTEM_PROCESS_INFORMATION): PSYSTEM_THREADS =
    var
        Thread : PSYSTEM_THREADS = cast[PSYSTEM_THREADS](cast[int](processInfo) +% SYSTEM_PROCESS_INFORMATION.sizeof)
    for i in 1 .. processInfo.NumberOfThreads:        
        yield Thread
        Thread = cast[PSYSTEM_THREADS](cast[int](Thread) +% SYSTEM_THREADS.sizeof)

func BaseSetLastNTError(Status: NTSTATUS) =
    var
        dwErrorCode : ULONG
    dwErrorCode = RtlNtStatusToDosError(Status)
    SetLastErrorEx(dwErrorCode, 0)

proc GetThreadHandle*(ThreadHandle: PHANDLE, ClientID: PCLIENT_ID, Functions: array[18, HGEntry]): bool =
    var
        Access  : ACCESS_MASK = THREAD_ALL_ACCESS
        ObjAttr : OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES()
        Status  : NTSTATUS
        
    syscallv = Functions.getSyscallWord(0u64)
    
    Status = ntOpenThread(ThreadHandle, Access, &ObjAttr, ClientID)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [GetThreadHandle Error] = {Status.toHex}"
        result = false

proc GetProcessHandle*(ProcessHandle: PHANDLE, Clid: PCLIENT_ID, Functions: array[18, HGEntry]): bool = 
    var 
        Access  : ACCESS_MASK       = PROCESS_ALL_ACCESS
        ObjAttr : OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES()
        Status  : NTSTATUS

    syscallv = Functions.getSyscallWord(0u64)
    
    Status = ntOpenProcess(ProcessHandle, Access, &ObjAttr, Clid)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [GetProcessHandle Error] = {Status.toHex}"
        result = false

proc GetContext*(ThreadHandle: HANDLE, Context: PCONTEXT, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS
    
    syscallv = Functions.getSyscallWord(0u64)
    
    Status = ntGetContextThread(ThreadHandle, Context)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [GetContext Error] = {Status.toHex}"
        result = false

proc SetContext*(ThreadHandle: HANDLE, Context: PCONTEXT, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS
    
    syscallv = Functions.getSyscallWord(0u64)
    
    Status = ntSetContextThread(ThreadHandle, Context)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [SetContext Error] = {Status.toHex}"
        result = false

proc SuspendThread*(ThreadHandle: HANDLE, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS

    syscallv = Functions.getSyscallWord(0u64)
    
    Status = ntSuspendThread(ThreadHandle, NULL)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [SuspendThread Error] = {Status.toHex}"
        result = false

proc ResumeThread*(ThreadHandle: HANDLE, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS

    syscallv = Functions.getSyscallWord(0u64)
        
    Status = ntResumeThread(ThreadHandle, NULL)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [ResumeThread Error] = {Status.toHex}"
        result = false

proc SuspendProcess*(ProcessHandle: HANDLE, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS
    
    syscallv = Functions.getSyscallWord(0u64)

    Status = ntSuspendProcess(ProcessHandle)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [SuspendProcess Error] = {Status.toHex}"
        result = false

proc ResumeProcess*(ProcessHandle: HANDLE, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS

    syscallv = Functions.getSyscallWord(0u64)
        
    Status = ntResumeProcess(ProcessHandle)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [ResumeProcess Error] = {Status.toHex}"
        result = false

proc VirtualAlloc*(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, RegionSize: var PSIZE_T, AllocType: ULONG, Protect: ULONG, Functions: array[18, HGEntry]): PVOID =
    var
        Status : NTSTATUS
    
    syscallv = Functions.getSyscallWord(0u64)
    
    Status = ntAllocateVirtualMemory(ProcessHandle, BaseAddress, 0, RegionSize, AllocType, Protect)
    if NT_SUCCESS(Status):
        result = BaseAddress[]
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [VirtualAlloc Error] = {Status.toHex}"
        result = nil

proc VirtualFree*(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, RegionSize: var PSIZE_T, FreeType: ULONG, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS
    
    syscallv = Functions.getSyscallWord(0u64)

    Status = ntFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [VirtualFree Error] = {Status.toHex}"
        result = false

proc QueryInformationSystem*(SystemInformationClass: SYSTEM_INFORMATION_CLASS, SystemInfoAddress: PVOID, 
                             SystemInfoLength: ULONG, ReturnLength: PULONG, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS 
    
    syscallv = Functions.getSyscallWord(0u64)

    Status = ntQuerySystemInformation(SystemInformationClass, SystemInfoAddress, SystemInfoLength, ReturnLength)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        result = false
        
proc QueryInformationProcess*(ProcessHandle: HANDLE, ProcessInfoClass: PROCESS_INFORMATION_CLASS, ProcessInfo: PVOID, 
                              ProcessInfoLength: ULONG, ReturnLength: PULONG, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS

    syscallv = Functions.getSyscallWord(0u64)

    Status = ntQueryInformationProcess(ProcessHandle, ProcessInfoClass, ProcessInfo, ProcessInfoLength, ReturnLength)
    if NT_SUCCESS(Status):
        result = true
    else:
        if Status == 0xC0000004:
            BaseSetLastNTError(Status)
            result = false
        else:
            BaseSetLastNTError(Status)
            when not defined(zima):
                echo fmt"   [QueryInformationProcess Error] = {Status.toHex}"
            result = false

proc QueryInformationThread*(ThreadHandle: HANDLE, InfoClass: THREAD_INFORMATION_CLASS, ThreadInfo: PVOID, 
                             ThreadInfoLength: ULONG, ReturnLength: PULONG, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS
    
    syscallv = Functions.getSyscallWord(0u64)

    Status = ntQueryInformationThread(ThreadHandle, InfoClass, ThreadInfo, ThreadInfoLength, ReturnLength)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [QueryInformationThread Error] = {Status.toHex}"
        result = false

proc QueryVirtualMemory*(ThreadHandle: HANDLE, BaseAddress: PVOID, MemoryInfoClass: MEMORY_INFORMATION_CLASS, MemoryInfo: PVOID, 
                         MemoryInfoLength: ULONG, ReturnLength: PULONG, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS

    syscallv = Functions.getSyscallWord(0u64)

    Status = ntQueryVirtualMemory(ThreadHandle, BaseAddress, MemoryInfoClass, MemoryInfo, MemoryInfoLength, ReturnLength)
    if NT_SUCCESS(Status):
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [QueryVirtualMemory Error] = {Status.toHex}"
        result = false

proc GetWindowHandle*(WindowObj: PWindowObject): bool =

    proc enumeratewindows(p1: HWND, p2: LPARAM): WINBOOL =
        var
            data    : PWindowObject = cast[PWindowObject](p2)
            tid     : HANDLE = GetWindowThreadProcessId(p1, NULL)

        when not defined(zima):
            var
                length  : int32 = GetWindowTextLength(p1)
                buff    : LPWSTR    = newWString(length)
            GetWindowText(p1, buff, length+1)
            if winimConverterBOOLToBoolean(p1.IsWindowVisible) and length != 0:
                echo fmt" Window: {$buff} | Handle : {p1} | tid: {tid}"

        if data.ThreadID == tid:
            data.WindowHandle = p1
            result = FALSE
        else:
            result = TRUE
        
    if not winimConverterBOOLToBoolean(EnumWindows(cast[WNDENUMPROC](enumeratewindows), cast[LPARAM](WindowObj))):
        result = true
    else:
        result = false

proc getClientID*(TargetProcess, TargetThread: int16, ClientID: PCLIENT_ID, Functions: array[18, HGEntry]): bool =
    var
        buffer          : LPVOID                        = NULL 
        retLength       : ULONG                         = 0
        dataSize        : PSIZE_T                                             
    let
        procInfo        : SYSTEM_INFORMATION_CLASS  = systemProcessInformation

    if not QueryInformationSystem(procInfo, NULL, 0, &retLength, Functions):        
        
        retLength += 0x1000
        dataSize = cast[PSIZE_T](&retLength) 
        buffer = VirtualAlloc(cast[HANDLE](-1), &buffer, dataSize, MEM_COMMIT.ULONG, PAGE_READWRITE.ULONG, Functions)

        if buffer == NULL:
            when not defined(zima):
                echo "[-] Failed to allocate buffer"
            return false
        
        if not QueryInformationSystem(procInfo, buffer, retLength, NULL, Functions):
            when not defined(zima):
                echo "[-] Unable to query process information..."

            if not VirtualFree(cast[HANDLE](-1), &buffer, dataSize, MEM_DECOMMIT, Functions):
                when not defined(zima):
                    echo "[-] Failed to free memory..."
            return false
        block ClientIDSearch:
            for process in buffer.processes():
                
                if process.UniqueProcessId == TargetProcess:
                    for thread in process.threads():        
                        
                        # Get Main Thread (should be first one) or the Target THread
                        if TargetThread == 0 or thread.ClientId.UniqueThread == TargetThread:    
                            ClientID[]              = thread.ClientId
                            break ClientIDSearch

        if not VirtualFree(cast[HANDLE](-1), &buffer, dataSize, MEM_DECOMMIT, Functions):
            when not defined(zima):
                echo "[-] Failed to free memory..."
            return false
    result = true

proc ReadProcessMemory*(ProcessHandle: HANDLE, BaseAddress: LPCVOID, Buffer: LPVOID, Size: SIZE_T, 
                        NumberOfBytesRead: ptr SIZE_T, Functions: array[18, HGEntry]): bool =
    var
        Status : NTSTATUS

    syscallv = Functions.getSyscallWord(0u64)
    
    Status = ntReadVirtualMemory(ProcessHandle, cast[PVOID](BaseAddress), Buffer, Size, Size.unsafeAddr)
    if NT_SUCCESS(Status):
        if not NumberOfBytesRead.isNil:
            NumberOfBytesRead[] = Size
        result = true
    else:
        BaseSetLastNTError(Status)
        when not defined(zima):
            echo fmt"   [ReadProcess Error] = {Status.toHex}"
        result = false
    
proc EnumProcessModules*(ProcessHandle: HANDLE, Module: ptr HMODULE, cb: DWORD, lpcNeeded: LPDWORD, Functions: array[18, HGEntry]): bool =    
    let
        BasicInformation    : PROCESS_INFORMATION_CLASS = PROCESS_INFORMATION_CLASS.ProcessBasicInformation
    
    var
        numModules, count   : DWORD         = 0
        retLength           : ULONG         = 0
        loaderData          : PPEB_LDR_DATA 
        listHead,listEntry  : PLIST_ENTRY
        procInfo            : PROCESS_BASIC_INFORMATION
        currModule          : LDR_DATA_TABLE_ENTRY 

    if not QueryInformationProcess(ProcessHandle, BasicInformation, &procInfo, cast[DWORD](procInfo.sizeof), &retLength, Functions):
        return false             

    if procInfo.PebBaseAddress == NULL:
        return false
    
    if not ReadProcessMemory(ProcessHandle, cast[PVOID](procInfo.PebBaseAddress->Ldr), &loaderData, loaderData.sizeof, NULL, Functions):
        return false

    # listHead address
    listHead = cast[PLIST_ENTRY](loaderData->InMemoryOrderModuleList)

    # Read in First List Entry Flink
    if not ReadProcessMemory(ProcessHandle, listHead, &listEntry, listEntry.sizeof, NULL, Functions):
        return false
    
    numModules = cb div cast[DWORD](HMODULE.sizeof)
    
    while listEntry != listHead:

        if not ReadProcessMemory(ProcessHandle, listEntry.ToModule, &currModule, currModule.sizeof, NULL, Functions):
            return false

        if count < numModules:
            cast[ptr HMODULE](cast[ByteAddress](Module) +% (count * HMODULE.sizeof))[] = cast[HMODULE](currModule.DLLBase)
           
        inc count
        if count > numModules:
            return true

        listEntry = currModule.InMemoryOrderLinks.Flink

    if not isNil(lpcNeeded):
        lpcNeeded[] = count * cast[DWORD](HMODULE.sizeof)

    result = true

proc ReadModuleName(ProcessHandle: HANDLE, Module: PLDR_DATA_TABLE_ENTRY, StringLength: DWORD, Functions: array[18, HGEntry]): string =
    var
        modAddr     : PUNICODE_STRING 
        strAddr     : PWSTR
        modNameW    : wstring
    let
        addrSz      : SIZE_T = PVOID.sizeof.SIZE_T
    
    modAddr     = cast[PUNICODE_STRING](Module->BaseDllName)
    modNameW    = newWString(StringLength)

    if not ReadProcessMemory(ProcessHandle, cast[PVOID](modAddr->Buffer), &strAddr, addrSz, NULL, Functions):
        raiseOSError(osLastError())
    
    if not ReadProcessMemory(ProcessHandle, strAddr, &modNameW, StringLength, NULL, Functions):
        raiseOSError(osLastError())

    result = $(modNameW)
    result.removeNullChars

proc EnumThreadStack*(ProcessHandle, ThreadHandle: HANDLE, StackBaseAddr: var PVOID, Functions: array[18, HGEntry]): bool =
    let
        ThreadInfoClass : THREAD_INFORMATION_CLASS  = THREAD_INFORMATION_CLASS.ThreadBasicInformation
    var
        ThreadBasicInfo : THREAD_BASIC_INFORMATION  = THREAD_BASIC_INFORMATION()

    result = true

    if not QueryInformationThread(ThreadHandle, ThreadInfoClass, &ThreadBasicInfo, ThreadBasicInfo.sizeof.int32, NULL, Functions):
        result = false
        return

    if ThreadBasicInfo.TebBaseAddress == NULL:
        result = false
        return

    let
        tib : PNT_TIB    = cast[PNT_TIB](ThreadBasicInfo.TebBaseAddress)

    if not ReadProcessMemory(ProcessHandle, cast[PVOID](tib->StackLimit), &StackBaseAddr, StackBaseAddr.sizeof, NULL, Functions):
        result = false

proc GetRemoteModule*(hProcess: HANDLE, ModuleName: string, Functions: array[18, HGEntry]): int {.raises: [OSError, ValueError].} = 
    let
        BasicInformation    : PROCESS_INFORMATION_CLASS = PROCESS_INFORMATION_CLASS.ProcessBasicInformation
    var
        count               : DWORD
        loaderData          : PPEB_LDR_DATA
        listHead, listEntry : PLIST_ENTRY
        procInfo            : PROCESS_BASIC_INFORMATION
        currModule          : LDR_DATA_TABLE_ENTRY 
        wstringLen          : DWORD
        modName             : string
    let
        MAX_MODULES = 0x2710

    if not QueryInformationProcess(hProcess, BasicInformation, &procInfo, procInfo.sizeof.DWORD, NULL, Functions):
        raiseOSError(osLastError())
    
    if procInfo.PebBaseAddress == NULL:
        raiseOSError(osLastError())

    if not ReadProcessMemory(hProcess, cast[PVOID](procInfo.PebBaseAddress->Ldr), &loaderData, loaderData.sizeof, NULL, Functions):
        raiseOSError(osLastError())
    
    listHead = cast[PLIST_ENTRY](loaderData->InMemoryOrderModuleList)

    if not ReadProcessMemory(hProcess, listHead, &listEntry, listEntry.sizeof, NULL, Functions):
        raiseOSError(osLastError())

    count = 0
    while listHead != listEntry:
        let
            CurrLdrData : PLDR_DATA_TABLE_ENTRY = listEntry.ToModule

        if not ReadProcessMemory(hProcess, CurrLdrData, &currModule, currModule.sizeof, NULL, Functions):
            raiseOSError(osLastError())
        
        wstringLen = currModule.BaseDllName.MaximumLength.DWORD
        modName = ReadModuleName(hProcess, CurrLdrData, wstringLen, Functions)
        
        if ModuleName == modName:
            result = cast[int](currModule.DLLBase)
            return

        inc count
        if count > MAX_MODULES:
            result = 0
            return

        listEntry = currModule.InMemoryOrderLinks.Flink

proc EnumProcesses*(Functions: array[18, HGEntry], Process: string = "", Io: File) =
    var
        buffer          : LPVOID                        = NULL
        retLength       : ULONG                         = 0
        dataSize        : PSIZE_T                           
    let
        procInfo        : SYSTEM_INFORMATION_CLASS  = systemProcessInformation
    
    if not QueryInformationSystem(procInfo, NULL, 0, &retLength, Functions):
        retLength += 0x1000
        dataSize = cast[PSIZE_T](&retLength)   
        buffer = VirtualAlloc(cast[HANDLE](-1), &buffer, dataSize, MEM_COMMIT, PAGE_READWRITE, Functions)
        if buffer == NULL:
            return
        if not QueryInformationSystem(procInfo, buffer, retLength, NULL, Functions):
            when not defined(zima):
                echo "[-] Unable to query process information..."
            if not VirtualFree(cast[HANDLE](-1), &buffer, dataSize, MEM_DECOMMIT, Functions):
                when not defined(zima):
                    echo "[-] Failed to free memory..."
            return
        for process in buffer.processes:
            let
                CurrentProcess : string = $process.ImageName.Buffer
            if Process.isEmptyOrWhitespace or CurrentProcess.contains(Process):
                let text = fmt"[i] Process: {process.ImageName.Buffer} | PID: {process.UniqueProcessID}"
                yellow(text, Io)
                for thread in process.threads:
                    let text = fmt"   Thread: {thread.ClientID.UniqueThread} | User Time: {thread.UserTime.LargeIntToInt64} | Context Switches: {thread.ContextSwitchCount}"
                    green(text, Io)
        if not VirtualFree(cast[HANDLE](-1), &buffer, dataSize, MEM_DECOMMIT, Functions):
            return

hashWrapperProc(GetThreadHandle, "NtOpenThread")
hashWrapperProc(GetProcessHandle, "NtOpenProcess")
hashWrapperProc(GetContext, "NtGetContextThread")
hashWrapperProc(SetContext, "NtSetContextThread")
hashWrapperProc(SuspendThread, "NtSuspendThread")
hashWrapperProc(ResumeThread, "NtResumeThread")
hashWrapperProc(SuspendProcess, "NtSuspendProcess")
hashWrapperProc(ResumeProcess, "NtResumeProcess")
hashWrapperProc(VirtualAlloc, "NtAllocateVirtualMemory")
hashWrapperProc(VirtualFree, "NtFreeVirtualMemory")
hashWrapperProc(QueryInformationProcess, "NtQueryInformationProcess")
hashWrapperProc(QueryInformationSystem, "NtQuerySystemInformation")
hashWrapperProc(QueryInformationThread, "NtQueryInformationThread")
hashWrapperProc(QueryVirtualMemory, "NtQueryVirtualMemory")
hashWrapperProc(ReadProcessMemory, "NtReadVirtualMemory")