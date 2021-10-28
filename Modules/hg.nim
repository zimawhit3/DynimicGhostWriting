#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import typedefs, pe, utility, macros, strformat

macro hashHGEntryArray(x: typed): untyped =
    echo fmt"[+] Hashing the HGEntry Array..."
    x.expectKind(nnkSym)
    let
        funcdef     = x.getImpl
        assignments = funcdef[6]
        syscalls : array[18, string] = [
            "NtOpenProcess", "NtWaitForSingleObject", "NtSuspendThread", "NtGetContextThread", "NtSetContextThread",
            "NtQuerySystemInformation", "NtQueryInformationProcess", "NtAllocateVirtualMemory", "NtFreeVirtualMemory",
            "NtOpenThread", "NtResumeThread", "NtReadVirtualMemory", "NtSuspendProcess", "NtResumeProcess", "NtUserGetThreadState",
            "NtUserPostMessage", "NtQueryVirtualMemory", "NtQueryInformationThread"
        ]
    for stmnt in assignments:
        if stmnt.kind != nnkLetSection and stmnt[0].kind != nnkIdentDefs:
            continue
        let
            idents      = stmnt[0]
            bracket     = idents[2]
        for i in 0 ..< bracket.len():
            let
                hash    = syscalls[i].djb2_hash
                newVal  = newLit(hash)
            echo fmt"[+] Setting {syscalls[i]} to hash value {hash}"
            bracket[i] = newVal

func isFilled*(t: array[18, HGEntry]): bool =
    result = true
    for entry in t:
        if not entry.Filled:
            result = false
            return

proc resolveEntry*(HGArray : var array[18, HGEntry], ImageBase: HMODULE) =    
    let
        ExportTable : PIMAGE_EXPORT_DIRECTORY  = ImageBase.GetExportTable
    if ExportTable.isNil:
        return
    for CurrentEntry in HGArray.mitems():
        GetTableEntry(CurrentEntry, ImageBase, ExportTable)
        
proc InitializeHGTable*(HGArray : var array[18, HGEntry]): bool =
    var 
        LocalModuleBaseAddress  : HMODULE
        LoadLibraryUsed         : bool
        HGModules               : array[2, string]  = ["ntdll.dll", "KERNEL32.DLL"]
    result = true
    for ModuleLabel in HGModules:

        LoadLibraryUsed = false
        LocalModuleBaseAddress = LoadLocalModule(ModuleLabel, LoadLibraryUsed)

        if LocalModuleBaseAddress == 0:
            result = false
            return
        if not HGArray.isFilled:
            HGArray.resolveEntry(LocalModuleBaseAddress)
        if LoadLibraryUsed:
            FreeLibrary(LocalModuleBaseAddress)
    
proc newHGEntry*(FunctionCall: uint64): HGEntry =
    result  = HGEntry(Hash : FunctionCall)

proc newHGArray*(): array[18, HGEntry] =
    let
        SyscallStrings  : array[18, uint64] = [
          0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64
        ]
    var
        Syscalls        : array[18, HGEntry]
    for i in 0 ..< SyscallStrings.len:
        var
            Entry : HGEntry = newHGEntry(SyscallStrings[i])
        Syscalls[i] = Entry

    result = Syscalls

hashHGEntryArray(newHGArray)