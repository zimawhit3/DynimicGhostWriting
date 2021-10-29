#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import typedefs, pe, utility

proc newHGEntry*(FunctionCall: uint64): HGEntry =
    result  = HGEntry(Hash : FunctionCall)

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
    
proc newHGArray*(): array[18, HGEntry] =
    const
        Hashes : array[18, uint64] = [
            ~"NtOpenProcess", ~"NtWaitForSingleObject", ~"NtSuspendThread", ~"NtGetContextThread", ~"NtSetContextThread",
            ~"NtQuerySystemInformation", ~"NtQueryInformationProcess", ~"NtAllocateVirtualMemory", ~"NtFreeVirtualMemory",
            ~"NtOpenThread", ~"NtResumeThread", ~"NtReadVirtualMemory", ~"NtSuspendProcess", ~"NtResumeProcess", ~"NtUserGetThreadState",
            ~"NtUserPostMessage", ~"NtQueryVirtualMemory", ~"NtQueryInformationThread"
            ]
    var
        Syscalls        : array[18, HGEntry]
    for i in 0 ..< Hashes.len:
        var
            Entry : HGEntry = newHGEntry(Hashes[i])
        Syscalls[i] = Entry
    result = Syscalls
