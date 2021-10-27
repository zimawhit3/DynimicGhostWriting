#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import typedefs, strutils, bytesequtils, winapi
from utility import djb2_hash, ToModule, GetPEBAsm64, ToBuffer, removeNullChars

iterator sections*(NtHeader: PIMAGE_NT_HEADERS): IMAGE_SECTION_HEADER =
    let 
        sections : ptr UncheckedArray[IMAGE_SECTION_HEADER] = cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](IMAGE_FIRST_SECTION(NtHeader))
    for i in 0 ..< int NtHeader.FileHeader.NumberOfSections:
        yield sections[i]

iterator functionAddresses*(ImageBase: HMODULE, ExportDirectory: PIMAGE_EXPORT_DIRECTORY): (string, int) =
    let
        Functions    : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](ImageBase +% ExportDirectory.AddressOfFunctions)
        Names        : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](ImageBase +% ExportDirectory.AddressOfNames)
        Ordinals     : ptr UncheckedArray[WORD]  = cast[ptr UncheckedArray[WORD]](ImageBase +% ExportDirectory.AddressOfNameOrdinals)
    for Index in 0 ..< ExportDirectory.NumberOfNames:
        var
            Name            : string    = $(cast[PCHAR](ImageBase +% Names[Index].int))
            Ordinal         : int       = Ordinals[Index].int
            FunctionRVA     : int       = Functions[Ordinal].int
            FunctionAddress : int       = ImageBase +% FunctionRVA
        yield (Name, FunctionAddress)

iterator functionRVAs*(ImageBase: HMODULE, ExportDirectory: PIMAGE_EXPORT_DIRECTORY): (string, int) =
    let
        Functions    : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](ImageBase +% ExportDirectory.AddressOfFunctions)
        Names        : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](ImageBase +% ExportDirectory.AddressOfNames)
        Ordinals     : ptr UncheckedArray[WORD]  = cast[ptr UncheckedArray[WORD]](ImageBase +% ExportDirectory.AddressOfNameOrdinals)
    for Index in 0 ..< ExportDirectory.NumberOfNames:
        var
            Name            : string    = $(cast[PCHAR](ImageBase +% Names[Index].int))
            Ordinal         : int       = Ordinals[Index].int
            FunctionRVA     : int       = Functions[Ordinal].int     
        yield (Name, FunctionRVA)

func ImageNtHeader*(ImageBase: HMODULE or PVOID): PIMAGE_NT_HEADERS =
    let
        DosHeader  : PIMAGE_DOS_HEADER  = cast[PIMAGE_DOS_HEADER](ImageBase)
        NtHeader   : PIMAGE_NT_HEADERS  = cast[PIMAGE_NT_HEADERS](cast[int](DosHeader) +% DosHeader.e_lfanew)
    if DosHeader.e_magic != IMAGE_DOS_SIGNATURE or NtHeader.Signature != IMAGE_NT_SIGNATURE.DWORD:
        result = nil
    else:
        result = NtHeader

iterator modules*(Peb: PPEB): PLDR_DATA_TABLE_ENTRY =
    var
        CurrentFlink    : LIST_ENTRY            = Peb.Ldr.InMemoryOrderModuleList.Flink[]
        CurrentModule   : PLDR_DATA_TABLE_ENTRY = CurrentFlink.ToModule  
    let
        FirstModule     : PLDR_DATA_TABLE_ENTRY = CurrentModule
    while true:
        yield CurrentModule

        CurrentFlink = CurrentFlink.Flink[]
        CurrentModule = CurrentFlink.ToModule
        if FirstModule == CurrentModule:
            break

func GetLocalModule*(ModuleName: string): HMODULE = 
    let
        Peb : PPEB = GetPEBAsm64()
    result = 0
    for Module in Peb.modules:
        if Module.ToBuffer.contains(ModuleName):
            result = cast[HMODULE](Module.DLLBase)
    
func GetExportTable*(ImageBase: HMODULE): PIMAGE_EXPORT_DIRECTORY =
    let 
        NtHeader   : PIMAGE_NT_HEADERS  = ImageBase.ImageNtHeader
    if NtHeader.isNil:
        result = nil
    else:
        result = cast[PIMAGE_EXPORT_DIRECTORY](ImageBase +% NtHeader.OptionalHeader.DataDirectory[0].VirtualAddress)

func GetBaseOfCode*(ImageBase: HMODULE): int =
    let
        NtHeader : PIMAGE_NT_HEADERS = ImageBase.ImageNtHeader
    if NtHeader.isNil:
        result = 0
    else:
        result = ImageBase +% NtHeader.OptionalHeader.BaseOfCode

func GetSizeOfImage*(ImageBase: HMODULE): int =
    let
        NtHeader : PIMAGE_NT_HEADERS = ImageBase.ImageNtHeader
    if NtHeader.isNil:
        result = 0
    else:
        result = NtHeader.OptionalHeader.SizeOfImage

proc GetCodeCaveRVA*(ImageBase: HMODULE, SectionLabel: string): int =
    let
        NtHeader : PIMAGE_NT_HEADERS = ImageBase.ImageNtHeader
    result = 0
    for Section in NtHeader.sections:
        let
            SectionNameArray : array[8, byte] = Section.Name
        var
            SectionNameSeq  : seq[byte] = @SectionNameArray
            SectionName     : string    = SectionNameSeq.toStrBuf()
        SectionName.removeNullChars()
        if SectionName == SectionLabel:
            result = Section.Misc.VirtualSize +% NtHeader.OptionalHeader.BaseOfCode
            return
        
proc GetTableEntry*(Entry: var HGEntry, ImageBase: HMODULE, PExportDir: PIMAGE_EXPORT_DIRECTORY) =
    for (FunctionName, FunctionAddress) in ImageBase.functionAddresses(PExportDir):
        let
            FunctionHash : uint64 = FunctionName.djb2_hash
        if Entry.Hash == FunctionHash:
            Entry.Address = FunctionAddress
            if cast[PBYTE](FunctionAddress +% 3)[] == 0xB8:
                Entry.Syscall = cast[PWORD](FunctionAddress +% 4)[]
                Entry.Filled = true
            else:
                #TODO
                discard         
            return

func GetFuncRVA*(HModule: HMODULE, FuncName: string): int =
    let
        PExportTable    : PIMAGE_EXPORT_DIRECTORY = HModule.GetExportTable
    result = 0
    if not PExportTable.isNil:
        for (Name, FuncRVA) in HModule.functionRVAs(PExportTable):  
            if Name == FuncName:
                result = FuncRVA
                return

func GetFuncAddress*(HModule: HMODULE, FuncName: string): int =
    let
        PExportTable : PIMAGE_EXPORT_DIRECTORY = HModule.GetExportTable
    result = 0
    if not PExportTable.isNil: 
        for (Name, FuncAddr) in HModule.functionAddresses(PExportTable):
            if Name == FuncName:
                result = FuncAddr
                return

proc LoadLocalModule*(ModuleLabel: string, LoadLibraryUsed: var bool): HMODULE  =
    var
        LocalModuleBaseAddress: HMODULE
    LocalModuleBaseAddress = ModuleLabel.GetLocalModule 
    if LocalModuleBaseAddress != 0:
        result = LocalModuleBaseAddress
    else:
        LoadLibraryUsed = true
        result = LoadLibrary(+$ModuleLabel)

proc ResolveModuleSize*(ModuleLabel: string): int {.raises: [OSError].} =
    var
        HMod            : HMODULE
        LoadLibraryUsed : bool
    HMod = LoadLocalModule(ModuleLabel, LoadLibraryUsed)
    if HMod == 0:
        raise newException(OSError, "Module couldn't be loaded in local process")
    result = HMod.GetSizeOfImage
    if LoadLibraryUsed: FreeLibrary(HMod)

proc ResolveFunctionRVA*(ModuleLabel, FuncName: string): int {.raises: [OSError].} =
    var
        LocalModuleBaseAddress  : HMODULE
        LoadLibraryUsed         : bool
    LocalModuleBaseAddress = LoadLocalModule(ModuleLabel, LoadLibraryUsed)
    if LocalModuleBaseAddress == 0:
        raise newException(OSError, "Module couldn't be loaded in local process")
    result = GetFuncRVA(LocalModuleBaseAddress, FuncName)
    if LoadLibraryUsed: FreeLibrary(LocalModuleBaseAddress)
    
proc ResolveCodeCaveRVA*(ModuleLabel, SectionLabel: string): int {.raises: [OSError].} =
    var
        LocalModuleBaseAddress  : HMODULE
        LoadLibraryUsed         : bool
    LocalModuleBaseAddress = LoadLocalModule(ModuleLabel, LoadLibraryUsed)
    if LocalModuleBaseAddress == 0:
        raise newException(OSError, "Module couldn't be loaded in local process")
    result = GetCodeCaveRVA(LocalModuleBaseAddress, SectionLabel)
    if LoadLibraryUsed: FreeLibrary(LocalModuleBaseAddress)
    
proc ResolveModuleBaseAddress*(ProcessHandle: HANDLE, ModuleLabel: string, Functions: array[18, HGEntry]): int {.raises: [OSError, ValueError].} =
    # ASLR on NTDLL only takes effect on system restart
    if ModuleLabel.contains "ntdll":
        var
            HMod        : HMODULE
        HMod = ModuleLabel.GetLocalModule
        if HMod == 0:
            raise newException(OSError, "Failed to get NTDLL base address...")
        result = HMod
    else:
        result = GetRemoteModule(ProcessHandle, ModuleLabel, Functions)

proc ResolveCodeCaveAddress*(ProcessHandle: HANDLE, ModuleLabel, SectionLabel: var string, Functions: array[18, HGEntry]): int {.raises: [OSError, ValueError].} =
    var
        ModuleBaseAddress       : int
        LocalModuleBaseAddress  : HMODULE
        LoadLibraryUsed         : bool
    if ModuleLabel.contains("ntdll"):       
        LocalModuleBaseAddress = LoadLocalModule(ModuleLabel, LoadLibraryUsed)
        if LocalModuleBaseAddress == 0:
            raise newException(OSError, "Module couldn't be loaded in local process")
        result = LocalModuleBaseAddress +% LocalModuleBaseAddress.GetCodeCaveRVA(SectionLabel)
    else:
        ModuleBaseAddress = GetRemoteModule(ProcessHandle, ModuleLabel, Functions)    
        LocalModuleBaseAddress = LoadLocalModule(ModuleLabel, LoadLibraryUsed)
        if LocalModuleBaseAddress == 0:
            raise newException(OSError, "Module couldn't be loaded in local process")
        result = ModuleBaseAddress +% LocalModuleBaseAddress.GetCodeCaveRVA(SectionLabel)
    if LoadLibraryUsed: FreeLibrary(LocalModuleBaseAddress)

proc ResolveFunction*(ProcessHandle: HANDLE, ModuleLabel, FuncName: var string, Functions: array[18, HGEntry]): int {.raises: [OSError, ValueError].} =
    var
        ModuleBaseAddress       : int
        LocalModuleBaseAddress  : HMODULE
        FuncRVA                 : int
        LoadLibraryUsed         : bool
    if ModuleLabel.contains("ntdll"):       
        LocalModuleBaseAddress = LoadLocalModule(ModuleLabel, LoadLibraryUsed)
        if LocalModuleBaseAddress == 0:
            raise newException(OSError, "Module couldn't be loaded in local process")
        FuncRVA = GetFuncRVA(LocalModuleBaseAddress, FuncName)
        result = LocalModuleBaseAddress +% FuncRVA
    else:   
        ModuleBaseAddress = GetRemoteModule(ProcessHandle, ModuleLabel, Functions)
        LocalModuleBaseAddress = LoadLocalModule(ModuleLabel, LoadLibraryUsed)
        if LocalModuleBaseAddress == 0:
            raise newException(OSError, "Module couldn't be loaded in local process")
        FuncRVA = GetFuncRVA(LocalModuleBaseAddress, FuncName)
        result = ModuleBaseAddress +% FuncRVA
    if LoadLibraryUsed: FreeLibrary(LocalModuleBaseAddress)