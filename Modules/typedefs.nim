
#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause

    References:
        - https://doxygen.reactos.org/d3/d71/struct__ASSEMBLY__STORAGE__MAP__ENTRY.html
        - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
        - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm
        - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
        - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm

]#
import winim/inc/windef except PLDR_DATA_TABLE_ENTRY, PPEB_LDR_DATA, LDR_DATA_TABLE_ENTRY,
                               PPEB, PEB, TEB, PTEB, PROCESS_BASIC_INFORMATION, PPROCESS_BASIC_INFORMATION, PEB_LDR_DATA
import winim/[winstr]
from winim/inc/winbase import LoadLibrary, FreeLibrary

export windef except PLDR_DATA_TABLE_ENTRY, PPEB_LDR_DATA, LDR_DATA_TABLE_ENTRY, PPEB, PEB, TEB, PTEB, PROCESS_BASIC_INFORMATION, 
                    PPROCESS_BASIC_INFORMATION, PEB_LDR_DATA
export winstr, LoadLibrary, FreeLibrary

type
    HGEntry* = object
        Address*    : int
        Hash*       : uint64
        Syscall*    : WORD
        Filled*     : bool

    Register* {.pure.} = enum
        RIP = "RIP"
        RSP = "RSP"
        RBP = "RBP"
        RAX = "RAX"
        RBX = "RBX"
        RCX = "RCX"
        RDX = "RDX"
        R8  = "R8"
        R9  = "R9"
        R10 = "R10"
        R11 = "R11"
        R12 = "R12"
        R13 = "R13"
        R14 = "R14"
        R15 = "R15"
        RDI = "RDI"
        RSI = "RSI"
        REL = "REL"

    GadgetType* {.pure.} = enum
        
        # Memory Types
        LoadImmediate
        Load
        Store

        # Arithmetic Types
        Add
        AddImmediate
        Subtract
        Negate

        # Logic Types
        And
        AndImmediate
        Or
        OrImmediate
        Xor
        XorImmediate
        Complement

        # Branch Types
        Unconditional
        Conditional

        # Function Call
        FunctionCall

        # Special
        Sink
        MainLoad
        MainStore
    
    Gadget* = ref object
        Address*                : int
        BytePattern*            : seq[byte]
        Name*                   : string
        Type*                   : GadgetType
        ModuleName*             : string
        ModuleHandle*           : HMODULE
        DestinationAddress*     : ptr int 
        DestinationRegister*    : Register
        SourceAddress*          : ptr int
        SourceRegister*         : Register
        Volatile*               : bool
        StackAdjust*            : int
        StackLoads*             : int8
        NumberOfArgs*           : int8

    MemoryWrite* = object
        WriteWhat*              : int
        WriteWhere*             : int

    Payload* = ref object
        Label*              : string
        Bytes*              : seq[byte]
        Size*               : int   
        StoreLocation*      : RWMemory
        StoreOffset*        : int

    RWMemory* = ref object
        Label*              : string
        WriteSequence*      : seq[MemoryWrite]
        BaseAddress*        : int
        CurrentAddress*     : int
        Size*               : int
        Padding*            : int

    WindowObject* = object
        ThreadID*           : int32
        WindowHandle*       : HWND
    PWindowObject* = ptr WindowObject

    MEMORY_INFORMATION_CLASS* {.pure.} = enum
        BasicInformation

    PROCESS_INFORMATION_CLASS* {.pure.} = enum
        ProcessBasicInformation
        ProcessQuotaLimits
        ProcessIoCounters
        ProcessVmCounters
        ProcessTimes
        ProcessBasePriority
        ProcessRaisePriority
        ProcessDebugPort
        ProcessExceptionPort
        ProcessAccessToken
        ProcessLdtInformation
        ProcessLdtSize
        ProcessDefaultHardErrorMode
        ProcessIoPortHandlers
        ProcessPooledUsageAndLimits
        ProcessWorkingSetWatch
        ProcessUserModeIOPL
        ProcessEnableAlignmentFaultFixup
        ProcessPriorityClass
        ProcessWx86Information
        ProcessHandleCount
        ProcessAffinityMask
        ProcessPriorityBoost
        MaxProcessInfoClass
    
    THREAD_BASIC_INFORMATION* {.pure.} = object
        ExitStatus*     : NTSTATUS
        TebBaseAddress* : PTEB
        ClientID*       : CLIENT_ID
        AffinityMask*   : KAFFINITY
        Priority*       : KPRIORITY
        BasePriority*   : KPRIORITY
    PTHREAD_BASIC_INFORMATION* = ptr THREAD_BASIC_INFORMATION

    THREAD_INFORMATION_CLASS* {.pure.} = enum
        ThreadBasicInformation  
        ThreadTimes             
        ThreadPriority          
        ThreadBasePriority                  
        ThreadAffinityMask                  
        ThreadImpersonationToken
        ThreadDescriptorTableEntry
        ThreadEnableAlignmentFaultFixup
        ThreadEventPair
        ThreadQuerySetWin32StartAddress
        ThreadZeroTlsCell
        ThreadPerformanceCount
        ThreadAmILastThread
        ThreadIdealProcessor
        ThreadPriorityBoost
        ThreadSetTlsArrayAddress
        ThreadIsIoPending
        ThreadHideFromDebugger

    ASSEMBLY_STORAGE_MAP {.pure.} = object
        Flags*      : ULONG
        DosPath*    : UNICODE_STRING
        Handle*     : HANDLE
    PASSEMBLY_STORAGE_MAP* = ptr ASSEMBLY_STORAGE_MAP

    PROCESS_BASIC_INFORMATION* {.pure.} = object
        ExitStatus*                     : NTSTATUS
        PebBaseAddress*                 : PPEB
        AffinityMask*                   : PVOID
        BasePriority*                   : PVOID
        UniqueProcessId*                : ULONG_PTR
        InheritedFromUniqueProcessId*   : ULONG_PTR
    PPROCESS_BASIC_INFORMATION*  = ptr PROCESS_BASIC_INFORMATION

    LDR_DLL_LOAD_REASON* {.pure.} = enum
        LoadReasonUnknown                       = -1
        LoadReasonStaticDependency              = 0
        LoadReasonStaticForwarderDependency     = 1
        LoadReasonDynamicForwarderDependency    = 2
        LoadReasonDelayloadDependency           = 3
        LoadReasonDynamicLoad                   = 4
        LoadReasonAsImageLoad                   = 5
        LoadReasonAsDataLoad                    = 6
        LoadReasonEnclavePrimary                = 7
        LoadReasonEnclaveDependency             = 8

    RTL_BALANCED_NODE_STRUCT1* {.pure.} = object
        Left* : PRTL_BALANCED_NODE
        Right* : PRTL_BALANCED_NODE

    RTL_BALANCED_NODE_UNION1* {.pure, union.} = object
        Children* : array[2, PRTL_BALANCED_NODE]
        Struct1*  : RTL_BALANCED_NODE_STRUCT1

    RTL_BALANCED_NODE_UNION2* {.pure, union.} = object
        Red*        {.bitsize:1.}   : UCHAR
        Balance*    {.bitsize:2.}   : UCHAR
        ParentValue*                : ULONG_PTR

    RTL_BALANCED_NODE* {.pure.} = object
        Union1* : RTL_BALANCED_NODE_UNION1
        Union2* : RTL_BALANCED_NODE_UNION2
    PRTL_BALANCED_NODE* = ptr RTL_BALANCED_NODE

    LDR_DATA_TABLE_ENTRY_UNION_ONE* {.pure, union.} = object
        InInitializationOrderLinks*  : LIST_ENTRY
        InProgressLinks*             : LIST_ENTRY
    PLDR_DATA_TABLE_ENTRY_UNION_ONE* = ptr LDR_DATA_TABLE_ENTRY_UNION_ONE

    LDR_DATA_TABLE_ENTRY_STRUCT_ONE* {.pure.} = object
        PackagedBinary* {.bitsize:1.}           : ULONG
        MarkedForRemoval* {.bitsize:1.}         : ULONG
        ImageDll* {.bitsize:1.}                 : ULONG
        LoadNotificationSent* {.bitsize:1.}     : ULONG
        TelemetryEntryProcessed* {.bitsize:1.}  : ULONG
        ProcessStaticImport* {.bitsize:1.}      : ULONG
        InLegacyLists* {.bitsize:1.}            : ULONG
        InIndexes* {.bitsize:1.}                : ULONG
        ShimDll* {.bitsize:1.}                  : ULONG
        InExceptionTable* {.bitsize:1.}         : ULONG
        ReservedFlags1* {.bitsize:2.}           : ULONG
        LoadInProgress* {.bitsize:1.}           : ULONG
        LoadConfigProcessed* {.bitsize:1.}      : ULONG
        EntryProcessed* {.bitsize:1.}           : ULONG
        ProtectDelayLoad* {.bitsize:1.}         : ULONG
        ReservedFlags3* {.bitsize:2.}           : ULONG
        DontCallForThreads* {.bitsize:1.}       : ULONG
        ProcessAttachCalled* {.bitsize:1.}      : ULONG
        ProcessAttachFailed* {.bitsize:1.}      : ULONG
        CorDeferredValidate* {.bitsize:1.}      : ULONG
        CorImage* {.bitsize:1.}                 : ULONG
        DontRelocate {.bitsize:1.}              : ULONG
        CorILOnly* {.bitsize:1.}                : ULONG
        ChpeImage* {.bitsize:1.}                : ULONG
        ReservedFlags5* {.bitsize:2.}           : ULONG
        Redirected* {.bitsize:1.}               : ULONG
        ReservedFlags6* {.bitsize:2.}           : ULONG
        CompatDatabaseProcessed* {.bitsize:1.}  : ULONG

    LDR_DATA_TABLE_ENTRY_UNION_TWO* {.pure, union.} = object
        FlagGroup*   : array[4, UCHAR]
        Flags*       : ULONG
        Struct*      : LDR_DATA_TABLE_ENTRY_STRUCT_ONE            
    PLDR_DATA_TABLE_ENTRY_UNION_TWO* = ptr LDR_DATA_TABLE_ENTRY_UNION_TWO
    
    LDR_DATA_TABLE_ENTRY* {.pure.} = object
        InLoadOrderLinks*               : LIST_ENTRY
        InMemoryOrderLinks*             : LIST_ENTRY
        Union_1*                        : LDR_DATA_TABLE_ENTRY_UNION_ONE
        DLLBase*                        : PVOID
        EntryPoint*                     : PVOID
        SizeOfImage*                    : ULONG
        FullDllName*                    : UNICODE_STRING
        BaseDllName*                    : UNICODE_STRING
        Union_2*                        : LDR_DATA_TABLE_ENTRY_UNION_TWO
        ObsoleteLoadCount               : USHORT
        TlsIndex*                       : USHORT
        HashLinks*                      : LIST_ENTRY
        TimeDateStamp*                  : ULONG
        EntryPointActivationContext*    : PVOID
        Lock*                           : PVOID
        DdgagNode*                      : PVOID       # PLDR_DDAG_NODE
        NodeModuleLink*                 : LIST_ENTRY
        LoadContext*                    : PVOID       # PLDRP_LOAD_CONTEXT
        ParentDllBase                   : PVOID
        SwitchBackContext*              : PVOID
        BaseAddressIndexNode*           : RTL_BALANCED_NODE
        MappingInfoIndexNode*           : RTL_BALANCED_NODE
        OriginalBase*                   : ULONG_PTR
        LoadTime*                       : LARGE_INTEGER
        BaseNameHashValue*              : ULONG
        LoadReason*                     : LDR_DLL_LOAD_REASON
        ImplicitPathOptions*            : ULONG
        ReferenceCount*                 : ULONG
        DependentLoadFlags*             : ULONG
        SigningLevel*                   : UCHAR
    PLDR_DATA_TABLE_ENTRY* = ptr LDR_DATA_TABLE_ENTRY

    PEB_LDR_DATA* {.pure.} = object
        Length*                             : ULONG
        Initialized*                        : BOOLEAN
        SsHandle*                           : PVOID
        InLoadOrderModuleList*              : LIST_ENTRY
        InMemoryOrderModuleList*            : LIST_ENTRY
        InInitializationOrderModuleList*    : LIST_ENTRY
        EntryInProgress*                    : PVOID
        ShutdownInProgress*                 : BOOLEAN
        ShutdownThreadId*                   : HANDLE
    PPEB_LDR_DATA* = ptr PEB_LDR_DATA

    PEB* {.pure.} = object
        InheritedAddressSpace*                  : BOOLEAN
        ReadImageFileExecOptions*               : BOOLEAN
        BeingDebugged*                          : BOOLEAN
        PebUnion1*                              : UCHAR
        Padding0*                               : array[4, UCHAR]
        Mutant*                                 : HANDLE
        ImageBaseAddress*                       : PVOID
        Ldr*                                    : PPEB_LDR_DATA                             
        ProcessParameters*                      : PRTL_USER_PROCESS_PARAMETERS  
        SubSystemData*                          : PVOID                         
        ProcessHeap*                            : HANDLE                        
        FastPebLock*                            : PVOID          # PRTL_CRITICAL_SECTION
        AtlThunkSListPtr*                       : PVOID                         
        IFEOKey*                                : PVOID                         
        PebUnion2*                              : ULONG                         
        Padding1*                               : array[4, UCHAR]               
        KernelCallBackTable*                    : ptr PVOID                     
        SystemReserved*                         : ULONG                         
        AltThunkSListPtr32*                     : ULONG                         
        ApiSetMap*                              : PVOID                         
        TlsExpansionCounter*                    : ULONG                         
        Padding2*                               : array[4, UCHAR]               
        TlsBitmap*                              : PVOID                         
        TlsBitmapBits*                          : array[2, ULONG]               
        ReadOnlyShareMemoryBase*                : PVOID                         
        SharedData*                             : PVOID                         
        ReadOnlyStaticServerData*               : ptr PVOID                     
        AnsiCodePageData*                       : PVOID                         
        OemCodePageData*                        : PVOID                         
        UnicodeCaseTableData*                   : PVOID                         
        NumberOfProcessors*                     : ULONG                         
        NtGlobalFlag*                           : ULONG                         
        CriticalSectionTimeout*                 : LARGE_INTEGER                 
        HeapSegmentReserve*                     : ULONG_PTR                     
        HeapSegmentCommit*                      : ULONG_PTR                     
        HeapDeCommitTotalFreeThreshold*         : ULONG_PTR                     
        HeapDeCommitFreeBlockThreshold*         : ULONG_PTR                     
        NumberOfHeaps*                          : ULONG                         
        MaximumNumberOfHeaps*                   : ULONG                         
        ProcessHeaps*                           : ptr PVOID                     
        GdiSharedHandleTable*                   : PVOID                         
        ProcessStarterHelper*                   : PVOID                         
        GdiDCAttributeList*                     : ULONG                         
        Padding3*                               : array[4, UCHAR]               
        LoaderLock*                             : PVOID           # PRTL_CRITICAL_SECTION
        OSMajorVersion*                         : ULONG
        OSMinorVersion*                         : ULONG
        OSBuildNumber*                          : USHORT
        OSCSDVersion*                           : USHORT
        OSPlatformId*                           : ULONG
        ImageSubsystem*                         : ULONG
        ImageSubsystemMajorVersion*             : ULONG
        ImageSubsystemMinorVersion*             : ULONG
        Padding4                                : array[4, UCHAR]
        ActiveProcessAffinityMask*              : PVOID            # KAFFINITY
        GdiHandleBuffer                         : array[0x3c, ULONG]
        PostProcessInitRoutine*                 : VOID
        TlsExpansionBitmap*                     : PVOID
        TlsExpansionBitmapBits*                 : array[0x20, ULONG]
        SessionId*                              : ULONG
        Padding5*                               : array[4, UCHAR]
        AppCompatFlags*                         : ULARGE_INTEGER
        AppCompatFlagsUser*                     : ULARGE_INTEGER
        ShimData*                               : PVOID
        AppCompatInfo*                          : PVOID
        CSDVersion*                             : UNICODE_STRING
        ActivationContextData*                  : PVOID             # PACTIVATION_CONTEXT_DATA 
        ProcessAssemblyStorageMap*              : PVOID             # PASSEMBLY_STORAGE_MAP
        SystemDefaultActivationContextData*     : PVOID             # PACTIVATION_CONTEXT_DATA
        SystemAssemblyStorageMap*               : PVOID             # PASSEMBLY_STORAGE_MAP
        MinimumStackCommit*                     : ULONG_PTR
        Sparepointers*                          : array[4, PVOID]
        SpareUlongs*                            : array[5, ULONG]
        WerRegistrationData*                    : PVOID
        WerShipAssertPtr*                       : PVOID
        Unused*                                 : PVOID
        ImageHeaderHash*                        : PVOID
        TracingFlags*                           : ULONG
        CsrServerReadOnlySharedMemoryBase*      : ULONGLONG
        TppWorkerpListLock*                     : ULONG
        TppWorkerpList*                         : LIST_ENTRY
        WaitOnAddressHashTable*                 : array[0x80, PVOID]
        TelemtryCoverageHeader*                 : PVOID
        CloudFileFlags*                         : ULONG
        CloudFileDiagFlags*                     : ULONG
        PlaceholderCompatabilityMode*           : CHAR
        PlaceholderCompatabilityModeReserved*   : array[7, CHAR]
        LeapSecondData*                         : PVOID
        LeapSecondFlags*                        : ULONG
        NtGlobalFlag2*                          : ULONG
    PPEB* = ptr PEB

    TEB* {.pure.} = object
        NtTib*                                  : NT_TIB
        EnvironmentPointer*                     : PVOID
        ClientId*                               : CLIENT_ID
        ActiveRpcHandle*                        : PVOID
        ThreadLocalStoragePointer*              : PVOID
        ProcessEnvironmentBlock*                : PEB
        LastErrorValue*                         : ULONG
        CountOfOwnedCriticalSections*           : ULONG
        CsrClientThread*                        : PVOID
        Win32ThreadInfo*                        : PVOID
        User32Reserved*                         : array[0x1A, ULONG]
        UserReserved*                           : array[5, ULONG]
        WOW32Reserved*                          : PVOID
        CurrentLocale*                          : ULONG
        FpSoftwareStatusRegister*               : ULONG
        ReservedForDebuggerInstrumentation*     : array[0x10, PVOID]
    PTEB* = ptr TEB
