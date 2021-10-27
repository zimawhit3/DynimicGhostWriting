# DynimicGhostwriting
Windows x64 Process Injection via Ghostwriting with Dynamic Configuration

Currently only tested on Windows 10 Home Build 19042

# Nim Dependencies #
Requires Winim. To install run:

`nimble install winim`

# Compilation #
For a DLL with echo statements:
`nim debugbuild`

For a DLL without echo statements:
`nim build`

# What is GhostWriting?
GhostWriting is a Windows Process Injection technique first publically mentioned in 2007 by c0de90e7. It achieves code execution within the context of a thread
without opening a handle to the process or writing to it's virtual memory. It achieves this by manipulating register context for a specific thread in combination with specific gadgets that prevent the thread from crashing after an operation. For more information on GhostWriting, see https://github.com/c0de90e7/GhostWriting.

# What the heck man! This isn't GhostWriting!
Technically, no this isn't GhostWriting as described by c0de90e7 since I'm opening a handle to the process nor am I simply enumerating windows to get the threadID. But I find the technique is way more stable when opening a handle to the process and allows for use of volatile registers in the Write Primative. Also, I wanted to advance my understand of Nim, so I went out of my way to write winAPI calls, dynamically resolve syscalls at run-time, enumerating the Stack's base address, etc. It would be trivial to implement the original method if you want :wink:

# On Gadget Volatility
GhostWriting, as described by c0de90e7, required the use of non-volatile registers for it's write primatives. However, these are hard to find in current Windows dlls commonly loaded by processes (ntdll, kernel32.dll, etc), and therefore, limited in number. The use of volatile registers comes with some limitations. This is because resuming the thread will often have other threads clobbering your register state, resulting in (most-likely) the process to crash. Some ways to get around this issue are to either manipulate at the process level, find a process with a single thread, or find a thread that is currently suspended. 

Since this repository is for educational purposes, I've decided to use a volatile write primative and to simply open a handle to the process and suspend it, preventing any clobbering of register contexts.

# On Dynamic Configuration
GhostWriting gives us the ability to write/execute ROP/JOP chains to/in a target thread's virtual address space. This can be useful to sneakily achieve arbitrary computation within a process whilst simultaneously bypassing CFG and CIG, along with the benefits of only opening a handle to a single thread with no writes. However, hard-coding re-useable code chains, gadgets, and payloads can be limiting, and having the ability to load in gadgets, payloads, and re-useable code chains at run-time could serve to be benificial to the technique. In my attempt to implement dynamic configurability, I've decided to use JSON.

# Configuration #

An example of a configuration can be seen in defaults.nim. 
Below are the JSON keys and their underlying fields to use.

## Memorys ##
A list of RW memory to use. The Stack is always created.
Field | Required? | Description
----- | --------- | --------------
Label | Yes | The Name of the Memory to be referenced
BaseAddress | Yes | The base address of the memory
Size | Yes | The size of the memory
Padding | Yes | The padding to increment the memory addresses by for successive writes

## Payloads ##
A list of payloads to write to the target thread.

Field | Required? | Description
----- | --------- | --------------
Label | Yes | The name of the Payload to be referneced in the Re-Useable Code Chain
Bytes | Yes | The byte sequence of the payload
StoreLocation | Yes | Which section of memory to store the payload. This can be the Stack or an arbitrary section of RW memory referenced under Memorys.
StoreOffset | Yes | The offset from the StoreLocation's Base Address to write the payload.

## Gadgets ##
A list of gadgets to be used in the injection. Requires atleast 1 Sink Gadget (jmp -2) and 1 Main Store (Write Primative).

Field | Required? | Description
----- | --------- | --------------
Name  |    Yes    | The name of the Gadget, to be refernced in the Re-Useable Code Chain.
BytePattern | Yes | The byte pattern of the gadget.
GadgetModule | Yes | The module where the gadget resides.
ModuleOffset | Yes | The offset within the module where the gadget resides.
GadgetType | Only for Sink and MainStore Gadgets | The type of operation the gadget performs.
Volatile | Yes | The volatiliy of the registers used by the gadget.
DestinationRegister | Only for MainStore Gadgets | The destination register of the gadget.
SourceRegister | Only for MainStore Gadgets | The source register of the gadget.


## StartContext ##
The Context to use to start the execution of the Re-Usable Code Chain

Field | Required? | Description
----- | --------- | --------------
Target | Yes | The Target Memory Address to signal the end of execution.
RIP | Yes | The starting memory address for the RIP register.
RSP | Yes | The starting memory address for the RSP register.

### StartContext Sub-Fields ###
The sub-fields of the above keys

Field | Required? | Description
----- | --------- | --------------
Type | Yes | The type of memory address.
Value | Yes | The value of the respective Type. For example, a value for Type Gadget would reference a named Gadget.
Offset | No | The offset from the value.

### Available Types ###
Type | Description
---- | -----------
Gadget| A loaded Gadget
Memory| A loaded RW Memory
Int| A raw integer

## CodeChain ##
The ROP/JOP chain to be written to the target thread. The program keeps track of the current address to write to, incrementing by the designated padding in the Memory section. For the Stack, the padding is set to 1.

Field | Required? | Description
----- | --------- | --------------
Type | Yes | The type of memory address.
Location | Yes | The referenced Memory to write to. For example, a value of "Stack" would write to the Stack.
Value | Yes | The value of the respective Type. For example, a value for Type Gadget would reference a named Gadget.
GadgetOffset | Optional | The Offset from the Gadget's address to write.
Module | Only for Function Types | The module containing the referenced function.
Section | Only for CodeCaveRVA Types | The section for the RVA of the code cave
MemoryOffset | Only for Memory Types | The offset from the refernced Memory's base address

### Available Types ###
Type | Description
---- | -----------
DONTCARE | The Value at the current address doesn't matter. Increments the current address by the referenced Memorys's padding * the specified value.
SHADOWSPACE | Useful for Function Calls. Writes 0x20 0's to the referenced Memory's current address
Gadget | A Loaded Gadget
Int | A raw integer
Memory | A loaded memory's base address
Function | A function's address
FunctionRVA | The relative virtual address of a function in a referenced module
Module | A loaded module's base address
ModuleSize | A loaded module's size
CodeCave | A code cave in a referenced module
CodeCaveRVA | The relative virtual address of a code cave in a referenced module
Payload | A payload's base address
PayloadSize | A payload's size

# TODO #
I'm still working on an example JOP Chain. Hopefully that doesn't break too many things 😆
