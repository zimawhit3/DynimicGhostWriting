#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import typedefs

var
    syscallv* : WORD

{.passC:"-masm=intel".}
{.push asmNoStackFrame.}
proc ntAllocateVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, ZeroBits: ULONG, RegionSize: var PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntFreeVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, RegionSize: var PSIZE_T, FreeType: ULONG): NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntGetContextThread*(ThreadHandle : HANDLE, Context : PCONTEXT) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntQuerySystemInformation*(SystemInformationClass: SYSTEM_INFORMATION_CLASS, SystemInformation: PVOID, SystemInformationLength: ULONG, 
                               ReturnLength: PULONG): NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntQueryInformationProcess*(ProcessHandle : HANDLE, ProcessInformationClass : PROCESS_INFORMATION_CLASS, ProcessInformation : PVOID, 
                                ProcessInformationLength : ULONG, ReturnLength : PULONG) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntQueryInformationThread*(ThreadHandle: HANDLE, ThreadInformatonClass: THREAD_INFORMATION_CLASS, ThreadInformation: PVOID, 
                               ThreadInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntQueryVirtualMemory*(ProcessHandle : HANDLE, BaseAddress : PVOID, MemoryInformationClass : MEMORY_INFORMATION_CLASS, MemoryInformation : PVOID, 
                           MemoryInformationLength : ULONG, ReturnLength : PULONG) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntOpenProcess*(ProcessHandle: PHANDLE, AccessMask : ACCESS_MASK, ObjAttributes : POBJECT_ATTRIBUTES, ClientId : PCLIENT_ID) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntOpenThread*(ThreadHandle: PHANDLE, AccessMask : ACCESS_MASK, ObjAttributes : POBJECT_ATTRIBUTES, ClientId : PCLIENT_ID) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntSetContextThread*(ThreadHandle : HANDLE, Context : PCONTEXT): NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntSuspendProcess*(ProcessHandle : HANDLE) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntSuspendThread*(ThreadHandle: HANDLE, PreviousSuspendCount : PULONG) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntReadVirtualMemory*(ProcessHandle : HANDLE, BaseAddress : PVOID, Buffer : PVOID, BufferSize : SIZE_T, NumberOfBytesRead : PSIZE_T) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntResumeThread*(ThreadHandle: HANDLE, PreviousSuspendCount : PULONG) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntResumeProcess*(ProcessHandle: HANDLE) : NTSTATUS =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntUserGetThreadState*(Routine : DWORD) : HWND =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

proc ntUserPostMessage*(hWnd : HWND, Msg : UINT, wParam : WPARAM, lParam : LPARAM) : BOOL =
    asm """
        mov r10, rcx
        mov eax, `syscallv`
        syscall
        ret
    """

{.pop.}