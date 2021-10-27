#[
    Author: zimawhit3
    Github: https://github.com/zimawhit3
    License: BSD 3-Clause
]#
import typedefs

iterator WriteSeqs*(MemoryObjs: seq[RWMemory]): var seq[MemoryWrite] =
    for MemoryObj in MemoryObjs:
        yield MemoryObj.WriteSequence

func getRWMemory*(MemorySequence: seq[RWMemory], MemoryLabel: string): RWMemory =
    result = nil
    for MemorySection in MemorySequence:
        if MemorySection.Label == MemoryLabel:
            result = MemorySection
            return

func getMemoryBaseAddress*(MemorySequence: seq[RWMemory], MemoryLabel: string): int =
    result = 0
    for Memory in MemorySequence:
        if Memory.Label == MemoryLabel:
            result = Memory.BaseAddress
            return

func newRWMemory*(Label: string, WriteSequence: seq[MemoryWrite], BaseAddress, CurrentAddress, Size, Padding: int = 0): RWMemory =
    result = RWMemory(
        Label           : Label,
        WriteSequence   : WriteSequence,
        BaseAddress     : BaseAddress,
        CurrentAddress  : CurrentAddress,
        Size            : Size,
        Padding         : Padding
    )