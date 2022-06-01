
from __future__ import annotations
from typing import TYPE_CHECKING, Iterable

from dragodis.ghidra.line import GhidraLine
from dragodis.ghidra.memory import GhidraMemory
from dragodis.interface import Segment, SegmentType, SegmentPermission

if TYPE_CHECKING:
    import ghidra
    from dragodis.ghidra import Ghidra


class GhidraSegment(Segment):

    def __init__(self, ghidra: Ghidra, memory_block: "ghidra.program.model.mem.MemoryBlock"):
        self._ghidra = ghidra
        self._memory_block = memory_block

    def __contains__(self, addr: int):
        return self._memory_block.contains(self._ghidra._flatapi.toAddr(addr))

    def __len__(self):
        return self._memory_block.getSize()

    @property
    def name(self) -> str:
        return self._memory_block.getName()

    @property
    def start(self) -> int:
        return self._memory_block.getStart().getOffset()

    @property
    def end(self) -> int:
        return self._memory_block.getEnd().getOffset() + 1

    @property
    def bit_size(self) -> int:
        return self._memory_block.getStart().getSize()

    @property
    def permissions(self) -> SegmentPermission:
        permissions = SegmentPermission(0)
        if self._memory_block.isRead():
            permissions |= SegmentPermission.read
        if self._memory_block.isWrite():
            permissions |= SegmentPermission.write
        if self._memory_block.isExecute():
            permissions |= SegmentPermission.execute
        if self._memory_block.isVolatile():
            permissions |= SegmentPermission.volatile
        return permissions

    @property
    def lines(self) -> Iterable[GhidraLine]:
        yield from self._ghidra.lines(self.start, self.end)

    def open(self) -> GhidraMemory:
        return GhidraMemory(self._ghidra, self.start, self.end)