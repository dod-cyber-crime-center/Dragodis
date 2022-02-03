
from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

from dragodis.exceptions import UnsupportedError
from dragodis.ida.line import IDALine
from dragodis.ida.memory import IDAMemory
from dragodis.interface import Segment, SegmentType, SegmentPermission
from dragodis.utils import cached_property

if TYPE_CHECKING:
    import ida_segment
    from dragodis.ida.flat import IDA


class IDASegment(Segment):

    def __init__(self, ida: IDA, segment_t: "ida_segment.segment_t"):
        self._ida = ida
        self._segment_t = segment_t
        self._end = None  # caching for end address.

    @cached_property
    def name(self) -> str:
        return self._ida._ida_segment.get_segm_name(self._segment_t)

    @cached_property
    def start(self) -> int:
        return self._segment_t.start_ea

    @cached_property
    def end(self) -> int:
        if self._end is None:
            # Exclude any overlay of uninitialized bytes from the segment.
            # This is to better match Ghidra's approach of separating uninitalized sections
            # into their own block.
            # TODO: Support separate segments for uninitialized bytes.
            end = self._segment_t.end_ea
            while not self._ida._ida_bytes.is_loaded(end - 1):
                end -= 1
            self._end = end
        return self._end

    @cached_property
    def bit_size(self) -> int:
        return self._segment_t.abits()

    @cached_property
    def permissions(self) -> SegmentPermission:
        perm = self._segment_t.perm
        ret = SegmentPermission(0)
        if perm & self._ida._ida_segment.SEGPERM_EXEC:
            ret |= SegmentPermission.execute
        if perm & self._ida._ida_segment.SEGPERM_WRITE:
            ret |= SegmentPermission.write
        if perm & self._ida._ida_segment.SEGPERM_READ:
            ret |= SegmentPermission.read
        return ret

    @property
    def lines(self) -> Iterable[IDALine]:
        yield from self._ida.lines(self.start, self.end)

    def open(self) -> IDAMemory:
        return self._ida.open_memory(self.start, self.end)
