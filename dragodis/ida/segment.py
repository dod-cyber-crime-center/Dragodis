
from __future__ import annotations
from typing import TYPE_CHECKING, Iterable

from dragodis.ida.line import IDALine
from dragodis.ida.memory import IDAMemory
from dragodis.interface import Segment, SegmentPermission

if TYPE_CHECKING:
    import ida_segment
    from dragodis.ida.flat import IDAFlatAPI


class IDASegment(Segment):

    def __init__(self, ida: IDAFlatAPI, segment_t: "ida_segment.segment_t"):
        self._ida = ida
        self._segment_t = segment_t
        self.__real_end = None  # caching for end address.

    @property
    def name(self) -> str:
        return self._ida._ida_segment.get_segm_name(self._segment_t)

    @property
    def start(self) -> int:
        return self._segment_t.start_ea

    @property
    def _real_end(self) -> int:
        """
        Returns the address for the real end of the segment without the padding.
        """
        if not self.initialized:
            return self.start
        if self.__real_end is None:
            # Exclude any overlay of uninitialized bytes from the segment.
            # This is to better match Ghidra's approach of separating uninitalized sections
            # into their own block.
            ida_bytes = self._ida._ida_bytes
            end = self._segment_t.end_ea
            if not ida_bytes.is_loaded(end - 1):
                # Find first initialized item, then move down to find first uninitialized byte from that.
                end = ida_bytes.prev_inited(end - 1, self._segment_t.start_ea)
                while ida_bytes.is_loaded(end):
                    end += 1
            self.__real_end = end
        return self.__real_end

    @property
    def end(self) -> int:
        return self._segment_t.end_ea

    @property
    def initialized(self) -> bool:
        # If first address isn't loaded, then no bytes are.
        return self._ida._ida_bytes.is_loaded(self._segment_t.start_ea)

    @property
    def bit_size(self) -> int:
        return self._segment_t.abits()

    @property
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
        if self.initialized:
            yield from self._ida.lines(self.start, self._real_end)

    def open(self) -> IDAMemory:
        if not self.initialized:
            # Empty memory
            return self._ida.open_memory(self.start, self.start)
        return self._ida.open_memory(self.start, self._real_end)
