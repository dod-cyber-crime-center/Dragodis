
from __future__ import annotations
import os
from typing import TYPE_CHECKING

from jpype.types import *

from dragodis.interface import Memory

if TYPE_CHECKING:
    import ghidra
    from dragodis.ghidra.flat import GhidraFlatAPI


class GhidraMemory(Memory):

    def __init__(self, ghidra: GhidraFlatAPI, start: int, end: int):
        super().__init__(start, end)
        self._ghidra = ghidra
        self._memory = self._ghidra._program.getMemory()

    def read(self, size: int = None) -> bytes:
        remaining_bytes = self.end - (self.start + self._offset)
        if size is None:
            size = remaining_bytes
        size = min(size, remaining_bytes)
        if not size:
            return b""

        address = self._ghidra._to_addr(self.start + self._offset)
        buffer = JByte[size]
        num_bytes = self._memory.getBytes(address, buffer)
        self._offset += num_bytes
        return bytes(buffer)

    def reset(self, size: int = None) -> int:
        remaining_bytes = self.end - (self.start + self._offset)
        if size is None:
            size = remaining_bytes
        size = min(size, remaining_bytes)
        if not size:
            return 0

        # Obtain original bytes directly from underlying file.
        address = self._ghidra._to_addr(self.start + self._offset)
        memory_block = self._memory.getBlock(address)
        memory_info = memory_block.getSourceInfos()[0]
        file_bytes = self._memory.getAllFileBytes()[0]
        file_offset = (
            address.getOffset()
            - memory_info.getMinAddress().getOffset()
            + memory_info.getFileBytesOffset()
        )
        buffer = JByte[size]
        file_bytes.getOriginalBytes(file_offset, buffer)

        # Write bytes.
        return self.write(bytes(buffer))

    def write(self, data: bytes) -> int:
        from ghidra.program.model.mem import MemoryAccessException
        # Trim given data to ensure we only write within the window.
        data = data[:self.end - (self.start + self._offset)]
        if not data:
            return 0
        address = self._ghidra._to_addr(self.start + self._offset)
        try:
            self._memory.setBytes(address, data)
        except MemoryAccessException as e:
            raise IOError(e)
        self._offset += len(data)
        return len(data)
