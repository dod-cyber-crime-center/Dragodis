
from __future__ import annotations
from typing import TYPE_CHECKING

import bytesparse

from dragodis.exceptions import NotExistError
from dragodis.interface import Memory

if TYPE_CHECKING:
    from dragodis.ida.flat import IDAFlatAPI


class CachedMemory:

    _PAGE_SIZE = 0x1000

    def __init__(self, ida: IDAFlatAPI):
        self._ida = ida
        # Blocks we still need to cache
        uncached_chunks = []
        for start, size in ida._ida_helpers.get_all_byte_chunks():
            # Split up large chunks into page size chunks.
            while size > self._PAGE_SIZE:
                uncached_chunks.append((start, self._PAGE_SIZE))
                start += self._PAGE_SIZE
                size -= self._PAGE_SIZE
            if size:
                uncached_chunks.append((start, size))

        self._uncached_chunks = uncached_chunks
        self._memory = bytesparse.Memory()

    def _obtain_uncached_chunks(self, address: int, size: int):
        """
        Obtains the uncached chunks that overlap the given address range,
        then pulls the chunks from IDA.
        """
        if not size:
            return

        start = address
        end = address + size

        index = 0
        while index < len(self._uncached_chunks):
            chunk_start, chunk_size = self._uncached_chunks[index]
            chunk_end = chunk_start + chunk_size
            if chunk_start >= end:
                # Chunks are in order and non-overlapping, so we can break
                # if we see a chunk past our range.
                break
            if start < chunk_end and chunk_start < end:  # overlaps?
                data = self._ida._ida_bytes.get_bytes(chunk_start, chunk_size)
                self._memory.write(chunk_start, data)
                del self._uncached_chunks[index]
            else:
                index += 1

    def get(self, address: int, size: int, fill_pattern=b"\x00") -> bytes:
        """
        Obtains bytes from given address range.
        Non-initialized bytes are filled with 0 bytes.

        :param address: Start address.
        :param size: Number of bytes to obtain.
        :param fill_pattern: byte value to fill non-initialized bytes.
            If set to None, a NotExistError will be thrown if data is not contiguous.
        """
        self._obtain_uncached_chunks(address, size)
        if fill_pattern:
            return bytes(self._memory[address:address+size:fill_pattern])
        else:
            try:
                return bytes(self._memory[address:address+size])
            except ValueError as e:
                raise NotExistError(f"Unable to obtain {size} bytes from 0x{address:08X}: {e}")

    def set(self, address: int, data: bytes):
        """
        Updates cached data with given data.
        """
        # Pull from IDB first to update cached blocks.
        # Usually we wouldn't be setting data at something we haven't
        # pulled from first, so the performance hit is acceptable.
        self._obtain_uncached_chunks(address, len(data))
        self._memory.write(address, data)

    def is_contiguous(self, address: int, size) -> bool:
        """
        Determines if the address range was fully loaded.
        Ie. there are no holes of uninitialized bytes (is_loaded() == False)
        """
        self._obtain_uncached_chunks(address, size)
        return self._memory[address:address+size].contiguous


class IDAMemory(Memory):
    """
    A file-like interface for  memory within IDA.
    Performs caching and buffering to improve performance.

    NOTE: Unloaded memory will be presented as zero bytes.
    """

    def __init__(self, ida: IDAFlatAPI, start: int, end: int):
        super().__init__(start, end)
        self._ida = ida
        self._cache = ida._cached_memory

    def read(self, size: int = None) -> bytes:
        remaining_bytes = self.end - (self.start + self._offset)
        if size is None:
            size = remaining_bytes
        size = min(size, remaining_bytes)
        if not size:
            return b""

        address = self.start + self._offset
        data = self._cache.get(address, size)

        self._offset += len(data)
        return data

    def reset(self, size: int = None) -> int:
        remaining_bytes = self.end - (self.start + self._offset)
        if size is None:
            size = remaining_bytes
        size = min(size, remaining_bytes)
        if not size:
            return 0

        address = self.start + self._offset
        self._ida._ida_helpers.revert_bytes(address, size)

        # Update cache.
        data = self._ida._ida_helpers.get_bytes(address, size)
        self._cache.set(address, data)

        self._offset += size
        return size

    def write(self, data: bytes) -> int:
        # Trim given data to ensure we only write within the window.
        data = data[:self.end - (self.start + self._offset)]
        if not data:
            return 0

        address = self.start + self._offset

        # Check if we would be writing to an uninitialized section.
        if not self._ida._ida_helpers.is_loaded(address, len(data)):
            raise IOError(f"Unable to write to address not fully initialized: 0x{address:08x}")

        # Patch bytes with given data.
        self._ida._ida_bytes.patch_bytes(address, data)

        # Update cache.
        self._cache.set(address, data)

        self._offset += len(data)
        return len(data)
