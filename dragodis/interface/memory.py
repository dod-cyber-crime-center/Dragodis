
from __future__ import annotations
import abc
import io
import os


class Memory(io.BufferedIOBase, metaclass=abc.ABCMeta):
    """
    Interface for reading and writing a window of memory within the program
    as a file-like object.
    """

    def __init__(self, start: int, end: int):
        """
        :param start: The start address of the memory window.
        :param end: The end address of the memory window (non-inclusive).
        """
        if start > end:
            raise ValueError(f"Start address must be less than end address.")
        self.start = start
        self.end = end
        self._offset = 0

    def __repr__(self) -> str:
        return f"<Memory 0x{self.start:08x} - 0x{self.end:08x}>"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        """
        Closes the memory buffer window if applicable.
        NOTE: Ensure you call super().close() if overriding this function.
        """
        # We don't need to do anything here, but want to make sure we provide a
        # docstring to warn users.
        super().close()

    @property
    def data(self) -> bytes:
        """
        Raw bytes that make up the underlying data within this memory window.
        WARNING: This can consume a lot of memory.
        Defaults to consuming all of the data stream.
        """
        offset = self.tell()
        try:
            self.seek(0)
            return self.read()
        finally:
            self.seek(offset)

    def flush(self):
        """
        Flush the write buffers of the memory window if applicable.
        """
        super().flush()

    @abc.abstractmethod
    def read(self, size: int = None) -> bytes:
        """
        Reads and returns size number of bytes from window.
        Reads in all data if size is omitted.

        :param size: Number of bytes to read.
        :return: Read bytes.
        """

    def readable(self) -> bool:
        return True

    @abc.abstractmethod
    def reset(self, size: int = None) -> int:
        """
        Resets given number of bytes back to original unpatched binary.

        :param size: Number of bytes to unpatch.
        :return: Number of bytes successfully unpatched.
        """

    @abc.abstractmethod
    def write(self, data: bytes) -> int:
        """
        Writes given data to memory window.

        :param data: Bytes to write to memory window.
        :return: Number of bytes successfully written.
        :raises IOError: If attempted to write to an uninitialized section.
        """

    def writable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """
        Sets the current offset, relative to whence flag.

        :param offset: Offset to set to.
        :param whence: Flag to indicate positioning.
        :return: The new absolute position.
        """
        if whence == os.SEEK_SET:
            self._offset = offset
        elif whence == os.SEEK_CUR:
            self._offset += offset
        elif whence == os.SEEK_END:
            self._offset = (self.end - self.start) + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")

        # Fix up offset if out of bounds.
        if self._offset < 0:
            self._offset = 0
        elif self._offset > self.end:
            self._offset = self.end

        return self._offset

    def seek_address(self, addr: int) -> int:
        """
        Sets memory window to given address.

        :param addr: Address within memory window to seek to.
        :return: The new absolute position (as an address).
        :raises IOError: If address is not within segment.
        """
        if addr < self.start or addr > self.end:
            raise IOError(f"Invalid seek address: 0x{addr:08x}")
        return self.seek(addr - self.start) + self.start

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        """
        Returns the current offset within the memory window.
        """
        return self._offset

    def tell_address(self) -> int:
        """
        Returns the virtual address representation of the current offset in the memory window.
        """
        return self.start + self.tell()
