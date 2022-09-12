
from __future__ import annotations
import abc
from functools import lru_cache
from typing import BinaryIO, Optional, Iterable, TYPE_CHECKING

from dragodis.interface.types import SegmentPermission, SegmentType

if TYPE_CHECKING:
    from dragodis.interface import Line, Memory


class Segment(metaclass=abc.ABCMeta):
    """
    Interface for accessing segment information. (Sometimes referred to as 'sections')
    """

    def __str__(self) -> str:
        return f"{self.name}: 0x{self.start:08x} --> 0x{self.end:08x}"

    def __repr__(self):
        return f"<Segment {self} - permissions={self.permissions!r}, bit_size={self.bit_size}>"

    def __contains__(self, addr: int) -> bool:
        """
        Whether the given address is found within the segment.
        Defaults to checking if address is between start and end.
        """
        return self.start <= addr < self.end

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.start == other.start

    def __len__(self) -> int:
        """
        The number of bytes contained in the segment.
        Defaults to checking difference between end and start.
        """
        return self.end - self.start

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        The name of the segment.
        """

    @name.setter
    @abc.abstractmethod
    def name(self, new_name: Optional[str]):
        """
        Sets the name of the segment or resets the name if None/"" is provided.
        """

    # TODO: Add ability to set start/end bounds?
    @property
    @abc.abstractmethod
    def start(self) -> int:
        """
        The start address of the segment.
        """

    @property
    @abc.abstractmethod
    def end(self) -> int:
        """
        The end address of the segment (non-inclusive).
        """

    @property
    @abc.abstractmethod
    def initialized(self) -> bool:
        """
        Returns True if we have initialized bytes in the segment.
        """

    @property
    @abc.abstractmethod
    def bit_size(self) -> int:
        """
        The addressing mode in number of bits (8, 16, 32, etc).
        """

    @property
    @abc.abstractmethod
    def permissions(self) -> SegmentPermission:
        """
        The permissions applied to the segment.
        """

    @property
    @abc.abstractmethod
    def lines(self) -> Iterable[Line]:
        """
        Iterates the lines found within the segment.
        """

    @property
    # @lru_cache
    def data(self) -> bytes:
        """
        Raw bytes that make up this segment.
        WARNING: This can consume a lot of memory. Use open() if you would like to
        iteratively stream the contained data instead.

        Defaults to consuming all of the data stream.
        """
        if not self.initialized:
            return b""
        with self.open() as stream:
            return stream.read()

    def get_bytes(self, addr: int, length: int) -> bytes:
        """
        Gets the specified number of bytes at the specified address.

        :param int addr: Address to pull bytes from
        :param int length: Number of bytes to return
        :return: Raw bytes from the segment
        :raises IOError: If address is not within the segment.
        """
        if not self.initialized:
            return b""
        with self.open() as stream:
            stream.seek_address(addr)
            return stream.read(length)

    @abc.abstractmethod
    def open(self) -> Memory:
        """
        Returns an open memory window to access the underlying data in the segment.
        """
