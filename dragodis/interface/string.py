"""
String Items
"""

import abc


class String(metaclass=abc.ABCMeta):
    """Found string item"""

    def __repr__(self):
        return f"<String 0x{self.address:08x}: '{str(self)}'>"

    def __str__(self):
        return self.value

    def __bytes__(self):
        return self.data

    @property
    @abc.abstractmethod
    def value(self) -> str:
        """
        The string found.
        """

    @property
    @abc.abstractmethod
    def data(self) -> bytes:
        """
        The raw bytes that make up the string.
        """

    @property
    @abc.abstractmethod
    def address(self) -> int:
        """
        The address of the string.
        """
