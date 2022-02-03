"""
Interface for data types.
"""

import abc


class DataType(metaclass=abc.ABCMeta):

    def __str__(self) -> str:
        return self.name

    @property
    def name(self) -> str:
        """
        The name of the data type.
        e.g: "dword", "char", etc.
        """

    @property
    def size(self) -> int:
        """
        The size of the data type.
        """
