"""
Interface for data types.
"""

import abc


class DataType(metaclass=abc.ABCMeta):

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<DataType: {self.name}, size={self.size}>"

    def __eq__(self, other):
        return isinstance(other, DataType) and self.name == other.name and self.size == other.size

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
