"""
Interface for cross references.
"""

import abc

from dragodis.interface.types import ReferenceType


class Reference(metaclass=abc.ABCMeta):
    """
    References represent the references to or from any address or function found in a disassembler.
    """

    @property
    @abc.abstractmethod
    def from_address(self) -> int:
        """
        The source address
        """

    @property
    @abc.abstractmethod
    def is_code(self) -> bool:
        """
        Is a reference to or from code.
        """

    @property
    @abc.abstractmethod
    def is_data(self) -> bool:
        ...

    @property
    @abc.abstractmethod
    def to_address(self) -> int:
        """
        The destination reference
        """

    # TODO: have a is_call and is_jump type (see Sark)
    @property
    @abc.abstractmethod
    def type(self) -> ReferenceType:
        ...
