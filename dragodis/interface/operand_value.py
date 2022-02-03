"""
Defines interface for different types of values found within an operand.

NOTE: Some of these are interfaces that must be subclassed to be implemented based on
    the underlying disassembler.
    Others can be used directly.
"""

import abc
from typing import Optional, Union, List


class OperandValue(metaclass=abc.ABCMeta):
    """
    Base class for all possible operand value types.
    """


class Immediate(int, OperandValue):
    """
    Defines an immediate or constant used in an operand.
    """


class MemoryReference(int, OperandValue):
    """
    Memory reference is a special type of immediate, where the value represents a defined
    item in the disassembler.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        The referenced name of the defined memory reference.
        """


# TODO: Should Register be of type str?
class Register(OperandValue, metaclass=abc.ABCMeta):
    """
    Register objects represent the register components of operands.
    """

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<Register {self.name} - bit_width = {self.bit_width}>"

    @abc.abstractmethod
    def __eq__(self, register: "Register"):
        ...

    @property
    @abc.abstractmethod
    def bit_width(self) -> int:
        """The total number of bits for this register."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The name of the register."""


class RegisterList(List[Register], OperandValue):
    """
    Defines a list of registers used as an operand.
    e.g.
        {R4-R10,LR}
    """


class Phrase(OperandValue):
    """
    Defines an operand phrase of one of the following forms:
        [base + index * scale + offset]
        [base + offset]
    """

    # TODO: For capstone, x86 had "segment" and ARM had "lshift"

    @property
    @abc.abstractmethod
    def base(self) -> Optional[Register]:
        """
        The base register if operand is a phrase.
        May be None if there is no base:
            e.g. dword ptr [EAX*0x4 + DAT_0040dc20]
        """

    @property
    @abc.abstractmethod
    def index(self) -> Optional[Register]:
        """
        The index register
        (May be None if phrase doesn't have scaled index.)
        """

    @property
    @abc.abstractmethod
    def scale(self) -> int:
        """
        The scaling factor for the index.
        NOTE: This should default to 0 if index * scale is not supported in the processor. (ARM)
        """

    @property
    @abc.abstractmethod
    def offset(self) -> Union[Register, int]:
        """
        The offset or displacement.
        This could be a register or immediate.
        """



