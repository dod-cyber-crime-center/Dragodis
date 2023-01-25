"""
Defines interface for different types of values found within an operand.

NOTE: Some of these are interfaces that must be subclassed to be implemented based on
    the underlying disassembler.
    Others can be used directly.
"""
from __future__ import annotations
import abc
from functools import total_ordering
from typing import Optional, Union, List


class OperandValue(metaclass=abc.ABCMeta):
    """
    Base class for all possible operand value types.
    """

    def __int__(self):
        """
        Operand values can be casted to int to get a sane value based on type.
        (This is equivalent to IDA's idc.get_operand_value() function)

        WARNING: Not all OperandValue subclasses have an equivalent int value (e.g. Register),
        in which case it will return a -1.
        """
        return -1


class Immediate(int, OperandValue):
    """
    Defines an immediate or constant used in an operand.
    """

    def __str__(self) -> str:
        return str(int(self))

    def __repr__(self) -> str:
        return f"<Immediate {self}>"


class MemoryReference(int, OperandValue):
    """
    Memory reference is a special type of immediate, where the value represents a defined
    item in the disassembler.
    """

    def __str__(self) -> str:
        return f"0x{self:08x}"

    def __repr__(self) -> str:
        return f"<MemoryReference {self}>"


@total_ordering
class Register(OperandValue, metaclass=abc.ABCMeta):
    """
    Register objects represent the register components of operands.
    """

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<Register {self.name} - bit_width={self.bit_width}>"

    @abc.abstractmethod
    def __eq__(self, register: Register):
        ...

    def __lt__(self, other: Register):
        return (self.base.name, self.mask) < (other.base.name, other.mask)

    @property
    @abc.abstractmethod
    def base(self) -> Register:
        """The full size register in this register's family."""

    @property
    @abc.abstractmethod
    def bit_width(self) -> int:
        """The total number of bits for this register."""

    @property
    @abc.abstractmethod
    def mask(self) -> int:
        """A mask indicating the applicable bits for this register within the base register."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The name of the register."""


class RegisterList(List[Register], OperandValue):
    """
    Defines a list of registers used as an operand.

    .. code::

        {R4-R10,LR}
    """

    def __str__(self) -> str:
        return f"{{{','.join(self)}}}"

    def __repr__(self) -> str:
        return f"<RegisterList {super().__repr__()}>"


class Phrase(OperandValue):
    """
    Defines an operand phrase of one of the following forms:

    .. code::

        [base + index * scale + offset]
        [base + offset]
    """

    # TODO: For capstone, x86 had "segment" and ARM had "lshift"

    def __int__(self):
        return self.offset

    def __str__(self) -> str:
        segments = []
        if (base := self.base) is not None:
            segments.append(str(base))
        if (index := self.index) is not None:
            segments.append(f"{index}*0x{self.scale:x}")
        if offset := self.offset:
            if isinstance(offset, int):
                segments.append(f"0x{offset:x}")
            else:
                segments.append(str(offset))
        return f"[{' + '.join(segments)}]"

    def __repr__(self) -> str:
        offset = self.offset
        if isinstance(offset, int):
            offset = f"0x{offset:x}"
        return f"<Phrase base={self.base}, index={self.index}, scale={self.scale}, offset={offset}>"

    @property
    @abc.abstractmethod
    def base(self) -> Optional[Register]:
        """
        The base register if operand is a phrase.
        May be None if there is no base:

        .. code::

            dword ptr [EAX*0x4 + DAT_0040dc20]
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



