
from __future__ import annotations
import abc
from functools import total_ordering
from typing import TYPE_CHECKING, Tuple

if TYPE_CHECKING:
    from dragodis.interface import Register


@total_ordering
class ArgumentLocation(metaclass=abc.ABCMeta):

    _PRIORITY: int

    def __lt__(self, other: ArgumentLocation) -> bool:
        return self._PRIORITY < other._PRIORITY

    @abc.abstractmethod
    def __eq__(self, other: ArgumentLocation) -> bool:
        ...


class StackLocation(ArgumentLocation):

    _PRIORITY = 3

    def __str__(self) -> str:
        return f"stack[0x{self.stack_offset:x}]"

    def __repr__(self) -> str:
        return f"<StackLocation 0x{self.stack_offset:x}>"

    @property
    @abc.abstractmethod
    def stack_offset(self) -> int:
        """
        The stack offset of the variable which holds the argument.
        NOTE: This offset is relative to the stack pointer BEFORE calling the function.
        It is the offset based on the current stack setup relative to the caller.
        ie. the first parameter would have an offset of 0 and second parameter would be +4
        on a 32bit x86 executable.
        """
        # TODO: Should we return a StackVariable object instead?

    def __lt__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, StackLocation):
            return self.stack_offset < other.stack_offset
        return super().__lt__(other)

    def __eq__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, StackLocation):
            return self.stack_offset == other.stack_offset
        return False


class RegisterLocation(ArgumentLocation):

    _PRIORITY = 0

    def __str__(self) -> str:
        return self.register.name

    def __repr__(self) -> str:
        return f"<RegisterLocation {self.register.name}>"

    @property
    @abc.abstractmethod
    def register(self) -> Register:
        """
        The register which holds the argument.
        """

    def __lt__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, RegisterLocation):
            return self.register < other.register
        return super().__lt__(other)

    def __eq__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, RegisterLocation):
            return self.register == other.register
        return False


class RegisterPairLocation(ArgumentLocation):

    _PRIORITY = 1

    def __str__(self) -> str:
        return f"({', '.join(reg.name for reg in self.registers)})"

    def __repr__(self) -> str:
        return f"<RegisterPairLocation {', '.join(repr(reg) for reg in self.registers)}>"

    @property
    @abc.abstractmethod
    def registers(self) -> Tuple[Register, Register]:
        """
        The pair of registers which holds the argument.
        """

    def __lt__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, RegisterPairLocation):
            return self.registers < other.registers
        return super().__lt__(other)

    def __eq__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, RegisterPairLocation):
            return self.registers == other.registers
        return False


class RelativeRegisterLocation(RegisterLocation):

    _PRIORITY = 2

    def __str__(self) -> str:
        return f"{self.register.name}[0x{self.offset:x}]"

    def __repr__(self) -> str:
        return f"<RelativeRegisterLocation {self.register!r}[0x{self.offset:x}]>"

    @property
    @abc.abstractmethod
    def offset(self) -> int:
        """
        The offset within the register which holds the argument.
        """

    def __lt__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, RelativeRegisterLocation):
            return (self.register, self.offset) < (other.register, other.offset)
        return super().__lt__(other)

    def __eq__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, RelativeRegisterLocation):
            return (self.register, self.offset) == (other.register, other.offset)
        return False


class StaticLocation(ArgumentLocation):

    _PRIORITY = 4

    def __str__(self) -> str:
        return f"0x{self.address:08x}"

    def __repr__(self) -> str:
        return f"<StaticLocation 0x{self.address:08x}>"

    @property
    @abc.abstractmethod
    def address(self) -> int:
        """
        The global address which holds the argument.
        """

    def __lt__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, StaticLocation):
            return self.address < other.address
        return super().__lt__(other)

    def __eq__(self, other: ArgumentLocation) -> bool:
        if isinstance(other, StaticLocation):
            return self.address == other.address
        return False
