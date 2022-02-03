
from __future__ import annotations
import abc
from typing import TYPE_CHECKING, Tuple

if TYPE_CHECKING:
    from dragodis.interface import Register


class ArgumentLocation(metaclass=abc.ABCMeta):
    ...


class StackLocation(ArgumentLocation):

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


class RegisterLocation(ArgumentLocation):

    @property
    @abc.abstractmethod
    def register(self) -> Register:
        """
        The register which holds the argument.
        """


class RegisterPairLocation(ArgumentLocation):

    @property
    @abc.abstractmethod
    def registers(self) -> Tuple[Register, Register]:
        """
        The pair of registers which holds the argument.
        """


class RelativeRegisterLocation(RegisterLocation):

    @property
    @abc.abstractmethod
    def offset(self) -> int:
        """
        The offset within the register which holds the argument.
        """


class StaticLocation(ArgumentLocation):

    @property
    @abc.abstractmethod
    def address(self) -> int:
        """
        The global address which holds the argument.
        """

