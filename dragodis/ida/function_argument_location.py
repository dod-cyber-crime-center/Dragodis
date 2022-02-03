
from __future__ import annotations

from functools import cached_property

from typing import Tuple, TYPE_CHECKING

from dragodis.ida.operand_value import IDARegister
from dragodis.interface.function_argument_location import (
    ArgumentLocation, StackLocation, RegisterLocation,
    RegisterPairLocation, RelativeRegisterLocation, StaticLocation
)

if TYPE_CHECKING:
    import ida_typeinf
    from dragodis import IDA


class IDAArgumentLocation(ArgumentLocation):

    def __init__(self, ida: IDA, argloc: "ida_typeinf.argloc_t", size: int):
        self._ida = ida
        self._argloc = argloc
        self._size = size


class IDAStackLocation(StackLocation, IDAArgumentLocation):

    @cached_property
    def stack_offset(self) -> int:
        return self._argloc.stkoff()


class IDARegisterLocation(RegisterLocation, IDAArgumentLocation):

    @cached_property
    def register(self) -> IDARegister:
        return IDARegister(self._ida, self._argloc.reg1(), self._size)


class IDARegisterPairLocation(RegisterPairLocation, IDAArgumentLocation):

    @cached_property
    def registers(self) -> Tuple[IDARegister, IDARegister]:
        # Size is the combination of both registers.
        size = self._size // 2
        return (
            IDARegister(self._ida, self._argloc.reg1(), size),
            IDARegister(self._ida, self._argloc.reg2(), size),
        )


class IDARelativeRegisterLocation(RelativeRegisterLocation, IDARegisterLocation):

    @cached_property
    def register(self) -> IDARegister:
        rrel = self._argloc.get_rrel()
        return IDARegister(self._ida, rrel.reg, self._size)

    @cached_property
    def offset(self) -> int:
        rrel = self._argloc.get_rrel()
        return rrel.off


class IDAStaticLocation(StaticLocation, IDAArgumentLocation):

    @cached_property
    def address(self) -> int:
        return self._argloc.get_ea()

