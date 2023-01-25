
from __future__ import annotations
from typing import Tuple, TYPE_CHECKING

from dragodis.ghidra.operand_value import GhidraRegister
from dragodis.interface.function_argument_location import (
    ArgumentLocation, StackLocation, RegisterLocation,
    RegisterPairLocation, RelativeRegisterLocation, StaticLocation
)

if TYPE_CHECKING:
    import ghidra


class GhidraArgumentLocation(ArgumentLocation):

    def __init__(self, function: "ghidra.program.model.listing.Function", storage: "ghidra.program.model.listing.VariableStorage"):
        self._function = function
        self._storage = storage


class GhidraStackLocation(StackLocation, GhidraArgumentLocation):

    @property
    def stack_offset(self) -> int:
        # Ghidra returns a stack offset relative to the beginning of the callee.
        # ie. the return address would have been pushed in making the offset for
        # the first parameter at offset +4
        # Therefore, we will subtract the return address size if applicable.
        calling_conv = self._function.getCallingConvention()
        if calling_conv is None:
            fman = self._function.getProgram().getFunctionManager()
            calling_conv = fman.getDefaultCallingConvention()
        return self._storage.getStackOffset() - calling_conv.getStackshift()


class GhidraRegisterLocation(RegisterLocation, GhidraArgumentLocation):

    @property
    def register(self) -> GhidraRegister:
        return GhidraRegister(self._storage.getRegister())


class GhidraRegisterPairLocation(RegisterPairLocation, GhidraArgumentLocation):

    @property
    def registers(self) -> Tuple[GhidraRegister, GhidraRegister]:
        reg1, reg2 = self._storage.getRegisters()
        return GhidraRegister(reg1), GhidraRegister(reg2)


class GhidraRelativeRegisterLocation(RelativeRegisterLocation, GhidraArgumentLocation):

    @property
    def register(self) -> GhidraRegister:
        return GhidraRegister(self._storage.getRegister())

    @property
    def offset(self) -> int:
        return self._storage.getLastVarnode().getOffset()


class GhidraStaticLocation(StaticLocation, GhidraArgumentLocation):

    @property
    def address(self) -> int:
        return self._storage.getFirstVarnode().getAddress().getOffset()
