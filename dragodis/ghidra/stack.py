
from __future__ import annotations
from typing import TYPE_CHECKING, Union, Iterable

from dragodis.ghidra.variable import GhidraStackVariable
from dragodis.interface.stack import StackFrame

if TYPE_CHECKING:
    from dragodis.ghidra.flat import GhidraFlatAPI
    import ghidra


class GhidraStackFrame(StackFrame):

    def __init__(self, ghidra: GhidraFlatAPI, frame: "ghidra.program.model.listing.StackFrame"):
        self._ghidra = ghidra
        self._frame = frame

    def __eq__(self, other):
        return self is other or self._frame == other._frame

    def __getitem__(self, name_or_offset: Union[str, int]) -> GhidraStackVariable:
        """
        Obtains stack variable based on name or offset.
        """
        if isinstance(name_or_offset, int):
            offset = name_or_offset
            # Casting int to ensure we don't pass in a JLong
            var = self._frame.getVariableContaining(int(offset))
            if var is not None:
                return GhidraStackVariable(self._ghidra, var)
        elif isinstance(name_or_offset, str):
            name = name_or_offset
            for variable in self:
                if variable.name and variable.name == name:
                    return variable
        raise KeyError(f"Unable to find stack variable from: {name_or_offset}")

    # TODO: For now, stack frame will be read-only.
    # def __setitem__(self, key, value: GhidraVariable):
    #     from ghidra.program.model.symbol import SourceType
    #     try:
    #         v = self[key]
    #         v._variable = value
    #     except KeyError:
    #         if isinstance(key, int) and key == value.loc or isinstance(key, str) and key == value.name:
    #             v = self._frame.createVariable(value.loc, value.dt, SourceType.USER_DEFINED)
    #     if v:
    #         return v
    #     raise KeyError

    def __delitem__(self, name_or_offset: Union[str, int]):
        self._frame.clearVariable(self[name_or_offset].stack_offset)

    def __len__(self) -> int:
        return len(self._frame.getStackVariables())

    def __iter__(self) -> Iterable[GhidraStackVariable]:
        for var in self._frame.getStackVariables():
            yield GhidraStackVariable(self._ghidra, var)
