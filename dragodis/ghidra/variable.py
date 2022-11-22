
from __future__ import annotations
from typing import TYPE_CHECKING, Union

from dragodis.interface.variable import StackVariable, GlobalVariable
from dragodis.ghidra.data_type import GhidraDataType

if TYPE_CHECKING:
    from dragodis.ghidra.flat import GhidraFlatAPI
    import ghidra


class GhidraGlobalVariable(GlobalVariable):

    def __init__(self, ghidra: GhidraFlatAPI, data: "ghidra.program.model.listing.Data"):
        self._ghidra = ghidra
        self._data = data

    def __eq__(self, other) -> bool:
        return isinstance(other, GhidraGlobalVariable) and self.address == other.address

    @property
    def address(self) -> int:
        return self._data.getAddress().getOffset()

    @property
    def name(self) -> str:
        return self._data.getPathName()

    @name.setter
    def name(self, new_name: str):
        from ghidra.program.model.symbol.SourceType import SourceType
        symbol = self._ghidra._flatapi.getSymbolAt(self._data.getAddress())
        symbol.setName(new_name, SourceType.USER_DEFINED)

    @property
    def data_type(self) -> GhidraDataType:
        return GhidraDataType(self._data.getDataType())

    @property
    def size(self) -> int:
        return self._data.getLength()


class GhidraStackVariable(StackVariable):

    def __init__(self, ghidra: GhidraFlatAPI, variable: "ghidra.program.model.listing.Variable"):
        if not variable.isStackVariable():
            raise ValueError(f"{variable} must be a stack variable")
        self._ghidra = ghidra
        self._variable = variable

    def __eq__(self, other) -> bool:
        return isinstance(other, GhidraStackVariable) and self._variable.isEquivalent(other._variable)

    @property
    def stack_offset(self) -> int:
        return self._variable.getStackOffset()

    @property
    def name(self) -> str:
        return self._variable.getName()

    @name.setter
    def name(self, new_name: str):
        from ghidra.program.model.symbol.SourceType import SourceType
        self._variable.setName(new_name, SourceType.USER_DEFINED)

    @property
    def data_type(self) -> GhidraDataType:
        return GhidraDataType(self._variable.getDataType())

    # @data_type.setter
    # def data_type(self, data_type: DataType):
    #     self._variable.setDataType(data_type)

    @property
    def size(self) -> int:
        return self._variable.getLength()


GhidraVariable = Union[GhidraGlobalVariable, GhidraStackVariable]
