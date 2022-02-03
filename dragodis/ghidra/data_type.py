
from typing import TYPE_CHECKING

from dragodis.interface.data_type import DataType

if TYPE_CHECKING:
    import ghidra


class GhidraDataType(DataType):

    def __init__(self, data_type: "ghidra.program.model.data.DataType"):
        self._data_type = data_type

    @property
    def name(self) -> str:
        return self._data_type.getName()

    @property
    def size(self) -> int:
        return self._data_type.getLength()
