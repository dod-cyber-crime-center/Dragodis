
from __future__ import annotations
from typing import TYPE_CHECKING

from dragodis.interface.string import String

if TYPE_CHECKING:
    from dragodis.ghidra.flat import GhidraFlatAPI
    import ghidra


class GhidraString(String):

    def __init__(self, ghidra: GhidraFlatAPI, data_item: "ghidra.program.model.listing.Data"):
        self._ghidra = ghidra
        self._data_item = data_item

    @property
    def value(self) -> str:
        return str(self._data_item.value)

    @property
    def data(self) -> bytes:
        return self._ghidra.get_bytes(self.address, self._data_item.getLength()).rstrip(b"\x00")

    @property
    def address(self) -> int:
        return self._data_item.getAddress().getOffset()
