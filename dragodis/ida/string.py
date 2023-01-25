
from __future__ import annotations
from typing import TYPE_CHECKING

from dragodis.interface.string import String

if TYPE_CHECKING:
    from dragodis.ida.flat import IDAFlatAPI
    import idautils


class IDAString(String):

    def __init__(self, ida: IDAFlatAPI, string: "idautils.Strings.StringItem"):
        self._ida = ida
        self._string = string

    @property
    def value(self) -> str:
        return str(self._string)

    @property
    def data(self) -> bytes:
        return self._ida._ida_bytes.get_strlit_contents(self._string.ea, self._string.length, self._string.strtype)

    @property
    def address(self) -> int:
        return self._string.ea
