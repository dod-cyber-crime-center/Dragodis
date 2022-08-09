
from __future__ import annotations
from typing import TYPE_CHECKING

from dragodis.interface.data_type import DataType

if TYPE_CHECKING:
    from dragodis import IDA
    import ida_typeinf


class IDADataType(DataType):

    def __init__(
            self,
            ida: IDA,
            tinfo: "ida_typeinf.tinfo_t" = None,
            address: int = None
    ):
        if not (tinfo or address):
            raise ValueError(f"Must provide a tinfo object or address.")
        self._ida = ida
        self._tinfo = tinfo
        self._address = address

    @property
    def name(self) -> str:
        if self._tinfo:
            return str(self._tinfo).lower().strip("_")
        else:
            TYPE_MAP = {
                self._ida._idc.FF_BYTE: "byte",
                self._ida._idc.FF_WORD: "word",
                self._ida._idc.FF_DWORD: "dword",
                self._ida._idc.FF_QWORD: "qword",
                self._ida._idc.FF_OWORD: "oword",
                self._ida._idc.FF_TBYTE: "tbyte",
                self._ida._idc.FF_STRLIT: "char",
                self._ida._idc.FF_STRUCT: "struct",
                self._ida._idc.FF_FLOAT: "float",
                self._ida._idc.FF_DOUBLE: "double",
                self._ida._idc.FF_PACKREAL: "packed decimal real",
                self._ida._idc.FF_ALIGN: "alignment directive",
            }
            flags = self._ida._ida_bytes.get_flags(self._address)
            flags &= self._ida._ida_bytes.DT_TYPE
            return TYPE_MAP[flags]

    @property
    def size(self) -> int:
        if self._tinfo:
            return self._tinfo.get_size()
        else:
            flags = self._ida._ida_bytes.get_flags(self._address)
            flags &= self._ida._ida_bytes.DT_TYPE
            return self._ida._ida_bytes.get_data_elsize(self._address, flags)
