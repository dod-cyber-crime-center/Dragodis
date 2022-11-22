
from __future__ import annotations

from dragodis.ida.data_type import IDADataType
from dragodis.interface.variable import StackVariable, GlobalVariable
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from dragodis.ida.flat import IDAFlatAPI
    from dragodis.ida.stack import IDAStackFrame
    import ida_struct


class IDAGlobalVariable(GlobalVariable):

    def __init__(self, ida: IDAFlatAPI, address: int):
        self._ida = ida
        self._address = address

    @property
    def address(self) -> int:
        return self._address

    @property
    def name(self) -> str:
        return self._ida.get_name(self._address)

    @name.setter
    def name(self, new_name: str):
        self._ida.set_name(self._address, new_name)

    @property
    def size(self) -> int:
        return self._ida._ida_bytes.get_item_size(self._address)

    @property
    def data_type(self) -> IDADataType:
        return IDADataType(self._ida, address=self._address)


class IDAStackVariable(StackVariable):

    def __init__(self, ida: IDAFlatAPI, frame: IDAStackFrame, member: "ida_struct.member_t"):
        self._ida = ida
        self._frame = frame
        self._member = member

    def __eq__(self, other: "IDAVariable") -> bool:
        return self._frame == other._frame and self._member.id == other._member.id

    @property
    def stack_offset(self) -> int:
        return self._member.soff - self._frame._base_offset

    @property
    def name(self) -> str:
        return self._ida._ida_struct.get_member_name(self._member.id) or ""

    @name.setter
    def name(self, new_name: str):
        self._ida._ida_struct.set_member_name(self._frame._frame, self._member.soff, new_name)

    @property
    def data_type(self) -> IDADataType:
        tif = self._ida._ida_typeinf.tinfo_t()
        success = self._ida._ida_struct.get_or_guess_member_tinfo(tif, self._member)
        if not success:
            raise RuntimeError("Unexpected error getting type information.")
        return IDADataType(self._ida, tif)  #, self._member.flag & self._ida._idc.DT_TYPE)

    @property
    def size(self) -> int:
        return self._ida._ida_struct.get_member_size(self._member)


IDAVariable = Union[IDAGlobalVariable, IDAStackVariable]
