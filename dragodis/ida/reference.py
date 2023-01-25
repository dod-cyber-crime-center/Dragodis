"""
Interface for cross references.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from dragodis.interface import Reference, ReferenceType

if TYPE_CHECKING:
    import ida_xref
    from dragodis.ida.flat import IDAFlatAPI


# noinspection PyPropertyAccess
class IDAReference(Reference):

    _type_map = {
        0: ReferenceType.unknown,          # ida_xref.fl_U
        1: ReferenceType.data_offset,           # ida_xref.dr_O
        2: ReferenceType.data_write,            # ida_xref.dr_W
        3: ReferenceType.data_read,             # ida_xref.dr_R
        4: ReferenceType.data_text,             # ida_xref.dr_T
        5: ReferenceType.data_informational,    # ida_xref.dr_I
        # 6: ReferenceType.??  # ida_xref.dr_S  # TODO
        16: ReferenceType.code_call,        # ida_xref.fl_CF
        17: ReferenceType.code_call,       # ida_xref.fl_CN
        18: ReferenceType.code_jump,        # ida_xref.fl_JF
        19: ReferenceType.code_jump,       # ida_xref.fl_JN
        20: ReferenceType.code_user,            # ida_xref.fl_USobsolete  # TODO: determine if we need this one?
        21: ReferenceType.ordinary_flow,        # ida_xref.fl_F
    }
    _type_map_inv = {value: key for key, value in _type_map.items()}

    def __init__(self, ida: IDAFlatAPI, xref: "ida_xref.xrefblk_t"):
        self._ida = ida
        self._xref = xref

    @property
    def from_address(self) -> int:
        return self._xref.frm

    @property
    def is_code(self) -> bool:
        return bool(self._xref.iscode)

    @property
    def is_data(self) -> bool:
        return self.type.name.startswith("data")  # TODO: confirm

    @property
    def to_address(self) -> int:
        return self._xref.to

    @property
    def type(self) -> ReferenceType:
        try:
            return self._type_map[self._xref.type]
        except KeyError:
            raise RuntimeError(f"Unexpected reference type: {self._xref.type}")
