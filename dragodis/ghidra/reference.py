from __future__ import annotations

from typing import TYPE_CHECKING

from dragodis.interface import Reference, ReferenceType

if TYPE_CHECKING:
    import ghidra
    from dragodis.ghidra.flat import GhidraFlatAPI


class GhidraReference(Reference):

    def __init__(self, ghidra: GhidraFlatAPI, reference: "ghidra.program.model.symbol.Reference"):
        self._ghidra = ghidra
        self._reference = reference

    @property
    def _ref_type(self) -> "ghidra.program.model.symbol.RefType":
        return self._reference.getReferenceType()

    @property
    def from_address(self) -> int:
        return self._reference.getFromAddress().getOffset()

    @property
    def is_code(self) -> bool:
        # TODO
        return not self.is_data

    @property
    def is_data(self) -> bool:
        return self._ref_type.isData()

    @property
    def to_address(self) -> int:
        return self._reference.getToAddress().getOffset()

    # TODO: Look into this further.
    #   - Need to better standardize reference types to match with both IDA and Ghidra.
    @property
    def type(self) -> ReferenceType:
        ref_type = self._ref_type
        if ref_type.isData():
            if ref_type.isRead():
                return ReferenceType.data_read
            elif ref_type.isWrite():
                return ReferenceType.data_write
            else:
                return ReferenceType.data  # TODO: Sometimes it is not read or write...
        elif ref_type.isCall():
            return ReferenceType.code_call
        elif ref_type.isJump():
            return ReferenceType.code_jump
        elif ref_type.isFallthrough():
            return ReferenceType.ordinary_flow
        else:
            return ReferenceType.unknown
