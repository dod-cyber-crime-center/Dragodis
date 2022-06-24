
from __future__ import annotations
from typing import TYPE_CHECKING, Optional, Iterable

from dragodis.ghidra.reference import GhidraReference
from dragodis.interface.symbol import Symbol, Import, Export

if TYPE_CHECKING:
    import ghidra
    from dragodis import Ghidra


class GhidraSymbol(Symbol):

    def __init__(self, ghidra: Ghidra, symbol: "ghidra.program.model.symbol.Symbol"):
        self._ghidra = ghidra
        self._symbol = symbol

    @property
    def address(self) -> int:
        return self._symbol.getAddress().getOffset()

    @property
    def name(self) -> str:
        return str(self._symbol.getName())

    @property
    def references_to(self) -> Iterable[GhidraReference]:
        for ref in self._symbol.getReferences():
            yield GhidraReference(self._ghidra, ref)


class GhidraImport(Import, GhidraSymbol):

    @property
    def address(self) -> int:
        # Ghidra separates import symbols from the actual address to reference the
        # function with a reference.
        # Therefore we need to iterate the references and look for a thunk or data
        # type references. (but prefer the thunk over data if we find both)
        from ghidra.program.model.symbol import RefType
        address = None
        for ref in self._symbol.getReferences():
            ref_type = ref.getReferenceType()
            if ref_type == RefType.DATA and not address:
                address = ref.getFromAddress().getOffset()
            elif ref_type == RefType.THUNK:
                address = ref.getFromAddress().getOffset()
        if not address:
            raise RuntimeError(f"Failed to get address for {self._symbol}")
        return address

    @property
    def namespace(self) -> Optional[str]:
        namespace = str(self._symbol.getParentSymbol().getName())
        if namespace == "<EXTERNAL>":
            return None
        return namespace

    @property
    def references_to(self) -> Iterable[GhidraReference]:
        address = self.address
        for ref in super().references_to:
            # Ignore self-references to thunk function.
            if ref.from_address != address:
                yield ref


class GhidraExport(Export, GhidraSymbol):
    ...
