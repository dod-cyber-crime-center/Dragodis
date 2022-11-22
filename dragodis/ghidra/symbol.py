
from __future__ import annotations
from typing import TYPE_CHECKING, Optional, Iterable

from dragodis.ghidra.reference import GhidraReference
from dragodis.interface.symbol import Symbol, Import, Export

if TYPE_CHECKING:
    import ghidra
    from dragodis.ghidra.flat import GhidraFlatAPI


class GhidraSymbol(Symbol):

    def __init__(self, ghidra: GhidraFlatAPI, symbol: "ghidra.program.model.symbol.Symbol"):
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
    def _linkage_address(self) -> "ghidra.program.model.address.GenericAddress":
        from ghidra.app.nav import NavigationUtils
        external_address = self._symbol.getAddress()
        addresses = NavigationUtils.getExternalLinkageAddresses(self._ghidra._program, external_address)
        if len(addresses) > 1:
            raise RuntimeError(f"Expected single external linkage address. Got {len(addresses)}")
        return addresses[0]

    @property
    def address(self) -> int:
        return self._linkage_address.getOffset()

    @property
    def thunk_address(self) -> Optional[int]:
        from ghidra.program.model.symbol import RefType
        symbol = self._ghidra._flatapi.getSymbolAt(self._linkage_address)
        for ref in symbol.getReferences():
            if ref.getReferenceType() == RefType.THUNK:
                return ref.getFromAddress().getOffset()

        # Before thinking we have no thunk function, try again by looking for standard
        # references from functions marked as being a thunk.
        # Sometimes Ghidra doesn't mark its references types correctly.
        for ref in symbol.getReferences():
            if ref.getReferenceType() in (RefType.COMPUTED_CALL, RefType.INDIRECTION):
                func = self._ghidra._flatapi.getFunctionContaining(ref.getFromAddress())
                if func.isThunk():
                    return func.getEntryPoint().getOffset()

    @property
    def namespace(self) -> Optional[str]:
        namespace = str(self._symbol.getParentSymbol().getName())
        if namespace == "<EXTERNAL>":
            return None
        return namespace

    @property
    def references_to(self) -> Iterable[GhidraReference]:
        thunk_address = self.thunk_address
        if thunk_address:
            thunk_function = self._ghidra.get_function(thunk_address)
        else:
            thunk_function = None

        # First pull references from original external symbol.
        from ghidra.program.model.symbol import RefType
        for ref in self._symbol.getReferences():
            if (
                ref.getReferenceType() != RefType.THUNK
                and ref.getFromAddress() != self._linkage_address
                and not (thunk_function and ref.getFromAddress().getOffset() in thunk_function)
            ):
                yield GhidraReference(self._ghidra, ref)

        # Pull references to original address pointer.
        for ref in self._ghidra.references_to(self.address):
            # Ignore self-references to thunk function.
            if ref.from_address != thunk_address:
                yield ref
        # Also pull references to thunk function.
        if thunk_address:
            yield from self._ghidra.references_to(thunk_address)


class GhidraExport(Export, GhidraSymbol):
    ...
