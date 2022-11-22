
from __future__ import annotations
from typing import Optional, Iterable, TYPE_CHECKING

from dragodis.ida.reference import IDAReference
from dragodis.interface.symbol import Symbol, Import, Export

if TYPE_CHECKING:
    from dragodis.ida.flat import IDAFlatAPI


class IDASymbol(Symbol):

    def __init__(self, ida: IDAFlatAPI, address: int, name: str):
        self._ida = ida
        self._address = address
        self._name = name

    @property
    def address(self) -> int:
        return self._address

    @property
    def name(self) -> str:
        return self._name

    @property
    def references_to(self) -> Iterable[IDAReference]:
        yield from self._ida.references_to(self.address)


class IDAImport(Import, IDASymbol):

    def __init__(self, ida: IDAFlatAPI, address: int, thunk_address: Optional[int], name: str, namespace: Optional[str]):
        super().__init__(ida, address, name)
        self._thunk_address = thunk_address
        self._namespace = namespace

    @property
    def thunk_address(self) -> Optional[int]:
        return self._thunk_address

    @property
    def namespace(self) -> Optional[str]:
        return self._namespace

    @property
    def references_to(self) -> Iterable[IDAReference]:
        # Pull references to original address pointer.
        thunk_address = self.thunk_address
        for ref in super().references_to:
            # ignore self-references to thunk address.
            if ref.from_address != thunk_address:
                yield ref
        # Also pull references to thunk function if it exists.
        if thunk_address:
            yield from self._ida.references_to(thunk_address)


class IDAExport(Export, IDASymbol):
    ...
