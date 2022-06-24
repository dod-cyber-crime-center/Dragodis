
from __future__ import annotations
from typing import Optional, Iterable, TYPE_CHECKING

from dragodis.ida.reference import IDAReference
from dragodis.interface.symbol import Symbol, Import, Export

if TYPE_CHECKING:
    from dragodis import IDA


class IDASymbol(Symbol):

    def __init__(self, ida: IDA, address: int, name: str):
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
        line = self._ida.get_line(self.address)
        yield from line.references_to


class IDAImport(Import, IDASymbol):

    def __init__(self, ida: IDA, address: int, name: str, namespace: Optional[str]):
        super().__init__(ida, address, name)
        self._namespace = namespace

    @property
    def namespace(self) -> Optional[str]:
        return self._namespace


class IDAExport(Export, IDASymbol):
    ...
