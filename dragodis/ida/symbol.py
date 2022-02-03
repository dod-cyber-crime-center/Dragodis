from typing import Optional

from dragodis.interface.symbol import Symbol, Import, Export


class IDASymbol(Symbol):

    def __init__(self, address: int, name: str):
        self._address = address
        self._name = name

    @property
    def address(self) -> int:
        return self._address

    @property
    def name(self) -> str:
        return self._name


class IDAImport(Import, IDASymbol):

    def __init__(self, address: int, name: str, namespace: Optional[str]):
        super().__init__(address, name)
        self._namespace = namespace

    @property
    def namespace(self) -> Optional[str]:
        return self._namespace


class IDAExport(Export, IDASymbol):
    ...
