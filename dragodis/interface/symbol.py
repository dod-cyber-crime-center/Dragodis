"""
Interface for symbols
"""

from __future__ import annotations
import abc

from typing import Optional, Iterable, TYPE_CHECKING

from dragodis.interface.types import ReferenceType

if TYPE_CHECKING:
    from dragodis.interface import Reference


class Symbol(metaclass=abc.ABCMeta):
    """
    Symbols match a specific address to a string name.
    """

    def __str__(self) -> str:
        return f"{self.name}: 0x{self.address:08x}"

    def __repr__(self) -> str:
        return f"<Symbol {self}>"

    @property
    @abc.abstractmethod
    def address(self) -> int:
        """
        The address pointed to by the symbol
        """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Name of the symbol
        """

    @property
    @abc.abstractmethod
    def references_to(self) -> Iterable[Reference]:
        """
        References to symbol
        """


class Import(Symbol):
    """
    Imports are a type of Symbol which have an external source or module.
    """

    def __str__(self) -> str:
        return f"{self.namespace}/{self.name}: 0x{self.address:08x}"

    def __repr__(self) -> str:
        return f"<Import {self}>"

    @property
    @abc.abstractmethod
    def namespace(self) -> Optional[str]:
        """
        The name of the external source of the import if available.
        Which is usually the name of the DLL.
        """

    @property
    @abc.abstractmethod
    def thunk_address(self) -> Optional[int]:
        """
        The address for the thunk function if it exists.
        """

    @property
    def calls_to(self) -> Iterable[int]:
        """
        Iterates addresses that call this import.
        """
        for ref in self.references_to:
            if ref.type == ReferenceType.code_call:
                yield ref.from_address


class Export(Symbol):
    """
    Exports are a type of Symbol which are declared entry points to the binary.
    """

    def __repr__(self) -> str:
        return f"<Export {self}>"
