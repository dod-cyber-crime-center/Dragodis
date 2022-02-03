"""
Interface for symbols
"""

import abc

from typing import Optional


class Symbol(metaclass=abc.ABCMeta):
    """
    Symbols match a specific address to a string name.
    """

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


class Import(Symbol):
    """
    Imports are a type of Symbol which have an external source or module.
    """

    @property
    @abc.abstractmethod
    def namespace(self) -> Optional[str]:
        """
        The name of the external source of the import if available.
        Which is usually the name of the DLL.
        """


class Export(Symbol):
    """
    Exports are a type of Symbol which are declared entry points to the binary.
    """

