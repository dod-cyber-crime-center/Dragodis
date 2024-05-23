"""
Function Stack
"""

import abc
from collections.abc import MutableMapping
from typing import Union, Iterable

from dragodis.interface.variable import StackVariable


class StackFrame(MutableMapping, metaclass=abc.ABCMeta):
    """Function Stack Frame"""

    def __str__(self) -> str:
        return "\n".join(map(str, self))

    def __repr__(self):
        vars = ", ".join(map(repr, self))
        return f"<StackFrame {vars}>"

    @abc.abstractmethod
    def __getitem__(self, name_or_offset: Union[str, int]) -> StackVariable:
        """
        Obtain a stack variable from given name or offset within the stack.
        """

    def __setitem__(self, key, value):
        raise KeyError("StackFrame is read-only.")

    @abc.abstractmethod
    def __delitem__(self, name_or_offset: Union[str, int]):
        """
        Remove a stack variable from given name or offset within the stack.
        """

    @abc.abstractmethod
    def __iter__(self) -> Iterable[StackVariable]:
        """
        Iterates variable objects in the stack.
        """

    @abc.abstractmethod
    def __len__(self) -> int:
        """
        Number of variables in the stack
        """
