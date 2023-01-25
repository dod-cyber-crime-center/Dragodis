
from __future__ import annotations
import abc
from typing import Optional, TYPE_CHECKING, Any, Iterable

from dragodis.interface.types import CommentType, LineType


if TYPE_CHECKING:
    from dragodis.interface import Instruction, FlatAPI, Reference


class Line(metaclass=abc.ABCMeta):
    """
    Interface for a defined item (instruction or data).
    (This represents a "line" as you see in the disassembly view.)
    """

    def __init__(self, api: FlatAPI):
        self._api = api

    def __len__(self):
        """Here for convenience"""
        return self.size

    def __str__(self):
        return f"0x{self.address:08x}: {self.value}"

    def __repr__(self):
        return f"<Line 0x{self.address:08x} - {self.value!r}>"

    @property
    @abc.abstractmethod
    def address(self) -> int:
        """
        Starting address of the line
        """

    @property
    @abc.abstractmethod
    def data(self) -> bytes:
        """
        Raw bytes that make up this line.
        """

    @data.setter
    @abc.abstractmethod
    def data(self, new_data: bytes):
        """
        Sets the data that represents the line.
        This patches the underlying disassembler with the given data.

        WARNING: The new_data provided should be of the same size as the original.
        """

    @abc.abstractmethod
    def get_comment(self, comment_type=CommentType.eol) -> Optional[str]:
        """
        Obtains comment (of specific type) at line.

        :param comment_type: Type of comment to get (defaults to end of line comment)
        :returns: String containing comment or None if there is no comment.
        """

    @property
    def instruction(self) -> Optional[Instruction]:
        """
        The Instruction object for the given line (if line is an instruction)
        Returns None if not an instruction.
        """
        if self.is_code:
            return self.value

    @property
    def is_code(self) -> bool:
        """
        Convenience property for determining if the line is an instruction.
        """
        return self.type == LineType.code

    @property
    def is_float(self) -> bool:
        """
        Convenience property for determing if the line is a float type.
        """
        return self.type in (LineType.float, LineType.double)

    @property
    def is_integer(self) -> bool:
        """
        Convenience property for determine if the line is an integer.
        """
        return self.type in (LineType.word, LineType.dword, LineType.qword, LineType.oword)

    @property
    def is_loaded(self) -> bool:
        """
        Convenience property for determining if the line is loaded.
        """
        return self.type != LineType.unloaded

    @property
    def is_string(self) -> bool:
        """
        Convenience property for determingin if the line is a string (with any encoding).
        """
        return self.type in (LineType.string, LineType.string16, LineType.string32)

    @property
    @abc.abstractmethod
    def name(self) -> Optional[str]:
        """
        The current name or label on the line.
        Returns None if line doesn't have a name.
        """

    # TODO: Since the name actual set by the disassembler may be different than
    #   what was passed, should we make this a function "set_name()" or "rename()"
    #   instead?
    # TODO: Should we have our own standardization for modifying duplicate names so
    #   they are consistent across disassemblers?
    @name.setter
    @abc.abstractmethod
    def name(self, value: str):
        """
        Sets the name of the line.
        """

    @property
    @abc.abstractmethod
    def next(self) -> Optional["Line"]:
        """
        The next line (if it exists).
        """

    @property
    @abc.abstractmethod
    def prev(self) -> Optional["Line"]:
        """
        The previous line (if it exists).
        """

    @abc.abstractmethod
    def set_comment(self, comment: Optional[str], comment_type=CommentType.eol):
        """
        Sets comment (of specific type) at line.

        :param str comment: comment string to set.
            (If value is an empty string or None, existing comments are cleared)
        :param comment_type: Type of comment to set (default to end of line comment)
        """

    @property
    @abc.abstractmethod
    def size(self) -> int:
        """
        Number of bytes of data that make up this line.
        """

    @property
    @abc.abstractmethod
    def type(self) -> LineType:
        """
        The type of line
        """

    @type.setter
    @abc.abstractmethod
    def type(self, new_type: LineType):
        """
        Sets the type that represents the line.
        This patches the underlying disassembler to the given type.

        WARNING: Changing this to a type that is larger and smaller will cause
        changes to the .next value, be sure to clear it's cache in your implementation.
        """

    @abc.abstractmethod
    def undefine(self):
        """
        Undefines the line, clearing the line of any type annotation.

        WARNING: Be sure to clear the property cache after clearing.
        TODO: We should have a utility for clearing the caches of all the properties.
        """

    @property
    @abc.abstractmethod
    def value(self) -> Any:
        """
        A value that represents the line.
        The return type is dependent upon the type of line.

        e.g.
            code -> Instruction
            dword -> int
            word -> int
            float -> float
            double -> float
            string -> str
            align -> bytes
            unknown -> bytes
        """

    @value.setter
    @abc.abstractmethod
    def value(self, new_value: Any):
        """
        Sets the value that represents the line.
        This patches the underlying disassembler with the given value.
        If the data type changes, the type will be patched too.
        """

    @property
    def references_from(self) -> Iterable[Reference]:
        """
        Iterates cross references from the specified address.

        :param int addr: Address to get references from
        :yield: `Reference` objects.
        """
        yield from self._api.references_from(self.address)

    @property
    def references_to(self) -> Iterable[Reference]:
        """
        Iterates cross references to the specified address.

        :param int addr: Address to get references to
        :yield: `Reference` objects.
        """
        yield from self._api.references_to(self.address)
