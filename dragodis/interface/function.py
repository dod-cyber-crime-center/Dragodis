
from __future__ import annotations
import abc
from typing import List, Iterable, Optional, TYPE_CHECKING, Tuple

from dragodis.exceptions import NotExistError
from dragodis.interface.function_signature import FunctionSignature
from dragodis.interface.stack import StackFrame
from dragodis.interface.types import ReferenceType

if TYPE_CHECKING:
    from dragodis.interface import Reference, Instruction, Flowchart, FlatAPI, Variable

from dragodis.interface.line import CommentType, Line


class Function(metaclass=abc.ABCMeta):
    """
    Function objects represent the actual functions that are found in a disassembler.
    """

    def __init__(self, api: FlatAPI):
        self._api = api

    def __hash__(self):
        return self.start

    def __eq__(self, other):
        return isinstance(other, Function) and self.start == other.start

    def __contains__(self, addr: int) -> bool:
        """
        Returns whether the given address is within the function.
        Defaults to checking if address is in-between start and end.
        """
        return self.start <= addr < self.end

    def __str__(self) -> str:
        return f"{self.name}()"

    def __repr__(self):
        return f"<Function 0x{self.start:08x}: {self}>"

    @property
    @abc.abstractmethod
    def start(self) -> int:
        """
        Returns the start address for the function.

        :return: The start address for the function
        :rtype: int
        """
        pass

    @property
    @abc.abstractmethod
    def end(self) -> int:
        """
        Returns the end address for the function.

        The end address is *not* part of the function.

        :return: The end address for the function
        :rtype: int
        """
        pass

    @property
    @abc.abstractmethod
    def flowchart(self) -> Flowchart:
        """
        The Flowchart that makes up the function.
        """

    @abc.abstractmethod
    def get_comment(self, comment_type=CommentType.anterior) -> Optional[str]:
        """
        Obtains comment for function.

        :param comment_type: Type of comment to get (defaults to end of line comment)
        :returns: String containing comment or None if there is no comment.
        """

    def lines(self, start: int = None, end: int = None, reverse=False) -> Iterable[Line]:
        """
        Iterates the line items in the function.

        NOTE: This is BFS using the flowchart.
        If you need something simpler you can use .lines() directly:

        .. code:: python

            lines = dis.lines(func.start, func.end)
        """
        for line in self.flowchart.lines(start, reverse=reverse):
            if end and line.address == end:
                break
            yield line

    def instructions(self, start: int = None, end: int = None, reverse=False) -> Iterable[Instruction]:
        """
        Iterates the instructions in the function.
        """
        for line in self.lines(start=start, end=end, reverse=reverse):
            insn = line.instruction
            if insn:
                yield insn

    @property
    def variables(self) -> Iterable[Variable]:
        """
        Iterates the variables in the function.
        """
        for insn in self.instructions():
            yield from insn.variables

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Returns the name of the function.

        NOTE: The default name of a function is disassembler specific.
        """

    @name.setter
    @abc.abstractmethod
    def name(self, new_name: Optional[str]):
        """
        Sets the name of the function or resets the name if None/"" is provided.
        """

    @property
    def references_from(self) -> Iterable[Reference]:
        """
        Iterates external cross references from the function.
        This includes references for all instructions contained within the function.
        However, only references to external locations are counted.

        :yield: `Reference` objects.
        """
        for instruction in self.instructions():
            for ref in instruction.references_from:
                # Only count external references to avoid recursive loops.
                if ref.to_address not in self:
                    yield ref

    @property
    def references_to(self) -> Iterable[Reference]:
        """
        Iterates external cross references to the function.
        This includes references for all instructions contained within the function.
        However, only references from external locations are counted.

        :yield: `Reference` objects.
        """
        for instruction in self.instructions():
            for ref in instruction.references_to:
                # Only count external references to avoid recursive loops.
                if ref.from_address not in self:
                    yield ref

    @abc.abstractmethod
    def set_comment(self, comment: str, comment_type=CommentType.anterior):
        """
        Sets comment (of specific type) at line.

        :param str comment: comment string to set.
            (If value is an empty string, existing comments are cleared)
        :param comment_type: Type of comment to set (default to end of line comment)
        """

    @property
    def data(self) -> bytes:
        """
        Returns all the bytes contained in the function.
        WARNING: This doesn't yet properly support fragmented functions.
        """
        return self._api.get_bytes(self.start, self.end - self.start)

    @property
    def source_code(self) -> Optional[str]:
        """
        Provides decompiled source code for the function.

        WARNING: Implementing this property is optional since not all
            disassemblers may support decompilation.
            Users should handle the scenario when this property is None.

        WARNING: Decompiled source code is going to look very different based
            on what disassembler is used. Therefore, users should not use
            this in program logic and should really only be for display purposes.
        """
        return None

    @property
    @abc.abstractmethod
    def stack_frame(self) -> StackFrame:
        """
        Provides the stack frame for this function.
        """

    @property
    def signature(self) -> FunctionSignature:
        """
        The signature of the function.
        """
        return self._api.get_function_signature(self.start)

    @property
    def calls_to(self) -> Iterable[int]:
        """
        Iterates addresses that call this function.
        """
        for ref in self._api.references_to(self.start):
            if ref.type == ReferenceType.code_call:
                yield ref.from_address

    @property
    def calls_from(self) -> Iterable[Tuple[int, int]]:
        """
        Iterates call address and callee address for the calls within this function.
        """
        for ref in self.references_from:
            if ref.type == ReferenceType.code_call:
                yield ref.from_address, ref.to_address

    @property
    def callers(self) -> Iterable["Function"]:
        """
        Iterates Functions that call this function.
        NOTE: Recursive calls to itself are not counted.
        """
        cache = set()
        for addr in self.calls_to:
            try:
                func = self._api.get_function(addr)
            except NotExistError:
                continue
            if func.name not in cache:
                cache.add(func.name)
                yield func

    @property
    def callees(self) -> Iterable["Function"]:
        """
        Iterates Functions that this function calls.
        NOTE: Recursive calls to itself are not counted.
        """
        cache = set()
        for addr, func_addr in self.calls_from:
            try:
                func = self._api.get_function(func_addr)
            except NotExistError:
                continue
            if func.name not in cache:
                cache.add(func.name)
                yield func

    # TODO: Proper support for Function types.
    @property
    @abc.abstractmethod
    def is_library(self) -> bool:
        """
        Whether the function is a known library function.
        """

