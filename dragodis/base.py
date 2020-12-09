"""
Base interface for Disassembler
"""

import abc
from enum import Flag, auto
import os
from typing import List


class OperandType(Flag):
    """Types of operands."""

    void = auto()
    register = auto()
    memory = auto()
    immediate = auto()
    phrase = auto()
    code = auto()


class Disassembler(abc.ABC):
    """
    Disassembler API

    - Only IDA and Ghidra currently supported
    """

    def __init__(self, input_path: str):
        """
        Initialization method.

        This  must perform any initialization, setup, or preparation needed to begin making
        regular calls to the disassembler. For instance, executing the
        disassembler binary, performing initial auto-analysis, and/or
        starting a communications server would all be appropriate actions to
        perform here.

        :param str input_path: The path of the file to process
        """
        self.input_path = os.path.abspath(input_path)

    @abc.abstractmethod
    def start(self):
        """
        Setup method.

        This should be called before starting analysis. Any setup should be done here.

        This can include spawning a process to handle the disassembler, creating a temporary
        workspace for the disassembler, etc...
        """
        pass

    @abc.abstractmethod
    def stop(self):
        """
        Teardown method.

        This should be called upon completion of analysis. Any teardown should be done here.

        This can include saving a generated file (such as an IDB), deleting temporary directories,
        shutting down spawned processes, etc...
        """
        pass

    def __enter__(self):
        """
        Entry method for context manager interface.

        Used to create a context manager for the disassembler.

        Only purpose is to call start()
        """
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """
        Exit method for context manager interface.

        Used to create a context manager for the disassembler.

        Only purpose is to call stop()
        """
        self.stop()

    @property
    @abc.abstractmethod
    def current_location(self) -> int:
        """
        Returns the current address of the disassembler's cursor.

        All addresses are treated as integers.

        :return: Current effective address
        :rtype: int
        """
        pass

    @abc.abstractmethod
    def prev_head(self, addr: int) -> int:
        """
        Returns the address head of the 'line', that is, instruction or data,
        preceding the specified address.

        If a preceding line does not exist (e.g. the base address is the first
        address of the image, or before it) then this must throw a NotExistError
        exception.

        :param int addr: Base address
        :return: Address head of previous line
        :rtype: int
        """
        pass

    @abc.abstractmethod
    def next_head(self, addr: int) -> int:
        """
        Returns the address head of the 'line', that is, instruction or data,
        following the specified address.

        If a following line does not exist (e.g. the base address is the last
        address of the image, or after it) then this must throw a NotExistError
        exception.

        :param int addr: Base address
        :return: Address head of following line
        :rtype: int
        """
        pass

    @abc.abstractmethod
    def get_head(self, addr: int) -> int:
        """
        Returns the address head of the 'line' containing ``addr``.  That is, the
        address of the start of the data item or instruction.

        For example, if there is an instruction at ``0x004010ef`` with 3 op codes and this
        method is called with ``get_line(0x004010f1)`` it must return ``0x004010ef``.

        If the address is not part of a line (instruction or data item), then
        it must throw a NotExistError exception.

        :param int addr: Base address
        :return: Address head of the line which contains ``addr``
        :rtype: int
        """
        pass

    @abc.abstractmethod
    def get_heads(self, start: int, end: int) -> List[int]:
        """
        Returns a list of all of the address heads between ``start`` and ``end``.

        The range of address heads must be ``[start, end)``. That is,
        if there is an address head at ``start``, it is included in the list, but if
        an address head is at ``end``, it is not included.

        If there are no address heads in the given range or the range is invalid
        (e.g. ``start >= end``) an empty list must be returned.

        :param int start: Start address (included)
        :param int end: End address (excluded)
        :return: List of address heads in the given range
        :rtype: list[int]
        """
        pass

    @abc.abstractmethod
    def get_xrefs_to(
        self, addr: int, code: bool = True, data: bool = True
    ) -> List[int]:
        """
        Returns a list of cross-references to the specified address.

        Two optional parameters, `code` and `data`, can be set to include
        or exclude references from code or data. By default both are set
        to `True` and all references are included.

        If there are no references to the specified address of the selected
        type(s), then this must return an empty list.

        :param int addr: Address to get references to
        :param bool code: If references from code should be included
        :param bool data: If references from data should be included
        :return: List of address that contain a reference to the address
        :rtype: list[int]
        """
        pass

    @abc.abstractmethod
    def get_xrefs_from(
        self, addr: int, code: bool = True, data: bool = True
    ) -> List[int]:
        """
        Returns a list of cross-references from the specified address.

        Two optional parameters, `code` and `data`, can be set to include
        or exclude references to code or data. By default both are set
        to `True` and all references are included.

        If there are no references from the specified address of the selected
        type(s), then this must return an empty list.

        :param int addr: Address to get references from
        :param bool code: If references to code should be included
        :param bool data: If references to data should be included
        :return: List of address that contain a reference from the address
        :rtype: list[int]
        """
        pass

    @abc.abstractmethod
    def set_name(self, addr: int, name: str):
        """
        Sets the name of specified location.

        The name text may be a unicode or bytes string. Any manipulation
        of the name to meet disassembler-specific restrictions are
        done by the implementation. This means what is given as ``name``
        may not be exactly what is saved by the disassembler.

        How this is precisely implemented is disassembler-specific, however,
        in general if ``addr`` is the starting address of a function, then
        the function at that location should have its name changed to ``name``.

        If the name was not successfully set, then this must throw an exception

        :param int addr: Address to rename
        :param name: The new name of the address
        """
        pass

    @abc.abstractmethod
    def get_function_containing(self, addr: int):
        """
        Returns a `Function` instance containing ``addr``.

        If ``addr`` is not contained within a function, then `None` must be returned.

        The :class:`~.Function` instance may be cached or a new instance created.

        :param int addr: Any address
        :return: A :class:`~.Function` instance containing the given address
        :rtype: Function or None
        """
        pass

    @abc.abstractmethod
    def get_mnemonic_at(self, addr: int) -> str:
        """
        Returns the disassembler text of the indicated instruction's mnemonic.

        The output text is disassembler specific, but all implementations
        will likely be similar. However, each implementation should do its best
        to follow the official mnemonics as much as possible.

        For valid instructions, the text must be returned as a unicode string.

        If the address is invalid, this must throw a NotExistError exception.

        :param int addr: Address of the instruction
        :return: String representation of the mnemonic
        :rtype: UnicodeString
        """
        pass

    @abc.abstractmethod
    def get_operand_type(self, addr: int, idx: int):
        """
        Returns the type of the selected operand.

        The type is returned as an :class:`~OperandType` instance.

        If the address is invalid, this must throw a NotExistError exception.
        If the index is invalid, this must throw a IndexError exception.

        :param int addr: Address of the instruction
        :param int idx: Index of the operand
        :return: Operand type
        :rtype: OperandType
        """
        pass

    @abc.abstractmethod
    def get_operand_value(self, addr: int, idx: int) -> int:
        """
        Returns the value of the indicated operand.

        If the address is invalid, this must throw a NotExistError exception.
        If the index is invalid, this must throw a IndexError exception.

        :param int addr: Address of the instruction
        :param int idx: Index of the operand
        :return: Value of the operand
        """
        pass

    @abc.abstractmethod
    def get_bytes(self, addr: int, length: int):
        """
        Returns the raw bytes at the indicated address.

        If the address is invalid, this must throw a NotExistError exception.

        :param int addr: Address to pull bytes from
        :param int length: Number of bytes to return
        :return: Raw bytes from the opened file
        :rtype: bytes
        """
        pass

    @abc.abstractmethod
    def get_qword(self, addr: int) -> int:
        """
        Returns the eight byte value at ``addr``.

        Must throw a NotExistError exception if the qword cannot be retrieved.

        :param int addr: Address where the qword is located
        :return: Eight byte value
        :rtype: int
        """

    @abc.abstractmethod
    def get_dword(self, addr: int) -> int:
        """
        Returns the four byte value at ``addr``.

        Must throw a NotExistError exception if the dword cannot be retrieved.

        :param int addr: Address where the dword is located
        :return: Four byte value
        :rtype: int
        """

    @abc.abstractmethod
    def get_word(self, addr: int) -> int:
        """
        Returns the two byte value at ``addr``.

        Must throw a NotExistError exception if the word cannot be retrieved.

        :param int addr: Address where the word is located
        :return: Two byte value
        :rtype: int
        """

    @abc.abstractmethod
    def get_byte(self, addr: int) -> int:
        """
        Returns the one byte value at ``addr``.

        Must throw a NotExistError exception if the byte cannot be retrieved.

        :param int addr: Address where the byte is located
        :return: One byte value
        :rtype: int
        """


class Function(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def from_addr(cls, addr: int):
        """Return the Function which contains ``addr``."""
        pass

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
    def name(self) -> str:
        """
        Returns the name of the function.

        The default name of a function is disassembler specific.

        The name must be returned as a `bytes` string

        :return: Function name
        :rtype: bytes
        """
        pass

    @name.setter
    @abc.abstractmethod
    def name(self, value: str):
        """Sets the name of the function to `value`."""
        pass

    @abc.abstractmethod
    def get_xrefs_to(self, code: bool = True, data: bool = True) -> List[int]:
        """
        Returns a list of all references to this function.

        In particular, this should only be references to the start
        of this function.

        See :meth:`.Disassembler.get_xrefs_to` for more information.

        :param bool code:
        :param bool data:
        :return:
        :rtype: list[int]
        """
        pass

    @abc.abstractmethod
    def get_heads(self) -> List[int]:
        """
        Returns a list of the address heads in a function.

        This method is approximately equivalent to
        ``Disassembler.get_heads(self.start_addr, self.end_addr)``.

        See :meth:`.Disassembler.get_heads` for more information.

        :return: List of address heads contained in the function
        :rtype: list[int]
        """
        pass

    @property
    @abc.abstractmethod
    def args(self) -> List[dict]:
        """
        Returns the arguments for the function.

        Each argument is represented by a dict, and must contain
        the following keys:

        * **name** (`UnicodeString`) - The name of the argument
        * **loc** (:class:`.ArgumentLocation`) - The location of the argument
        * **type** (`UnicodeString`) - The name of the argument type (like ``int``)
        * **size** (`int`) - The size of argument in bytes
        * **offset** (`int` or `None`) - The stack offset of the argument
        * **reg** (`UnicodeString` or `None`) - The register the argument is saved in
        * **reg2** (`UnicodeString` or `None`) - The 2nd register the argument is saved in
        * **address** (`int` or `None`) - The address of the argument
        * **rrel** (`dict` or `None`) - A dictionary of two keys, ``reg`` and ``off`` which contain
          the register and offset of where the argument is saved.

        Only the first four are required to have a value other than `None`. Which of the other keys
        must be set is determined by the :class:`.ArgumentLocation` in the **loc** key.

        * :attr:`.ArgumentLocation.void` - No extra fields set
        * :attr:`.ArgumentLocation.stack` - **offset** is set
        * :attr:`.ArgumentLocation.register` - **reg** is set
        * :attr:`.ArgumentLocation.register_pair` - **reg** and **reg2** are set
        * :attr:`.ArgumentLocation.register_relative` - **rrel** is set
        * :attr:`.ArgumentLocation.global_address` - **address** is set
        * :attr:`.ArgumentLocation.distributed` - Not yet implemented
        * :attr:`.ArgumentLocation.other` - Not supported

        :return: A list of the arguments for the function
        :rtype: list[dict]
        """
        pass

    @property
    @abc.abstractmethod
    def return_type(self) -> str:
        """
        Returns the return type of the function

        :return: String of the function's return type
        :rtype: UnicodeString
        """
        pass
