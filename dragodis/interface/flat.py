
import abc
from typing import Iterable, Optional, Union

import capstone

# TODO: Rename to base?
from dragodis.exceptions import NotExistError
from dragodis.interface.string import String
from dragodis.interface.variable import GlobalVariable
from dragodis.interface.data_type import DataType
from dragodis.interface.function_signature import FunctionSignature
from dragodis.interface.operand import Operand
from dragodis.interface.operand_value import Register, OperandValue
from dragodis.interface.function import Function
from dragodis.interface.flowchart import Flowchart, BasicBlock
from dragodis.interface.instruction import Instruction
from dragodis.interface.memory import Memory
from dragodis.interface.segment import Segment
from dragodis.interface.line import Line
from dragodis.interface.reference import Reference
from dragodis.interface.symbol import Import, Export
from dragodis.interface.types import OperandType, CommentType, ReferenceType


# TODO: Look into using zope.interface instead of abc
class FlatAPI(metaclass=abc.ABCMeta):
    """
    The Flat API is provided to allow easier access to some data that would require more
    steps than necessary to access through the OOP API. The Flat API also provides many of
    the functions that the OOP API is built upon.

    NOTE: This class is designed to be used as a mixin along with a Disassembler class.
    """

    # TODO:
    #   - FlatAPI/Base should handle the caching of different types based on its constructors?
    #       - Or should that be done by the classes themselves? (ie. a from_cache() function)
    #   - FlatAPI/Base should define the classes used to construct Function, Operand, etc.

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)  # forward to Disassembler class
        self.__capstone_dis = None

    def __repr__(self):
        return (
            f"<Disassembler "
            f"{self.name}:{self.processor_name}:{self.bit_size}-{'BE' if self.is_big_endian else 'LE'}>"
        )

    @property
    def _capstone_dis(self) -> capstone.Cs:
        """
        Obtains capstone disassembler.
        This can be used to help fill in for missing feature sets of the backend disassembler.
        """
        if not self.__capstone_dis:
            if self.processor_name == "x86":
                arch = capstone.CS_ARCH_X86
                mode = {
                    16: capstone.CS_MODE_16,
                    32: capstone.CS_MODE_32,
                    64: capstone.CS_MODE_64,
                }[self.bit_size]
            elif self.processor_name == "ARM":
                arch = {
                    32: capstone.CS_ARCH_ARM,
                    64: capstone.CS_ARCH_ARM64,
                }[self.bit_size]
                # TODO: Support thumb mode.
                mode = capstone.CS_MODE_ARM
            else:
                raise NotImplementedError(f"Unsupported processor: {self.processor_name}")
            self.__capstone_dis = capstone.Cs(arch, mode)
            self.__capstone_dis.detail = True
        return self.__capstone_dis

    @property
    @abc.abstractmethod
    def processor_name(self) -> str:
        """
        Returns the name of the processor.
        """

    @property
    @abc.abstractmethod
    def compiler_name(self) -> str:
        """
        Returns the name of the compiler.
        """

    @property
    @abc.abstractmethod
    def bit_size(self) -> int:
        """
        Returns the address bit size of the detected processor.
        """

    @property
    @abc.abstractmethod
    def is_big_endian(self) -> bool:
        """
        Whether the processor is big endian.
        (Assumed to be little endian if False)
        """

    @property
    @abc.abstractmethod
    def entry_point(self) -> Optional[int]:
        """
        The address for the OEP (Original Entry Point) or general starting address for the program (if applicable).
        NOTE: This is usually the "AddressOfEntryPoint" listing. Use .exports to get other possible entry points.

        :yields: Address of the entry point or None if not applicable.
        """

    def is_loaded(self, addr: int) -> bool:
        """
        Determines if the given address exists and is loaded in the sample.

        :param addr: Address to test.
        :return: Whether the address exists and is loaded.
        """
        try:
            return self.get_line(addr).is_loaded
        except NotExistError:
            return False

    @abc.abstractmethod
    def functions(self, start=None, end=None) -> Iterable[Function]:
        """
        Iterates `Function` objects found within the range of the given
        `start` and `end` addresses.

        :param int start: Start address to start iterating functions (defaults to beginning of program)
            If the start address is at the beginning of a function, that function is
            not included. Only functions for which we find the entry point.
        :param int end: End address to end iterating functions (defaults to end of program)
            If end address is within a function, that function may still be counted if the
            entry point is before the end address.
        """

    @abc.abstractmethod
    def get_virtual_address(self, file_offset: int) -> int:
        """
        Obtains virtual address from given file offset.

        :param int file_offset: Offset within underlying source file.
        :raises NotExistsError: If a virtual address doesn't exists for given file offset.
        """

    @abc.abstractmethod
    def get_file_offset(self, addr: int) -> int:
        """
        Obtains offset within underlying source file from given virtual address.

        :param int addr: Linear address.
        :raises NotExistsError: If a file offset doesn't exists for given address.
        """

    # TODO: Move these to some type of Memory object?

    @abc.abstractmethod
    def get_byte(self, addr: int) -> int:
        """
        Returns the one byte value at ``addr``.

        Must throw a NotExistError exception if the byte cannot be retrieved.

        :param int addr: Address where the byte is located
        :return: One byte value
        :rtype: int
        """

    @abc.abstractmethod
    def get_bytes(self, addr: int, length: int, default: int = None) -> bytes:
        """
        Returns the raw bytes at the indicated address.

        If the address is invalid, this must throw a NotExistError exception.

        :param addr: Address to pull bytes from
        :param length: Number of bytes to return
        :param default: Default byte value to use for anything not mapped in the disassembler.
            Defaults to throwing a NotExistError for invalid ranges.

        :return: Raw bytes from the opened file
        :raises NotExistError: If bytes within the given range does not exist.
        """

    @abc.abstractmethod
    def find_bytes(self, pattern: bytes, start: int = None, reverse: bool = False) -> int:
        """
        Search to find bytes for given pattern.

        NOTE: This just preforms simple byte matching. For something more complex
            like wild cards, I recommend using rugosa.re

        :param pattern: Bytes we are looking for
        :param start: Address to start the search (defaults to min or max address)
        :param reverse: Whether to search upwards instead of downwards.
        :return: The start address for the first found instance of given bytes or -1 if not found.
        """

    def get_word(self, addr: int) -> int:
        """
        Returns the two byte value at ``addr``.

        Must throw a NotExistError exception if the word cannot be retrieved.

        :param int addr: Address where the word is located
        :return: Two byte value
        :rtype: int
        """
        return int.from_bytes(self.get_bytes(addr, 2), "little")

    def get_dword(self, addr: int) -> int:
        """
        Returns the four byte value at ``addr``.

        Must throw a NotExistError exception if the dword cannot be retrieved.

        :param int addr: Address where the dword is located
        :return: Four byte value
        :rtype: int
        """
        return int.from_bytes(self.get_bytes(addr, 4), "little")

    def get_qword(self, addr: int) -> int:
        """
        Returns the eight byte value at ``addr``.

        Must throw a NotExistError exception if the qword cannot be retrieved.

        :param int addr: Address where the qword is located
        :return: Eight byte value
        :rtype: int
        """
        return int.from_bytes(self.get_bytes(addr, 8), "little")

    # TODO: determine if it would be better the other way around, where line's
    #   get_comment()/set_comment() call the flat api implementation.
    #   - OR should we only have comment stuff on flat and remove from line object?
    def get_comment(self, addr: int, comment_type=CommentType.eol) -> Optional[str]:
        """
        Obtains comment (of specific type) at line.

        :param addr int: Address of line to get comment from.
        :param comment_type: Type of comment to get (defaults to end of line comment)
        :returns: String containing comment or None if there is no comment.
        """
        return self.get_line(addr).get_comment(comment_type=comment_type)

    @abc.abstractmethod
    def get_function(self, addr: int) -> Function:
        """
        Returns a `Function` instance containing ``addr``.

        The :class:`~.Function` instance may be cached or a new instance created.

        :param int addr: Any address within the Function

        :return: A :class:`~.Function` instance containing the given address
        :raises NotExistError: If there is no function containing the given address.
        """

    def get_function_by_name(self, name: str, ignore_underscore: bool = True) -> Function:
        """
        Returns a `Function` instance with given name.

        :param str name: Name of function to obtain
        :param bool ignore_underscore: Whether to ignore leading or trailing underscores in function name.
            (Will return the first found function if enabled.)

        :return: A :class:`~.Function` instance containing the given address
        :raises NotExistError: If there is no function containing the given address.
        """
        for func in self.functions():
            func_name = func.name
            if ignore_underscore:
                func_name = func_name.strip("_")
            if func_name == name:
                return func
        raise NotExistError(f"Unable to find function with name: {name}")

    # TODO: Implement ability to provide operand for the assist?
    @abc.abstractmethod
    def get_function_signature(self, addr: int) -> FunctionSignature:
        """
        Returns a `FunctionSignature` instance for the function defined at ``addr``.
        Address can be the start of a function or address or an imported function.

        :param int addr: Any address
        :raises NotExistError: If there is no function signature at the given address.
        """

    def get_flowchart(self, addr: int) -> Flowchart:
        """
        Returns a `Flowchart` instance containing ``addr``.

        :param int addr: Any address within the Flowchart
        :raises NotExistError: If there is no flowchart containing the given address.
        """
        return self.get_function(addr).flowchart

    def get_basic_block(self, addr: int) -> BasicBlock:
        """
        Returns a `BasicBlock` instance containing ``addr``.

        :param int addr: Any address within the BasicBlock
        :raises NotExistError: If there is no basic block containing the given address.
        """
        return self.get_flowchart(addr).get_block(addr)

    def get_instruction(self, addr: int) -> Instruction:
        """
        Returns an Instruction object for the given any address contained within the
        instruction.

        :param int addr: Address of the instruction
        :return: Instruction object
        :raises NotExistError: If instruction isn't present at given address.
        """
        line = self.get_line(addr)
        instruction = line.instruction
        if instruction:
            return instruction
        else:
            raise NotExistError(f"Instruction not found at {hex(addr)}")

    @abc.abstractmethod
    def get_line(self, addr: int) -> Line:
        """
        Returns a Line object representing a defined item containing an instruction
        or data containing the given ``addr``

        If the address is not part of a line (instruction or data item), then
        it must throw a NotExistError exception.

        :param int addr: An address contained within the Line.
        """

    def get_line_address(self, addr: int) -> int:
        """
        Returns the address head of the 'line' containing ``addr``.  That is, the
        address of the start of the data item or instruction.

        For example, if there is an instruction at ``0x004010ef`` with 3 op codes and this
        method is called with ``get_line(0x004010f1)`` it must return ``0x004010ef``.

        :param int addr: Base address
        :return: Address head of the line which contains ``addr``
        :rtype: int
        """
        return self.get_line(addr).address

    def get_mnemonic(self, addr: int) -> str:
        """
        Returns the disassembler text of the indicated instruction's mnemonic.

        The output text is disassembler specific, but all implementations
        will likely be similar. However, each implementation should do its best
        to follow the official mnemonics as much as possible.

        :param int addr: Address of the instruction
        :return: String representation of the mnemonic
        :raises NotExistError: If instruction isn't present at given address.
        """
        instruction = self.get_instruction(addr)
        return instruction.mnemonic

    def get_name(self, addr: int) -> Optional[str]:
        """
        Gets the name of the specified location (if applicable)

        :param int addr: Address
        :returns: Name at address or None if address has no name.
        """
        # Get name for either the function or line
        func = None
        try:
            func = self.get_function(addr)
        except NotExistError:
            pass

        if func and func.start == addr:
            return func.name
        else:
            return self.get_line(addr).name

    def get_operand(self, addr: int, index: int) -> Operand:
        """
        Returns an Operand object based on the operand at a given address.
        """
        instruction = self.get_instruction(addr)
        operands = instruction.operands
        try:
            return operands[index]
        except IndexError:
            raise NotExistError(
                f"Instruction at {hex(instruction.address)} does not have an operand at index {index}"
            )

    def get_operand_type(self, addr: int, idx: int) -> OperandType:
        """
        Returns the type of the selected operand.

        The type is returned as an :class:`~OperandType` instance.

        If the address is invalid, this must throw a NotExistError exception.
        If the index is invalid, this must throw a IndexError exception.

        :param int addr: Address of the instruction
        :param int idx: Index of the operand
        :return: Operand type
        """
        operand = self.get_operand(addr, idx)
        return operand.type

    def get_operand_value(self, addr: int, idx: int) -> Optional[OperandValue]:
        """
        The number used in the operand.
        This function returns an immediate number used in the operand
        based on the type of operand.

        :return: OperandValue object
        """
        operand = self.get_operand(addr, idx)
        return operand.value

    @abc.abstractmethod
    def get_data_type(self, name: str) -> DataType:
        """
        Obtain the data type from the given name.
        """

    @abc.abstractmethod
    def get_register(self, name: str) -> Register:
        """
        Obtains a register from given name.

        :param str name: Name of register.
        :return: Register object for given register.
        :raises NotExistError: If register of given name is not a valid processor register.
        """

    @abc.abstractmethod
    def get_segment(self, addr_or_name: Union[int, str]) -> Segment:
        """
        Returns an open memory segment object that contains the given address or has the given name.
        (If providing a name and there are multiple segments with the given name,
        it returns the first one.)

        :param addr_or_name: Either an address contained in the segment or name of the segment.
        :return: Segment object.
        :rtype: Segment
        :raises NotExistError: If a segment doesn't exist for the given input.
        """

    @abc.abstractmethod
    def create_segment(self, name: str, start: int, size: int) -> Segment:
        """
        Creates and returns a memory segment object that starts at given address.

        :param name: Name of segment
        :param start: Start address of segment
        :param size: Size of segment
        :return: Segment object created
        :raises ValueError: If segment couldn't be created.
        """

    @property
    @abc.abstractmethod
    def segments(self) -> Iterable[Segment]:
        """
        Iterates (initialized) segments found in the program.
        """

    @abc.abstractmethod
    def get_string_bytes(self, addr: int, length: int = None, bit_width: int = None) -> bytes:
        """
        Returns the raw bytes for a string at the represented address.
        (This effectively gets bytes until it encounters the null terminator)

        WARNING: This function should return just the raw bytes.
        User is responsible for decoding data as appropriate.

        :param int addr: Start address to pull string data.
        :param int length: Max length of string data.
            (May be omitted to allow disassembler to determine appropriate value.)
        :param int bit_width: Number of bits which represent a code point.
            (May be omitted to allow disassembler to determine appropriate value.)
            (Must be 8, 16, or 32 if provided.)
        :return: Raw bytes containing encoded string.
        """

    @abc.abstractmethod
    def strings(self, min_length=3) -> Iterable[String]:
        """
        Iterates strings found in the disassembly.

        :param min_length: Minimum length of string to have the found string count.

        :yields: String object
        """

    def line_addresses(self, start: int = None, end: int = None, reverse=False) -> Iterable[int]:
        """
        Returns a list of all of the address heads between ``start`` and ``end``.

        The range of address heads must be ``[start, end)``. That is,
        if there is an address head at ``start``, it is included in the list, but if
        an address head is at ``end``, it is not included.

        If there are no address heads in the given range or the range is invalid
        (e.g. ``start >= end``) an empty list must be returned.

        :param int start: Start address (included)
        :param int end: End address (excluded)
        :return: Iterates start addresses.
        """
        for line in self.lines(start=start, end=end, reverse=reverse):
            yield line.address

    def lines(self, start: int = None, end: int = None, reverse=False) -> Iterable[Line]:
        """
        Iterates the Line objects found with the given range of addresses.
        If addresses are not found, the address among the full program is iterated.

        By default we take advantage of the .prev and .next properties of Line
        to implement this functionality. However, this may be overwritten if optimization
        is necessary.

        :param start: Start address (included)
        :param end: End address (excluded)
        :param reverse: Whether to iterate lines in reverse.
        """
        if start is None:
            start = self.min_address if not reverse else self.max_address
        if end is None:
            end = self.max_address if not reverse else self.min_address

        # TODO: Automatically detect reverse if start > end?
        if reverse:
            if end > start:
                raise ValueError(f"Start address {hex(start)} must be greater than end address {hex(end)}")
            line = self.get_line(start)
            while True:
                if line.address <= end:
                    break
                yield line
                line = line.prev
                if not line:
                    break
        else:
            if end < start:
                raise ValueError(f"Start address {hex(start)} must be less than end address {hex(end)}")
            line = self.get_line(start)
            while True:
                if line.address >= end:
                    break
                yield line
                line = line.next
                if not line:
                    break

    def instructions(self, start: int = None, end: int = None, reverse=False) -> Iterable[Instruction]:
        """
        Iterates the Instruction objects found with the given range of addresses.
        If addresses are not found, the address among the full program is iterated.
        """
        for line in self.lines(start=start, end=end, reverse=reverse):
            insn = line.instruction
            if insn:
                yield insn

    @property
    @abc.abstractmethod
    def max_address(self) -> int:
        """
        Maximum address in program.
        """

    @property
    @abc.abstractmethod
    def min_address(self) -> int:
        """
        Minimum address in program.
        """

    @property
    @abc.abstractmethod
    def base_address(self) -> int:
        """
        Image base address.
        """

    def next_line_address(self, addr: int) -> int:
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
        return self.get_line(addr).next.address

    def prev_line_address(self, addr: int) -> int:
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
        return self.get_line(addr).prev.address

    @abc.abstractmethod
    def open_memory(self, start: int, end: int) -> Memory:
        """
        Opens and returns a file-like object backed by the given memory window.

        :param start: Starting address of the memory window.
        :param end: Ending address of the memory window (non-inclusive).
        :return: Memory object.
        """

    @abc.abstractmethod
    def references_from(self, addr: int) -> Iterable[Reference]:
        """
        Iterates cross references from the specified address.

        :param int addr: Address to get references from
        :yield: `Reference` objects.
        """

    @abc.abstractmethod
    def references_to(self, addr: int) -> Iterable[Reference]:
        """
        Iterates cross references to the specified address.

        :param int addr: Address to get references to
        :yield: `Reference` objects.
        """

    @abc.abstractmethod
    def create_reference(self, from_address: int, to_address: int, ref_type: ReferenceType) -> Reference:
        """
        Creates a cross reference.

        :param from_address: source address
        :param to_address: destination address
        :param ref_type: Type of reference
        :return: Reference object created
        :raises ValueError: If cross reference failed to create.
        """

    def get_variable(self, addr: int) -> GlobalVariable:
        """
        Obtains the global variable containing the given address.

        :param int addr: An address contained in the variable.
        :raises NotExistError: If a variable doesn't exist for the given address.
        """

    def set_comment(self, addr: int, comment: Optional[str], comment_type=CommentType.eol):
        """
        Sets comment (of specific type) at line.

        :param addr int: Address of line to set comment.
        :param str comment: comment string to set or None to reset comment.s
        :param comment_type: Type of comment to set (default to end of line comment)
        """
        self.get_line(addr).set_comment(comment, comment_type=comment_type)

    # TODO: Handle duplicate names, by adding a prefix, ala IDA, but do it locally.
    def set_name(self, addr: int, name: Optional[str]):
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
        :param name: The new name of the address or None/"" to reset the name.
        """
        # Set name for either the function or line
        func = None
        try:
            func = self.get_function(addr)
        except NotExistError:
            pass

        if func and func.start == addr:
            func.name = name
        else:
            self.get_line(addr).name = name

    @property
    @abc.abstractmethod
    def imports(self) -> Iterable[Import]:
        """
        The imports within the binary.
        """

    def get_import(self, name: str) -> Import:
        """
        Gets import symbol by name.
        :param name: Name of import function
        :return: Import symbol
        :raises NotExistError: If import by the given name doesn't exist.
        """
        for import_ in self.imports:
            if import_.name == name:
                return import_
        raise NotExistError(f"Import with name '{name}' doesn't exist.")

    @property
    @abc.abstractmethod
    def exports(self) -> Iterable[Export]:
        """
        The exports within the binary.
        """

    def get_export(self, name: str) -> Export:
        """
        Gets export symbol by name.
        :param name: Name of import function
        :return: Export symbol
        :raises NotExistError: If export by the given name doesn't exist.
        """
        for export in self.exports:
            if export.name == name:
                return export
        raise NotExistError(f"Export with name '{name}' doesn't exist.")
