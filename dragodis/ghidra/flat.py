
from __future__ import annotations

from functools import cached_property

from typing import Iterable, Union, List, TYPE_CHECKING

from dragodis.interface.flat import FlatAPI
from dragodis.exceptions import NotExistError
from dragodis import utils
from .data_type import GhidraDataType
from .disassembler import GhidraDisassembler, GhidraLocalDisassembler, GhidraRemoteDisassembler
from .function import GhidraFunction
from .function_signature import GhidraFunctionSignature
from .line import GhidraLine
from .memory import GhidraMemory
from .operand_value import GhidraRegister
from .reference import GhidraReference
from .segment import GhidraSegment
from .symbol import GhidraImport, GhidraExport
from .variable import GhidraGlobalVariable

if TYPE_CHECKING:
    from ghidra.program.model.address import Address
    import ghidra.program.model.listing


class Ghidra(FlatAPI, GhidraDisassembler):

    def _to_addr(self, addr: int) -> "Address":
        """
        Internal function used to generate Ghidra Address object from integer.
        :raises NotExistError: If overflow error occurs.
        """
        try:
            address = self._flatapi.toAddr(hex(addr))
            if address is not None:
                return address
            raise NotExistError(f"Invalid address {hex(addr)}")
        except OverflowError:
            raise NotExistError(f"Invalid address {hex(addr)}. Expect 32 bit integer, got {addr.bit_length()}")

    @property
    def bit_size(self) -> int:
        return self._program.getDefaultPointerSize() * 8

    @property
    def is_big_endian(self) -> bool:
        return self._program.getLanguage().isBigEndian()

    def get_virtual_address(self, file_offset: int) -> int:
        memory = self._program.getMemory()
        addresses = memory.locateAddressesForFileOffset(file_offset)
        if not addresses:
            raise NotExistError(f"Cannot get virtual address for file offset: {hex(file_offset)}")
        for address in addresses:
            return address.getOffset()

    def get_file_offset(self, addr: int) -> int:
        memory = self._program.getMemory()
        info = memory.getAddressSourceInfo(self._to_addr(addr))
        if not info or info.getFileOffset() == -1:
            raise NotExistError(f"Cannot get file offset for address: {hex(addr)}")
        return info.getFileOffset()

    def functions(self, start=None, end=None) -> Iterable[GhidraFunction]:
        if start is None and end is None:
            iterator = self._listing.getFunctions(True)
        elif start is not None and end is None:
            iterator = self._listing.getFunctions(self._to_addr(start), True)
        elif start is None and end is not None:
            iterator = self._listing.getFunctions(self._to_addr(end), False)
        else:
            from ghidra.program.model.address import AddressSet
            address_set = AddressSet(
                self._to_addr(start),
                self._to_addr(end),
            )
            iterator = self._listing.getFunctions(address_set, True)

        for function in iterator:
            yield GhidraFunction(self, function)

    def get_byte(self, addr: int) -> int:
        from ghidra.program.model.mem import MemoryAccessException
        try:
            # Mask necessary because jpype bytes are signed.
            return self._flatapi.getByte(self._to_addr(addr)) & 0xff
        except MemoryAccessException:
            raise NotExistError(f"Cannot get byte at {hex(addr)}")

    def get_bytes(self, addr: int, length: int, default: int = None) -> bytes:
        from ghidra.program.model.mem import MemoryAccessException
        if default is None:
            try:
                return memoryview(self._flatapi.getBytes(self._to_addr(addr), length)).tobytes()
            except MemoryAccessException:
                raise NotExistError(f"Cannot get bytes at {hex(addr)}")
        else:
            data = bytearray()
            for _addr in range(addr, addr + length):
                try:
                    data.append(self._flatapi.getByte(self._to_addr(_addr)) & 0xFF)
                except MemoryAccessException:
                    data.append(default)
            return bytes(data)

    def find_bytes(self, pattern: bytes, start: int = None, reverse=False) -> int:
        if start is not None:
            start = self._to_addr(start)
        elif reverse:
            start = self._program.getMaxAddress()
        else:
            start = self._program.getMinAddress()
        memory = self._program.getMemory()
        found = memory.findBytes(start, pattern, None, not reverse, self._monitor)
        if found is None:
            return -1
        else:
            return found.getOffset()

    def get_data_type(self, name: str) -> GhidraDataType:
        from ghidra.util.data import DataTypeParser
        from ghidra.program.model.data import InvalidDataTypeException
        # Must use .valueOf() because jpype doesn't handle enums well.
        parser = DataTypeParser(None, DataTypeParser.AllowedDataTypes.valueOf("ALL"))
        try:
            data_type = parser.parse(name)
        except InvalidDataTypeException as e:
            raise NotExistError(e)
        return GhidraDataType(data_type)

    def get_function(self, addr: int) -> GhidraFunction:
        function = self._flatapi.getFunctionContaining(self._to_addr(addr))
        if not function:
            raise NotExistError(f"Function containing {hex(addr)} does not exist.")
        return GhidraFunction(self, function)

    def get_function_signature(self, addr: int) -> GhidraFunctionSignature:
        address = self._to_addr(addr)
        function = self._flatapi.getFunctionAt(address)
        # If we don't find a function, address might be pointing to an external function pointer. (ie. import)
        if not function:
            for ref in self._flatapi.getReferencesFrom(address):
                if ref.isExternalReference():
                    function = ref.getExternalLocation().getFunction()
                    break
        if not function:
            raise NotExistError(f"Function signature at {hex(addr)} does not exist.")
        return GhidraFunctionSignature(self, function)

    def get_line(self, addr: int) -> GhidraLine:
        code_unit = self._listing.getCodeUnitContaining(self._to_addr(addr))
        return GhidraLine(self, code_unit)

    def get_register(self, name: str) -> GhidraRegister:
        reg = self._program.getRegister(name)
        if not reg:
            raise NotExistError(f"Invalid register name: {name}")
        return GhidraRegister(reg)

    # TODO: Be a little more lax here?
    def get_string_bytes(self, addr: int, length: int = None, bit_width: int = None) -> bytes:
        addr_obj = self._to_addr(addr)
        # First check if a string or other data type is set here.
        string_obj = self._flatapi.getDataAt(addr_obj)
        if string_obj:
            if not string_obj.hasStringValue():
                # TODO: Create a different custom exception here?
                raise NotExistError(
                    f"Data type conflict at {hex(addr)}. Expected 'string', got '{string_obj.getDataType()}'")
            return bytes(string_obj.getBytes()).rstrip(b"\x00")

        from ghidra.app.util.bin import MemoryByteProvider, BinaryReader

        mem = self._program.getMemory()
        provider = MemoryByteProvider(mem, addr_obj)
        reader = BinaryReader(provider, not mem.isBigEndian())
        if bit_width is None:
            bit_width = 8  # TODO: Determine how to auto detect string type.

        try:
            if bit_width == 8:
                return reader.readNextAsciiString().encode('ascii')
            elif bit_width == 16:
                return reader.readNextUnicodeString().encode('utf-16')
            else:
                raise ValueError(f"Invalid bit width: {bit_width}")
        except Exception as e:
            raise RuntimeError(f"Failed to create a string at {hex(addr)} with error: {e}")

    def get_segment(self, addr_or_name: Union[int, str]) -> GhidraSegment:
        memory = self._program.getMemory()
        if isinstance(addr_or_name, str):
            name = addr_or_name
            memory_block = memory.getBlock(name)
            if not memory_block:
                raise NotExistError(f"Could not find segment with name: {name}")
        elif isinstance(addr_or_name, int):
            addr = addr_or_name
            memory_block = memory.getBlock(self._to_addr(addr))
            if not memory_block:
                raise NotExistError(f"Could not find segment containing address 0x{addr:08x}")
        else:
            raise ValueError(f"Invalid input: {addr_or_name!r}")

        if not memory_block.isInitialized():
            raise NotExistError(f"Memory block at {memory_block.getStart()} is not initialized.")

        return GhidraSegment(self, memory_block)

    @property
    def max_address(self) -> int:
        return self._program.getMaxAddress().getOffset()

    @property
    def min_address(self) -> int:
        return self._program.getMinAddress().getOffset()

    def open_memory(self, start: int, end: int) -> GhidraMemory:
        return GhidraMemory(self, start, end)

    @property
    def processor_name(self) -> str:
        return str(self._program.getLanguage().getProcessor())

    def references_from(self, addr: int) -> Iterable[GhidraReference]:
        # TODO: cache chunks
        for reference in self._flatapi.getReferencesFrom(self._to_addr(addr)):
            # For now, we are only going to consider memory references.
            # TODO: Expand this to allow things like stack references after implementing
            #   the equivalent in IDA.
            if reference.isMemoryReference():
                yield GhidraReference(self, reference)

    def references_to(self, addr: int) -> Iterable[GhidraReference]:
        # TODO: cache chunks
        for reference in self._flatapi.getReferencesTo(self._to_addr(addr)):
            if reference.isMemoryReference():
                yield GhidraReference(self, reference)

    def get_variable(self, addr: int) -> GhidraGlobalVariable:
        data = self._flatapi.getDataContaining(self._to_addr(addr))
        if not data:
            raise NotExistError(f"Variable doesn't exist at {hex(addr)}")
        return GhidraGlobalVariable(self, data)

    @property
    def segments(self) -> Iterable[GhidraSegment]:
        memory = self._program.getMemory()
        for memory_block in memory.getBlocks():
            yield GhidraSegment(self, memory_block)

    @property
    def imports(self) -> Iterable[GhidraImport]:
        for symbol in self._program.getSymbolTable().getExternalSymbols():
            yield GhidraImport(self, symbol)

    @property
    def exports(self) -> Iterable[GhidraExport]:
        symbol_table = self._program.getSymbolTable()
        for address in symbol_table.getExternalEntryPointIterator():
            symbol = symbol_table.getPrimarySymbol(address)
            yield GhidraExport(self, symbol)

    @cached_property
    def _static_functions(self) -> List[ghidra.program.model.listing.Function]:
        """
        Obtains the static functions defined by the FID service.
        """
        from ghidra.feature.fid.service import FidService

        fid = FidService()
        language = self._program.getLanguage()
        if not fid.canProcess(language):
            return []

        service = fid.openFidQueryService(language, False)
        try:
            results = fid.processProgram(self._program, service, fid.getDefaultScoreThreshold(), self._monitor)
            return [result.function for result in results]
        finally:
            service.close()


# Set proper Disassembler class based on whether we are inside or outside Ghidra.
if utils.in_ghidra():
    class Ghidra(Ghidra, GhidraLocalDisassembler):
        ...
else:
    class Ghidra(Ghidra, GhidraRemoteDisassembler):
        ...

