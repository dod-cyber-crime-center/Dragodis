
from __future__ import annotations

from functools import lru_cache

from .. import utils

from typing import Iterable, Union, Optional

from dragodis.interface.flat import FlatAPI
from dragodis.exceptions import NotExistError
from .data_type import IDADataType
from .disassembler import IDADisassembler, IDARemoteDisassembler, IDALocalDisassembler
from .function_signature import IDAFunctionSignature
from .line import IDALine
from .memory import IDAMemory, CachedMemory
from .function import IDAFunction
from .operand_value import IDARegister
from .reference import IDAReference
from .segment import IDASegment
from .string import IDAString
from .symbol import IDAImport, IDAExport
from .variable import IDAGlobalVariable
from ..interface import ReferenceType


cache = lru_cache(maxsize=1024)


class IDAFlatAPI(FlatAPI, IDADisassembler):

    @property
    def _cached_memory(self):
        return CachedMemory(self)

    def _bytes_loaded(self, addr: int, num_bytes: int) -> bool:
        return self._ida_helpers.is_loaded(addr, num_bytes)

    @property
    def processor_name(self) -> str:
        proc = self._ida_ida.inf_get_procname()
        # Switching "metapc" to "x86" to match Ghidra.
        if proc == "metapc":
            return "x86"
        return proc

    @property
    def compiler_name(self) -> str:
        cc_id = self._ida_ida.inf_get_cc_id()
        return self._ida_typeinf.get_compiler_name(cc_id)

    @property
    def bit_size(self) -> int:
        # IDA 7.6 adds ida_ida.inf_get_app_bitness()
        if self._idaapi.IDA_SDK_VERSION >= 760:
            return self._ida_ida.inf_get_app_bitness()

        if self._ida_ida.inf_is_64bit():
            return 64
        elif self._ida_ida.inf_is_32bit():
            return 32
        else:
            return 16

    @property
    def is_big_endian(self) -> bool:
        return self._ida_ida.inf_is_be()

    @property
    def entry_point(self) -> Optional[int]:
        address = self._ida_ida.inf_get_start_ip()
        if address != self._BADADDR:
            return address

    @cache
    def get_virtual_address(self, file_offset: int) -> int:
        addr = self._ida_loader.get_fileregion_ea(file_offset)
        if addr == self._idc.BADADDR:
            raise NotExistError(f"Cannot get linear address for file offset: {hex(file_offset)}")
        return addr

    @cache
    def get_file_offset(self, addr: int) -> int:
        file_offset = self._ida_loader.get_fileregion_offset(addr)
        if file_offset == -1:
            raise NotExistError(f"Cannot get file offset for address: {hex(addr)}")
        return file_offset

    def functions(self, start=None, end=None) -> Iterable[IDAFunction]:
        # TODO: use remove_eval to optimize this?
        #   - Create mechanism to chunk iterators?
        #   - Reimplement idautils.Functions here?
        for ea in self._idautils.Functions(start=start, end=end):
            # IDA will include the function if started in the middle of it.
            # Ignore this function to stay consistent with Ghidra.
            if start and ea < start:
                continue
            yield self.get_function(ea)

    # TODO: make a Memory object?

    def get_byte(self, addr: int) -> int:
        if not self._bytes_loaded(addr, 1):
            raise NotExistError(f"Cannot get byte at {hex(addr)}")
        return self._ida_bytes.get_wide_byte(addr)

    def get_bytes(self, addr: int, length: int, default: int = None) -> bytes:
        if default is None and not self._ida_helpers.is_loaded(addr, length):
            raise NotExistError(
                f"Unable to obtain {length} bytes from 0x{addr:08X}: "
                f"Address range not fully loaded."
            )
        return self._ida_helpers.get_bytes(addr, length, default=default or 0)
        # FIXME: Disabling use of cached memory since we aren't invalidating caches properly.
        # # If all bytes aren't available but a default was provided, get bytes
        # # one at a time, replacing invalid bytes with the default.
        # if default:
        #     default = bytes([default])
        # return self._cached_memory.get(addr, length, fill_pattern=default)

    def find_bytes(self, pattern: bytes, start: int = None, reverse=False) -> int:
        # Convert bytes pattern into hex separated by space format that IDA likes.
        pattern = " ".join(format(byte, "02X") for byte in pattern)
        if reverse:
            flag = self._ida_search.SEARCH_UP
            if start is None:
                start = self.max_address
            end = self.min_address
        else:
            flag = self._ida_search.SEARCH_DOWN
            if start is None:
                start = self.min_address
            end = self.max_address

        found = self._ida_search.find_binary(start, end, pattern, 16, flag)
        if found == self._BADADDR:
            return -1
        else:
            return found

    def get_word(self, addr: int) -> int:
        if not self._bytes_loaded(addr, 2):
            raise NotExistError(f"Cannot get word at {hex(addr)}")
        return self._ida_bytes.get_wide_word(addr)

    def get_dword(self, addr: int) -> int:
        if not self._bytes_loaded(addr, 4):
            raise NotExistError(f"Cannot get dword at {hex(addr)}")
        return self._ida_bytes.get_wide_dword(addr)

    def get_qword(self, addr: int) -> int:
        if not self._bytes_loaded(addr, 8):
            raise NotExistError(f"Cannot get qword at {hex(addr)}")
        return self._ida_bytes.get_qword(addr)

    def get_function(self, addr: int) -> IDAFunction:
        func_t = self._ida_funcs.get_func(addr)
        if not func_t:
            raise NotExistError(f"Function does not exist at {hex(addr)}")
        return IDAFunction(self, func_t)

    def get_function_by_name(self, name: str, ignore_underscore: bool = True) -> IDAFunction:
        # Using ida_helpers instead of default implementation to improve performance.
        func_t = self._ida_helpers.get_function_by_name(name, ignore_underscore=ignore_underscore)
        if func_t is None:
            raise NotExistError(f"Unable to find function with name: {name}")
        return IDAFunction(self, func_t)

    # TODO: Add support for providing an operand to help get a better function signature type.
    @cache
    def get_function_signature(self, addr: int) -> IDAFunctionSignature:
        # Constructor will raise a NotExistError if we can't make a function signature.
        return IDAFunctionSignature(self, addr)

    def get_line(self, addr: int) -> IDALine:
        return IDALine(self, addr)

    def get_register(self, name: str) -> IDARegister:
        reg_info = self._ida_idp.reg_info_t()
        success = self._ida_idp.parse_reg_name(reg_info, name)
        if not success:
            raise NotExistError(f"Invalid register name: {name}")
        return IDARegister(self, reg_info.reg, reg_info.size)

    @cache
    def get_segment(self, addr_or_name: Union[int, str]) -> IDASegment:
        if isinstance(addr_or_name, str):
            name = addr_or_name
            segment_t = self._ida_segment.get_segm_by_name(name)
            if not segment_t:
                raise NotExistError(f"Could not find segment with name: {name}")
        elif isinstance(addr_or_name, int):
            addr = addr_or_name
            segment_t = self._ida_segment.getseg(addr)
            if not segment_t:
                raise NotExistError(f"Could not find segment containing address: 0x{addr:08x}")
        else:
            raise ValueError(f"Invalid input: {addr_or_name!r}")

        return IDASegment(self, segment_t)

    def create_segment(self, name: str, start: int, size: int) -> IDASegment:
        # TODO: Support other segment class types.
        success = self._ida_segment.add_segm(0, start, start + size, name, "XTRN")
        if not success:
            raise ValueError(f"Unable to create segment at 0x{start:08x}")
        return self.get_segment(start)

    @property
    def segments(self) -> Iterable[IDASegment]:
        # Taken from idautils.Segments()
        for n in range(self._ida_segment.get_segm_qty()):
            seg = self._ida_segment.getnseg(n)
            if seg:
                yield IDASegment(self, seg)

    def get_string_bytes(self, addr: int, length: int = None, bit_width: int = None) -> bytes:
        if bit_width is None:
            str_type = self._idc.get_str_type(addr)
        elif bit_width == 8:
            str_type = self._ida_nalt.STRTYPE_C
        elif bit_width == 16:
            str_type = self._ida_nalt.STRTYPE_C_16
        elif bit_width == 32:
            str_type = self._ida_nalt.STRTYPE_C_32
        else:
            raise ValueError(f"Invalid bit width: {bit_width}")

        if length is None:
            length = self._ida_bytes.get_max_strlit_length(
                addr, str_type,
                self._ida_bytes.ALOPT_IGNCLT | self._ida_bytes.ALOPT_IGNPRINT | self._ida_bytes.ALOPT_MAX4K
            )

        return self._ida_bytes.get_strlit_contents(addr, length, str_type)

    def strings(self, min_length=3) -> Iterable[IDAString]:
        sc = self._idautils.Strings()
        sc.setup(
            strtypes=[
                self._ida_nalt.STRTYPE_C,
                self._ida_nalt.STRTYPE_C_16,
                self._ida_nalt.STRTYPE_C_32,
                self._ida_nalt.STRTYPE_PASCAL,
                self._ida_nalt.STRTYPE_PASCAL_16,
                self._ida_nalt.STRTYPE_LEN2,
                self._ida_nalt.STRTYPE_LEN2_16,
                self._ida_nalt.STRTYPE_LEN4,
                self._ida_nalt.STRTYPE_LEN4_16,
            ],
            minlen=min_length,
        )
        for string in sc:
            yield IDAString(self, string)

    def get_data_type(self, name: str) -> IDADataType:
        is_ptr = name.endswith("*")
        name = name.strip(" *")

        # Name has to be uppercase for get_named_type() to work.
        name = name.upper()

        # Create new tinfo object of type.
        tif = self._ida_typeinf.tinfo_t()
        success = tif.get_named_type(self._ida_typeinf.get_idati(), name)
        if not success:
            raise NotExistError(f"Invalid data type: {name}")

        # If a pointer, create another tinfo object that is the pointer of the first.
        if is_ptr:
            tif2 = self._ida_typeinf.tinfo_t()
            tif2.create_ptr(tif)
            tif = tif2

        return IDADataType(self, tif)

    @property
    def max_address(self) -> int:
        return self._ida_ida.inf_get_max_ea()

    @property
    def min_address(self) -> int:
        return self._ida_ida.inf_get_min_ea()

    @property
    def base_address(self) -> int:
        return self._ida_nalt.get_imagebase()

    def open_memory(self, start: int, end: int) -> IDAMemory:
        return IDAMemory(self, start, end)

    def references_from(self, addr: int) -> Iterable[IDAReference]:
        # TODO: Cache chunks
        for xref in self._idautils.XrefsFrom(addr):
            reference = IDAReference(self, xref)
            # Ignore "ordinary flow" references, since that's just a reference to the next
            # instruction, which Ghidra doesn't do.
            if reference.type == ReferenceType.ordinary_flow:
                continue
            yield reference

    def references_to(self, addr: int) -> Iterable[IDAReference]:
        # TODO: Cache chunks
        for xref in self._idautils.XrefsTo(addr):
            yield IDAReference(self, xref)

    def create_reference(self, from_address: int, to_address: int, ref_type: ReferenceType) -> IDAReference:
        ref_type = IDAReference._type_map_inv[ref_type]
        code = False
        if ref_type in range(1, 6):  # data reference
            success = self._ida_xref.add_dref(from_address, to_address, ref_type)
        elif ref_type in range(16, 22):  # code reference
            code = True
            success = self._ida_xref.add_cref(from_address, to_address, ref_type)
        else:
            raise ValueError(f"Unsupported reference type: {ref_type}")
        if not success:
            raise ValueError(f"Unable to create reference: 0x{from_address:08x} -> 0x{to_address:08x}")

        # IDA's xrefblt_t is actually an iterator which holds the attributes of the "current" reference
        # being iterated.
        # Copying the work done in xrefblt_t.refs_from()/refs_to()
        xref = self._ida_xref.xrefblk_t()
        xref.frm = from_address
        xref.to = to_address
        xref.type = ref_type
        xref.iscode = code
        xref.user = ref_type == 20
        reference = IDAReference(self, xref)

        # If reference is a new code call, tell analyzer to apply the callee's type to calling point.
        if reference.type == ReferenceType.code_call:
            self._ida_auto.auto_apply_type(reference.from_address, reference.to_address)

        return reference

    def get_variable(self, addr: int) -> IDAGlobalVariable:
        start_address = self._ida_bytes.get_item_head(addr)
        # Don't count code as "variables". Otherwise we get all the
        # loop labels as variables.
        flags = self._ida_bytes.get_flags(addr)
        is_code = self._ida_bytes.is_code(flags)
        # Only count as variable if item has a name.
        if not is_code and self._ida_name.get_name(start_address):
            return IDAGlobalVariable(self, start_address)
        else:
            raise NotExistError(f"Variable doesn't exist at {hex(addr)}")

    @property
    def imports(self) -> Iterable[IDAImport]:
        for address, thunk_address, name, namespace in self._ida_helpers.iter_imports():
            yield IDAImport(self, address, thunk_address, name, namespace)

    def get_import(self, name: str) -> IDAImport:
        # Using ida_helpers instead of default implementation to improve performance.
        ret = self._ida_helpers.get_import(name)
        if ret is None:
            raise NotExistError(f"Import with name '{name}' doesn't exist.")
        return IDAImport(self, *ret)

    @property
    def exports(self) -> Iterable[IDAExport]:
        ida_entry = self._ida_entry
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            address = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            yield IDAExport(self, address, name)


class IDALocal(IDAFlatAPI, IDALocalDisassembler):
    ...


class IDARemote(IDAFlatAPI, IDARemoteDisassembler):
    ...
