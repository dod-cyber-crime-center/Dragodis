from __future__ import annotations

import logging
import struct
from typing import Optional, TYPE_CHECKING, Any

from dragodis.exceptions import NotExistError
from dragodis.ida.instruction import IDAInstruction
from dragodis.interface import Line, LineType, CommentType

if TYPE_CHECKING:
    from dragodis.ida.flat import IDAFlatAPI


logger = logging.getLogger(__name__)


# TODO: Fixup the exceptions used here. Switch to custom exceptions?


class IDALine(Line):

    def __init__(self, ida: IDAFlatAPI, addr: int):
        super().__init__(ida)
        self._ida = ida
        if addr < 0:
            raise NotExistError(f"Got negative address: {addr}")
        # IDA has no concept of a "line", so we'll keep track of the start address,
        # which IDA refers to as the "head".
        start_addr = self._ida._ida_bytes.get_item_head(addr)
        if start_addr == self._ida._BADADDR:
            raise NotExistError(f"Line at {hex(addr)} does not exist.")
        self._addr = start_addr
        self._name = None

    # TODO: Move these into utility module inside IDA
    def _iter_extra_comments(self, addr: int, start: int):
        end = self._ida._ida_lines.get_first_free_extra_cmtidx(addr, start)
        for idx in range(start, end):
            comment_line = self._ida._ida_lines.get_extra_cmt(addr, idx)
            yield comment_line or ""

    def _set_extra_comments(self, addr: int, start: int, comment: str):
        if not comment:
            self._ida._ida_lines.del_extra_cmt(addr, start)
        else:
            index = 0
            for index, comment_line in enumerate(comment.splitlines()):
                self._ida._ida_lines.update_extra_cmt(addr, start + index, comment_line)
            self._ida._ida_lines.del_extra_cmt(addr, start + (index + 1))

    @property
    def address(self):
        return self._addr

    @property
    def data(self) -> bytes:
        if not self.is_loaded:
            return b""
        # Call flat api to take advantage of memory caching.
        return self._ida.get_bytes(self.address, self.size)

    @data.setter
    def data(self, new_data: bytes):
        if not self.is_loaded:
            return
        type_ = self.type
        self.undefine()
        self._ida._ida_bytes.patch_bytes(self.address, new_data)
        self.type = type_

    def get_comment(self, comment_type=CommentType.eol) -> Optional[str]:
        if comment_type == CommentType.eol:
            return self._ida._ida_bytes.get_cmt(self.address, 0) or None
        elif comment_type == CommentType.repeatable:
            return self._ida._ida_bytes.get_cmt(self.address, 1) or None
        elif comment_type in (CommentType.anterior, CommentType.plate):
            return "\n".join(self._iter_extra_comments(self.address, self._ida._ida_lines.E_PREV)) or None
        elif comment_type == CommentType.posterior:
            return "\n".join(self._iter_extra_comments(self.address, self._ida._ida_lines.E_NEXT)) or None
        else:
            raise ValueError(f"Invalid comment type: {repr(comment_type)}")

    @property
    def name(self) -> Optional[str]:
        if not self._name:
            self._name = self._ida._ida_name.get_name(self.address) or None
        return self._name

    @name.setter
    def name(self, new_name: Optional[str]):
        flags = self._ida._ida_name.SN_NOCHECK
        if new_name:
            # only force if not clearing.
            flags |= self._ida._ida_name.SN_FORCE
        else:
            new_name = ""

        success = self._ida._ida_name.set_name(self.address, new_name, flags)
        if not success:
            raise ValueError(f"Failed to set {hex(self.address)} to {new_name}")
        self._name = None  # clear cache

        # If we reset the name for a string we need to undefine it
        # so IDA gives us the appropriate auto-generated name.
        # Otherwise, a data item original named like "aHello" will be reset to "asc_40C130"
        if not new_name and self.is_string:
            type_ = self.type
            self.undefine()
            self.type = type_

    @property
    def next(self) -> Optional["IDALine"]:
        addr = self._ida._idc.next_head(self.address)
        if addr != self._ida._BADADDR:
            return IDALine(self._ida, addr)

    @property
    def prev(self) -> Optional["IDALine"]:
        addr = self._ida._idc.prev_head(self.address)
        if addr != self._ida._BADADDR:
            return IDALine(self._ida, addr)

    def set_comment(self, comment: Optional[str], comment_type=CommentType.eol):
        # IDA takes an empty string to clear comments
        if not comment:
            comment = ""

        if comment_type == CommentType.eol:
            self._ida._ida_bytes.set_cmt(self.address, comment, 0)
        elif comment_type == CommentType.repeatable:
            self._ida._ida_bytes.set_cmt(self.address, comment, 1)
        elif comment_type in (CommentType.anterior, CommentType.plate):
            self._set_extra_comments(self.address, self._ida._ida_lines.E_PREV, comment)
        elif comment_type == CommentType.posterior:
            self._set_extra_comments(self.address, self._ida._ida_lines.E_NEXT, comment)

    @property
    def size(self) -> int:
        return self._ida._ida_bytes.get_item_size(self.address)

    @property
    def type(self) -> LineType:
        flags = self._ida._ida_bytes.get_flags(self.address)

        if self._ida._ida_bytes.is_code(flags):
            return LineType.code

        elif self._ida._ida_bytes.is_byte(flags):
            return LineType.byte

        elif self._ida._ida_bytes.is_word(flags):
            return LineType.word

        elif self._ida._ida_bytes.is_dword(flags):
            return LineType.dword

        elif self._ida._ida_bytes.is_qword(flags):
            return LineType.qword

        elif self._ida._ida_bytes.is_oword(flags):
            return LineType.oword

        elif self._ida._ida_bytes.is_tbyte(flags):
            return LineType.tbyte

        elif self._ida._ida_bytes.is_float(flags):
            return LineType.float

        elif self._ida._ida_bytes.is_double(flags):
            return LineType.double

        elif self._ida._ida_bytes.is_pack_real(flags):
            return LineType.pack_real

        elif self._ida._ida_bytes.is_strlit(flags):
            str_type = self._ida._ida_nalt.get_str_type(self.address)
            str_type &= self._ida._ida_nalt.STRWIDTH_MASK
            if str_type == self._ida._ida_nalt.STRTYPE_C:
                return LineType.string
            elif str_type == self._ida._ida_nalt.STRTYPE_C_16:
                return LineType.string16
            elif str_type == self._ida._ida_nalt.STRTYPE_C_32:
                return LineType.string32
            else:
                RuntimeError(f"String type at {hex(self.address)} not currently supported.")

        elif self._ida._ida_bytes.is_struct(flags):
            return LineType.struct

        elif self._ida._ida_bytes.is_align(flags):
            return LineType.align

        elif self._ida._ida_bytes.is_tail(flags):
            return LineType.tail

        elif self._ida._ida_bytes.is_unknown(flags):
            if self._ida._ida_bytes.is_loaded(self.address):
                return LineType.undefined
            else:
                return LineType.unloaded

        else:
            raise RuntimeError(f"Unexpected line type at {hex(self.address)}")

    @type.setter
    def type(self, new_type: LineType):
        if new_type not in LineType:
            raise ValueError(f"Invalid line type: {new_type}")

        type = self.type
        if type == new_type:
            return  # No change necessary

        # First undefine line, otherwise IDA will fail to change the type in many cases.
        self.undefine()

        # Create new data type at address.
        # NOTE: Using idc over ida_bytes so we don't have to bother with size.
        success = False
        if new_type == LineType.code:
            raise NotImplementedError("Setting a line to code is not currently supported.")

        elif new_type == LineType.byte:
            success = self._ida._idc.create_byte(self.address)

        elif new_type == LineType.word:
            success = self._ida._idc.create_word(self.address)

        elif new_type == LineType.dword:
            success = self._ida._idc.create_dword(self.address)

        elif new_type == LineType.qword:
            success = self._ida._idc.create_qword(self.address)

        elif new_type == LineType.oword:
            success = self._ida._idc.create_oword(self.address)

        elif new_type == LineType.tbyte:
            success = self._ida._idc.create_tbyte(self.address)

        elif new_type == LineType.float:
            success = self._ida._idc.create_float(self.address)

        elif new_type == LineType.double:
            success = self._ida._idc.create_double(self.address)

        elif new_type == LineType.pack_real:
            success = self._ida._idc.create_pack_real(self.address)

        elif new_type == LineType.string:
            success = self._ida._ida_bytes.create_strlit(self.address, 0, self._ida._ida_nalt.STRTYPE_C)

        elif new_type == LineType.string16:
            success = self._ida._ida_bytes.create_strlit(self.address, 0, self._ida._ida_nalt.STRTYPE_C_16)

        elif new_type == LineType.string32:
            success = self._ida._ida_bytes.create_strlit(self.address, 0, self._ida._ida_nalt.STRTYPE_C_32)

        elif new_type == LineType.struct:
            # TODO: Create a special "Structure" class that helps interfacing with structs
            # success = self._ida._idc.create_struct(self.addr, self.size, "TODO")
            raise NotImplementedError("Setting a line to a struct is not currently supported.")

        elif new_type == LineType.align:
            # success = self._ida._idc.create_align(self.addr, 0, 0)
            raise NotImplementedError("Setting a line to an alignment is not currently supported.")

        elif new_type == LineType.tail:
            raise NotImplementedError("Setting a line to a tail is not currently supported.")

        elif new_type == LineType.undefined:
            success = True  # Already undefined, nothing more to do.

        elif new_type == LineType.unloaded:
            # TODO: Should we ever support this?
            raise NotImplementedError("Setting a line to unloaded is not currently supported.")

        if not success:
            raise TypeError(f"Failed to set new type {repr(new_type)} at {hex(self.address)}")

    def undefine(self):
        if self.type in [LineType.undefined, LineType.unloaded]:
            return
        # TODO: kordesii's EncryptedString called with like so. Should we be doing that here?
        #   idc.del_items(self.start_ea, idc.DELIT_SIMPLE, len(self.decoded_data))
        success = self._ida._ida_bytes.del_items(self.address)
        if not success:
            raise TypeError(f"Failed to undefine data at {hex(self.address)}")

    @property
    def value(self) -> Any:
        type = self.type

        if type == LineType.code:
            return IDAInstruction(self._ida, self.address)

        elif type == LineType.byte:
            return self._ida._ida_bytes.get_wide_byte(self.address)

        elif type == LineType.word:
            return self._ida._ida_bytes.get_wide_word(self.address)

        elif type == LineType.dword:
            return self._ida._ida_bytes.get_wide_dword(self.address)

        elif type == LineType.qword:
            return self._ida._ida_bytes.get_qword(self.address)

        elif type == LineType.oword:
            raise NotImplementedError(f"Getting oword value is not currently supported.")

        elif type == LineType.tbyte:
            raise NotImplementedError(f"Getting tbyte value is not currently supported.")

        elif type == LineType.float:
            return self._ida._idc.GetFloat(self.address)

        elif type == LineType.double:
            return self._ida._idc.GetDouble(self.address)

        elif type == LineType.pack_real:
            raise NotImplementedError(f"Getting pack_real value is not currently supported.")

        elif type == LineType.string:
            return self.data.decode("utf-8").rstrip("\x00")

        elif type == LineType.string16:
            return self.data.decode("utf-16-le").rstrip("\x00")

        elif type == LineType.string32:
            return self.data.decode("utf-32-le").rstrip("\x00")

        elif type == LineType.struct:
            raise NotImplementedError(f"Getting struct value is not currently supported.")

        elif type == LineType.align:
            return self.data

        elif type == LineType.tail:
            raise NotImplementedError(f"Getting tail value is not currently supported.")

        elif type == LineType.undefined:
            return self._ida._ida_bytes.get_wide_byte(self.address)

        elif type == LineType.unloaded:
            return None

    @value.setter
    def value(self, new_value: Any):
        matched_types = LineType.match_type(new_value)
        if not matched_types:
            raise TypeError(f"Unsupported value type: {type(new_value)}")

        type_ = self.type

        # First see if setting this new value would required changing the line type.
        if type_ not in matched_types:
            # Use the first entry of matched types to be the type we change it to.
            # Type must be changed after we patch to avoid the type change failing
            # due to bytes originally set at location.
            # (e.g, IDA will fail to change the type to string if original bytes are printable)
            new_type = matched_types[0]
            logger.debug(f"Changing line type from {type_} to {new_type}")
            type_ = new_type

        # TODO: Should we undefine before we patch?

        # Set the value based on line type.
        success = False
        if type_ == LineType.code:
            # TODO: If number of bytes that make up the instruction is lower, make sure to
            #   add nops?
            # self._ida._idc.create_insn(new_value._insn_t)
            raise NotImplementedError(f"Setting instruction value is not currently supported.")

        elif type_ == LineType.byte:
            if isinstance(new_value, bytes):
                new_value = new_value[0]
            success = self._ida._ida_bytes.patch_byte(self.address, new_value)

        elif type_ == LineType.word:
            success = self._ida._ida_bytes.patch_word(self.address, new_value)

        elif type_ == LineType.dword:
            success = self._ida._ida_bytes.patch_dword(self.address, new_value)

        elif type_ == LineType.qword:
            success = self._ida._ida_bytes.patch_qword(self.address, new_value)

        elif type_ == LineType.oword:
            raise NotImplementedError(f"Setting oword value is not currently supported.")

        elif type_ == LineType.tbyte:
            raise NotImplementedError(f"Setting tbyte value is not currently supported.")

        elif type_ == LineType.float:
            new_value_dword = struct.unpack("I", struct.pack("f", new_value))[0]
            success = self._ida._ida_bytes.patch_dword(self.address, new_value_dword)

        elif type_ == LineType.double:
            new_value_qword = struct.unpack("Q", struct.pack("d", new_value))[0]
            success = self._ida._ida_bytes.patch_qword(self.address, new_value_qword)

        elif type_ == LineType.pack_real:
            raise NotImplementedError(f"Setting pack_real value is not currently supported.")

        elif type_ in (LineType.string, LineType.string16, LineType.string32):
            new_value += "\x00"
            encoding = {
                LineType.string: "utf-8",
                LineType.string16: "utf-16-le",
                LineType.string32: "utf-32-le",
            }[type_]
            new_value = new_value.encode(encoding)
            # Ensure there is enough space to fit the new value.
            if len(new_value) > (self.next.address - self.address):
                raise ValueError(f"Encoded string too large to fit on line.")
            # Fill with zero bytes.
            new_value += b"\x00" * (len(self) - len(new_value))
            # For strings, we are going to undefine the value first so ida appropriately
            # resets the item.
            self.undefine()
            self._ida._ida_bytes.patch_bytes(self.address, new_value)
            success = True

        elif type_ == LineType.struct:
            raise NotImplementedError(f"Setting struct value is not currently supported.")

        elif type_ == LineType.align:
            self._ida._ida_bytes.patch_bytes(self.address, new_value)
            success = True

        elif type_ == LineType.tail:
            raise NotImplementedError(f"Getting tail value is not currently supported.")

        elif type_ == LineType.undefined:
            if isinstance(new_value, int):
                new_value = bytes([new_value])
            self._ida._ida_bytes.patch_bytes(self.address, new_value)
            success = True

        elif type_ == LineType.unloaded:
            return  # ignore attempts to set a value to unloaded.

        if success:
            # Now set the new type. (Does nothing if already the right type.)
            self.type = type_
        else:
            raise TypeError(f"Failed to set value {repr(new_value)} at {hex(self.address)}")
