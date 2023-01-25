
from __future__ import annotations

import array
import logging
from typing import Optional, TYPE_CHECKING, Any, Union

from jpype.types import *

from dragodis.exceptions import NotExistError
from dragodis.ghidra.instruction import GhidraInstruction
from dragodis.interface import Line, LineType, CommentType

# Used for typing.
if TYPE_CHECKING:
    from dragodis.ghidra.flat import GhidraFlatAPI
    import ghidra
    # A "CodeUnit" that line takes in is a subclass of CodeUnit.
    CodeUnit = Union[
        ghidra.program.model.listing.CodeUnit,
        ghidra.program.model.listing.Instruction,
        ghidra.program.model.listing.Data,
    ]

logger = logging.getLogger(__name__)


class GhidraLine(Line):

    _comment_type_map = {
        CommentType.eol: 0,          # EOL_COMMENT
        CommentType.anterior: 1,     # PRE_COMMENT
        CommentType.posterior: 2,    # POST_COMMENT
        CommentType.plate: 3,        # PLATE_COMMENT
        CommentType.repeatable: 4,   # REPEATABLE_COMMENT
    }

    # Maps Ghidra DataType to LineType
    _data_type_map = {
        "byte": LineType.byte,
        "word": LineType.word,
        "short": LineType.word,
        "dword": LineType.dword,
        "int": LineType.dword,
        "qword": LineType.qword,
        "int16": LineType.oword,
        "float": LineType.float,
        "float4": LineType.float,
        "double": LineType.double,
        # TODO: Support pointer types?
        #   (Also, this could be qword if 64bit)
        "pointer": LineType.dword,
        "string": LineType.string,
        "string-utf8": LineType.string,
        "TerminatedCString": LineType.string,
        "unicode": LineType.string16,
        "TerminatedUnicode": LineType.string16,
        "unicode32": LineType.string32,
        "TerminatedUnicode32": LineType.string32,
        "Alignment": LineType.align,
        # TODO: struct
    }
    # Inverse _data_type_map with most recent item as value for many-to-one scenerio.
    # (We can do this because Python 3 dictionaries are ordered!)
    _data_type_map_inv = {}
    for k, v in _data_type_map.items():
        if v not in _data_type_map_inv:
            _data_type_map_inv[v] = k

    def __init__(self, api: GhidraFlatAPI, code_unit: "CodeUnit"):
        super().__init__(api)
        self._ghidra = api
        self._code_unit = code_unit

    @property
    def _addr_obj(self) -> "ghidra.program.model.address.Address":
        return self._code_unit.getAddress()

    @property
    def _next_defined(self) -> "GhidraLine":
        """
        Gets the next defined line. (helps to simulate IDA's next_head())
        """
        line = self.next
        while line.type == LineType.undefined:
            line = line.next
        return line

    @property
    def address(self) -> int:
        return self._addr_obj.getOffset()

    @property
    def data(self) -> bytes:
        # NOTE: Need to cast returned array.array from Ghidra, so we can
        # get a Python 3 version of array.array that has the tobytes() function.
        # TODO: Undo this when we use Jpype?
        if not self.is_loaded:
            return b""
        else:
            return array.array("b", self._code_unit.getBytes()).tobytes()

    @data.setter
    def data(self, new_data: bytes):
        if not self.is_loaded:
            return
        type_ = self.type
        self.undefine()
        self._ghidra._flatapi.setBytes(self._addr_obj, new_data)
        self.type = type_

    def get_comment(self, comment_type=CommentType.eol) -> Optional[str]:
        return self._code_unit.getComment(self._comment_type_map[comment_type])

    @property
    def name(self) -> Optional[str]:
        # NOTE: getLabel() is a shortcut for getPrimarySymbol().getName()
        return self._code_unit.getLabel()

    @name.setter
    def name(self, new_name: str):
        # Sanitize name.
        if new_name:
            new_name = new_name.replace(" ", "")

        # First get the label at the address (if it exists), then we need to either
        # modify/delete the existing label, or create a new label.
        # If we attempt to just call createLabel() Ghidra will stack the label along with
        # the other.
        label = self._code_unit.getPrimarySymbol()  # Ghidra calls labels, "symbols" for legacy reasons.
        if label:
            # First see if name is the same.
            if label.getName() == new_name:
                return
            # Modify existing label
            if new_name:
                # TODO: Ghidra throws a DuplicateNameException if the name exists somewhere
                #   else instead of adding a prefix.
                label.setName(new_name, label.getSource())
            # Remove existing label.
            else:
                label.delete()

        # Set new label.
        elif new_name:
            label = self._ghidra._flatapi.createLabel(self._addr_obj, new_name, True)
            if not label:
                raise ValueError(f"Failed to set {hex(self.address)} with name: {new_name}")

    @property
    def next(self) -> Optional["GhidraLine"]:
        next_code_unit = self._ghidra._listing.getCodeUnitAfter(self._addr_obj)
        if next_code_unit:
            return GhidraLine(self._ghidra, next_code_unit)

    @property
    def prev(self) -> Optional["GhidraLine"]:
        prev_code_unit = self._ghidra._listing.getCodeUnitBefore(self._addr_obj)
        if prev_code_unit:
            return GhidraLine(self._ghidra, prev_code_unit)

    def set_comment(self, comment: Optional[str], comment_type=CommentType.eol):
        # Ghidra clears comment when null
        if not comment:
            comment = None

        self._code_unit.setComment(self._comment_type_map[comment_type], comment)

    @property
    def size(self) -> int:
        return self._code_unit.getLength()

    # TODO: Need to look into reevaluating what a line type can contain to better support ghidra
    @property
    def type(self) -> LineType:
        code_unit_type = str(self._code_unit.getClass())

        if "Instruction" in code_unit_type:
            return LineType.code

        data_type = self._code_unit.getDataType().getName()

        if "struct" in data_type:  # FIXME
            return LineType.struct

        # If data type is undefined, check if data is unloaded by checking if it has a value.
        if data_type == "undefined" and self._code_unit.getValue() is None:
            return LineType.unloaded

        if data_type.startswith("undefined"):
            return LineType.undefined

        try:
            return self._data_type_map[data_type]
        except KeyError:
            raise RuntimeError(f"Unexpected line type at {hex(self.address)}")

    @type.setter
    def type(self, new_type: LineType):
        unsupported = (LineType.tbyte, LineType.pack_real)
        if new_type not in LineType or new_type in unsupported:
            raise ValueError(f"Invalid line type: {new_type}")

        orig_type = self.type
        if orig_type == new_type:
            return  # No change necessary

        if new_type == LineType.undefined:
            self.undefine()
            return

        if new_type == LineType.unloaded:
            # TODO: Should we ever support this?
            raise TypeError(f"Setting a line type to unloaded is not currently supported.")

        if new_type == LineType.code:
            raise NotImplementedError("Setting a line to code is not currently supported.")

        if new_type == LineType.struct:
            raise NotImplementedError("Setting a line type to struct is not currently supported.")

        manager = self._ghidra._program.getDataTypeManager()
        data_type = manager.getDataType(f"/{self._data_type_map_inv[new_type]}")
        if not data_type:
            # FIXME: For some unknown reason somes types don't show up in the DataTypeManager.
            #   Therefore, we are going to initialize it manually.
            #   Determine if we need to do some type of data type initialization or something.
            if new_type == LineType.align:
                from ghidra.program.model.data import AlignmentDataType
                data_type = AlignmentDataType(manager)
            elif new_type == LineType.float:
                from ghidra.program.model.data import FloatDataType
                data_type = FloatDataType(manager)

            if not data_type:
                raise TypeError(f"Invalid line type: {repr(new_type)}")

        # TODO: catch possible exception thrown by Ghidra.
        self.undefine()
        self._code_unit = self._ghidra._flatapi.createData(self._addr_obj, data_type)

    def undefine(self):
        # TODO: catch the "CancelledException" that could be thrown.
        self._ghidra._flatapi.clearListing(self._addr_obj)
        self._code_unit = self._ghidra._listing.getCodeUnitAt(self._addr_obj)

    @property
    def value(self) -> Any:
        line_type = self.type

        if line_type == LineType.code:
            # TODO: Need to figure out generic way to pull x86Instruction and ARMInstruction types from Instruction???
            return GhidraInstruction(self._ghidra, self._code_unit)
        elif line_type == LineType.align:
            return self.data

        value = self._code_unit.getValue()

        # Scalar object
        if hasattr(value, "getUnsignedValue"):
            # NOTE: Right now we are forcing a signed value by calling getUnsignedValue(),
            #   but we may want to selectively use getValue() or getSignedValue().
            value = value.getUnsignedValue()

        # Pointer object
        if hasattr(value, "getOffset"):
            value = value.getOffset()

        return value

    @value.setter
    def value(self, new_value: Any):
        from ghidra.program.model.mem import MemoryAccessException
        try:
            self._set_value(new_value)
        except MemoryAccessException:
            block = self._ghidra._flatapi.getMemoryBlock(self._addr_obj)
            if block.isInitialized():
                # caused by some other problem
                raise

            # initialize the block and try again
            memory = self._ghidra._program.getMemory()
            memory.convertToInitialized(block, 0)
            self._set_value(new_value)

    def _set_value(self, new_value: Any):
        matched_types = LineType.match_type(new_value)
        if not matched_types:
            raise TypeError(f"Unsupported value type: {type(new_value)}")

        type_ = self.type

        # First see if setting this new value would require changing the line type.
        if type_ not in matched_types:
            # Use the first entry of matched types to be the type we change it to.
            new_type = matched_types[0]
            logger.debug(f"Changing line type from {type_} to {new_type}")
            self.type = new_type
            type_ = new_type

        if type_ == LineType.code:
            raise NotImplementedError(f"Setting an instruction is not currently supported.")

        elif type_ == LineType.byte:
            if isinstance(new_value, bytes):
                new_value = new_value[0]
            self._ghidra._flatapi.setByte(self._addr_obj, JByte(new_value))

        elif type_ == LineType.word:
            self._ghidra._flatapi.setShort(self._addr_obj, JShort(new_value))

        elif type_ == LineType.dword:
            self._ghidra._flatapi.setInt(self._addr_obj, JInt(new_value))

        elif type_ == LineType.qword:
            self._ghidra._flatapi.setLong(self._addr_obj, JLong(new_value))

        elif type_ == LineType.oword:
            raise NotImplementedError(f"Setting oword value it not currently supported.")

        elif type_ == LineType.tbyte:
            raise NotImplementedError(f"Setting tbyte value is not currently supported.")

        elif type_ == LineType.float:
            self._ghidra._flatapi.setFloat(self._addr_obj, JFloat(new_value))

        elif type_ == LineType.double:
            self._ghidra._flatapi.setDouble(self._addr_obj, JDouble(new_value))

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
            if len(new_value) > (self._next_defined.address - self.address):
                raise ValueError(f"Encoded string too large to fit on line.")
            # Fill with zero bytes.
            new_value += b"\x00" * (len(self) - len(new_value))
            # For strings, we are going to undefine the value first so ghidra appropriately
            # resets the code unit.
            self.undefine()
            self._ghidra._flatapi.setBytes(self._addr_obj, list(new_value))
            self.type = type_
            return

        elif type_ == LineType.struct:
            raise NotImplementedError(f"Setting struct value is not currently supported.")

        elif type_ == LineType.align:
            self._ghidra._flatapi.setBytes(self._addr_obj, new_value)

        elif type_ == LineType.tail:
            raise NotImplementedError(f"Getting tail value is not currently supported.")

        elif type_ == LineType.undefined:
            if isinstance(new_value, int):
                new_value = bytes([new_value])
            self._ghidra._flatapi.setBytes(self._addr_obj, new_value)

        elif type_ == LineType.unloaded:
            ...  # Nothing needs to be done for unloaded data.
