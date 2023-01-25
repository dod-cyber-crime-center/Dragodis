"""
Home for constants and types.
"""

from enum import IntEnum, IntFlag, auto
from typing import Any, List


class CommentType(IntEnum):
    eol = auto()
    anterior = auto()
    posterior = auto()
    plate = auto()
    repeatable = auto()


class FlowType(IntEnum):
    call = auto()
    terminal = auto()
    conditional_jump = auto()
    unconditional_jump = auto()
    fall_through = auto()


# TODO: We should add a type for func_ptr, (which would overwrite being DWORD or whatever)
class LineType(IntEnum):
    code = auto()
    byte = auto()
    word = auto()
    dword = auto()
    qword = auto()
    oword = auto()  # also known as xmmword (16 byte integer)
    tbyte = auto()
    float = auto()
    double = auto()
    pack_real = auto()
    string = auto()     # utf-8 string type
    string16 = auto()   # utf-16-le string type
    string32 = auto()   # utf-32-le string type
    struct = auto()
    align = auto()
    tail = auto()
    undefined = auto()
    unloaded = auto()

    @classmethod
    def match_type(cls, value: Any) -> List["LineType"]:
        """
        Returns all possible LineTypes that match to the given value.
        List is sorted so that the first entry would be default.
        """
        # Import here to prevent cyclic loop.
        from dragodis.interface import Instruction

        if isinstance(value, Instruction):
            return [cls.code]
        elif isinstance(value, int):
            types = []
            if value < 0:
                return []  # TODO: handle negative values?
            if value <= 0xffffffffffffffffffffffffffffffff:
                types.append(cls.oword)
            if value <= 0xffffffffffffffff:
                types.append(cls.qword)
            if value <= 0xffff:
                types.append(cls.word)
            if value <= 0xff:
                types.append(cls.byte)
                types.append(cls.undefined)
            if value <= 0xffffffff:  # checking last so we can have dword as default over byte and word
                types.append(cls.dword)
            types.reverse()
            return types
        elif isinstance(value, float):
            return [cls.float, cls.double]
        elif isinstance(value, str):
            return [cls.string, cls.string16, cls.string32]
        # TODO: should code count as bytes?
        elif isinstance(value, bytes) and len(value) == 1:
            return [cls.byte, cls.undefined, cls.align]
        elif isinstance(value, bytes):
            return [cls.undefined, cls.align]
        elif value is None:
            return [cls.unloaded]
        # TODO: Support this?
        # elif isinstance(value, dict):
        #     return [self.struct]
        else:
            return []


# TODO: Add description and example for each type.
class OperandType(IntEnum):
    """Types of operands."""
    void = auto()           # No Operand
    register = auto()       # General Register
    register_list = auto()  # List of Registers
    memory = auto()         # Direct Memory Reference  # TODO: Rename this to "data"?
    immediate = auto()      # Immediate Value
    phrase = auto()         # Memory Phrase/Displacement
    code = auto()           # Immediate Near/Far Address to code (usually the start of a function)


class ARMShiftType(IntEnum):
    """
    The possible shift types found in ARM operands.
    """
    LSL = 0       # logical left         LSL #0 - (don't shift)
    LSR = auto()  # logical right        LSR #0 means LSR #32
    ASR = auto()  # arithmetic right     ASR #0 means ASR #32
    ROR = auto()  # rotate right         ROR #0 means RRX
    RRX = auto()  # extended rotate right

    # ARMv8 shifts
    MSL = auto()  # masked shift left (ones are shifted in from the right)

    # extending register operations
    UXTB = auto()
    UXTH = auto()
    UXTW = auto()
    UXTX = auto()  # alias for LSL
    SXTB = auto()
    SXTH = auto()
    SXTW = auto()
    SXTX = auto()


# TODO: Define what these mean
# TODO: Should these be flags instead of exclusive?
#   - We can have both a read and a write!
class ReferenceType(IntEnum):
    """Types of references."""
    # TODO: These where originally based on IDA. Get influence from Ghidra
    unknown = auto()
    data = auto()
    data_offset = auto()  #TODO: what is this?
    data_write = auto()
    data_read = auto()
    data_text = auto()
    data_informational = auto()
    code_call = auto()
    # code_far_call = auto()
    # code_near_call = auto()
    code_jump = auto()
    # code_far_jump = auto()
    # code_near_jump = auto()
    code_user = auto()
    ordinary_flow = auto()


class SegmentPermission(IntFlag):
    execute = auto()
    write = auto()
    read = auto()
    volatile = auto()


class SegmentType(IntEnum):
    code = auto()
    data = auto()
    null = auto()
    uninitialized = auto()
    external = auto()


class ProcessorType(IntEnum):
    ARM = auto()
    ARM64 = auto()
    x86 = auto()
    x64 = auto()


# convenience
PROCESSOR_ARM = ProcessorType.ARM
PROCESSOR_ARM64 = ProcessorType.ARM64
PROCESSOR_X86 = ProcessorType.x86
PROCESSOR_X64 = ProcessorType.x64
