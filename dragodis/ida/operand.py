from __future__ import annotations

from typing import Optional, TYPE_CHECKING, Union, Tuple

from dragodis.exceptions import NotExistError
from dragodis.ida.stack import IDAStackVariable, IDAStackFrame
from dragodis.ida.variable import IDAVariable
from dragodis.interface import Phrase
from dragodis.interface.operand import Operand, ARMOperand, x86Operand, OperandType
from dragodis.ida.operand_value import (
    OperandValue, IDARegister, IDAImmediate, IDAMemoryReference,
    IDAARMPhrase, IDAx86Phrase, IDARegisterList,
)
from dragodis.interface.types import ARMShiftType
from dragodis.utils import cached_property

if TYPE_CHECKING:
    from dragodis.ida.flat import IDA
    from dragodis.ida.instruction import IDAInstruction

# Used for typing.
# noinspection PyUnreachableCode
if False:
    import ida_ua


# TODO: Cache this operand to return same object for same address.
class IDAOperand(Operand):

    _type_map = {
        0: OperandType.void,          # o_void
        1: OperandType.register,      # o_reg
        2: OperandType.memory,        # o_mem
        3: OperandType.phrase,        # o_phrase
        4: OperandType.phrase,        # o_displ
        5: OperandType.immediate,     # o_imm
        6: OperandType.code,          # o_far
        7: OperandType.code,          # o_near
    }

    def __init__(self, instruction: IDAInstruction, ida: IDA, addr: int, index: int, op_t: "ida_ua.op_t"):
        super().__init__(instruction)
        self._ida = ida
        self._addr = addr
        self._index = index
        self._op_t = op_t

    @property
    def address(self) -> int:
        return self._addr

    @property
    def index(self) -> int:
        return self._index

    @cached_property
    def text(self) -> str:
        # Get operand text and then remove the color tags.
        # (Doing same thing as idc.print_operand())
        text = self._ida._ida_ua.print_operand(self.address, self.index)
        return self._ida._ida_lines.tag_remove(text)

    @cached_property
    def type(self) -> OperandType:
        # Equivalent to idc.get_operand_type(), but using already cached op_t object.
        op_type = self._op_t.type
        try:
            return self._type_map[op_type]
        except KeyError:
            raise RuntimeError(f"Unexpected operand type: {op_type}")

    @cached_property
    def value(self) -> OperandValue:
        operand_type = self.type
        # TODO: Should we be recording both .value and .addr in the MemoryReference object?
        if operand_type in (OperandType.memory, OperandType.code):  # o_mem or o_near/o_far
            return IDAMemoryReference(self._op_t.addr)
        elif operand_type == OperandType.register:  # o_reg
            return IDARegister(self._ida, self._op_t.reg, self.width)
        elif operand_type == OperandType.immediate:  # o_imm
            return IDAImmediate(self._op_t.value)

        # Architecture specific operands types like phrase should be handled by the
        # appropriate subclass.
        raise ValueError(f"Invalid operand type: {operand_type!r}")

    @cached_property
    def width(self) -> int:
        return self._ida._ida_ua.get_dtype_size(self._op_t.dtype)

    @cached_property
    def variable(self) -> Optional[IDAVariable]:
        value = self.value
        if isinstance(value, Phrase):
            offset = value.offset
            if isinstance(offset, int):
                stack_var = self._ida._ida_frame.get_stkvar(self.instruction._insn_t, self._op_t, value.offset)
                if stack_var:
                    member, _ = stack_var
                    func_t = self._ida._ida_funcs.get_func(self.address)
                    frame = self._ida._ida_frame.get_frame(func_t)
                    frame = IDAStackFrame(self._ida, frame)
                    return IDAStackVariable(self._ida, frame, member)

        elif isinstance(value, int):  # memory or immediate
            try:
                # Cast to int() to strip off custom classes.
                return self._ida.get_variable(int(value))
            except NotExistError:
                pass


class IDAARMOperand(IDAOperand, ARMOperand):

    # Append ARM specific operand types.
    _type_map = {
        **IDAOperand._type_map,
        # We treat shifted registers just as regular register types, but with the .shift attribute available.
        8: OperandType.register,       # ida_arm.o_shreg
        9: OperandType.register_list,  # ida_arm.o_reglist
    }

    @cached_property
    def shift(self) -> Tuple[ARMShiftType, Union[int, IDARegister]]:
        if self._op_t.type == self._ida._ida_ua.o_phrase:
            # For a phrase, shift count is in op.value
            shift_count = self._op_t.value
            return ARMShiftType(self._op_t.specflag2), shift_count

        elif self._op_t.type == self._ida._ida_arm.o_shreg:
            # Shift can be an immediate or another register.
            # I believe we determine which one it is based on whether op.value is zero.
            shift_count = self._op_t.value
            if not shift_count:
                shift_count = IDARegister(self._ida, self._ida._ida_arm.secreg(self._op), self.width)
            return ARMShiftType(self._op_t.specflag2), shift_count

        return ARMShiftType.LSL, 0  # not shifted

    @cached_property
    def value(self) -> OperandValue:
        # Get value for ARM specific types.
        operand_type = self.type

        if operand_type == OperandType.register_list:
            # Register numbers are stored in a bitmap in specval.
            reg_bitmap = self._op_t.specval
            width = self.width
            return IDARegisterList([
                IDARegister(self._ida, reg, width)
                for reg in range(16) if reg_bitmap & (1 << reg)
            ])

        if operand_type == OperandType.phrase:  # o_phrase/o_displ
            return IDAARMPhrase(self._ida, self.instruction._insn_t, self._op_t)

        return super().value


class IDAx86Operand(IDAOperand, x86Operand):

    @cached_property
    def type(self) -> OperandType:
        # For x86, there is a weird corner case, where we could have something like
        # dword_40DC20[eax*4], which really is closer to a phrase, without
        # the base:  [0 + eax*4 + dword_40DC20]
        type = super().type
        if type == OperandType.memory:
            try:
                # Check if we have an index register to know if if this should
                # be a phrase.
                index_reg = self._ida._ida_intel.x86_index_reg(self.instruction._insn_t, self._op_t)
                if index_reg != -1:  # RegNo.R_none
                    return OperandType.phrase
            except ValueError:
                pass
        return type

    @cached_property
    def value(self) -> OperandValue:
        # Get value for x86 specific types.
        operand_type = self.type

        if operand_type == OperandType.phrase:  # o_phrase/o_displ
            return IDAx86Phrase(self._ida, self.instruction._insn_t, self._op_t)

        return super().value
