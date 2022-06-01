
from __future__ import annotations

from typing import TYPE_CHECKING, Union, List, Optional

from dragodis.interface.operand_value import (
    OperandValue, Immediate, MemoryReference, Register,
    RegisterList, Phrase,
)
from dragodis.utils import cached_property
cached_property = property  # FIXME: cached property disabled for now.

if TYPE_CHECKING:
    import ida_ua
    from dragodis.ida.flat import IDA


class IDAImmediate(Immediate):
    ...


class IDAMemoryReference(MemoryReference):
    ...


class IDARegister(Register):

    def __init__(self, ida: IDA, reg: int, width: int):
        """
        :param ida: The IDA disassembler.
        :param reg: Internal register number as defined in the IDA processor module.
        :param width: The size of the register in bytes.
        """
        self._ida = ida
        self._reg = reg
        self._width = width

    def __eq__(self, other: "IDARegister"):
        if isinstance(other, IDARegister):
            return self._reg == other._reg and self._width == other._width
        return False

    @cached_property
    def bit_width(self) -> int:
        return self._width * 8

    @cached_property
    def name(self) -> str:
        return self._ida._ida_idp.get_reg_name(self._reg, self._width).lower()


class IDARegisterList(RegisterList):
    ...


class IDAARMPhrase(Phrase):
    """
    Defines an ARM phrase/displacement
    e.g.
        [R5],#4
        [R11,#-8]
    """

    def __init__(self, ida: IDA, insn_t: "ida_ua.insn_t", op_t: "ida_ua.op_t"):
        self._ida = ida
        self._insn_t = insn_t
        self._op_t = op_t
        self._width = ida.bit_size // 8

    @cached_property
    def base(self) -> IDARegister:
        """
        The base register
        """
        return IDARegister(self._ida, self._op_t.reg, self._width)

    @property
    def index(self) -> Optional[IDARegister]:
        """
        The index register
        """
        # Index register is not a thing for ARM.
        return None

    @property
    def scale(self) -> int:
        """
        The scaling factor for the index.
        """
        return 1

    @cached_property
    def offset(self) -> Union[IDARegister, int]:
        """
        The offset or displacement.
        This could be a register or immediate.
        e.g.
            [R1, R2] -> R2
            [R1, #1] -> 1

        NOTE: For shift information, please access the Operand.shift attribute.
            [R1, R2,LSL #3] -> R2
        """
        # [R1, R2]
        if self._op_t.type == self._ida._ida_ua.o_phrase:
            second_reg = self._ida._ida_arm.secreg(self._op_t)  # pulling the R2
            return IDARegister(self._ida, second_reg, self._width)


        # [R1, #1]
        else:
            offset = self._op_t.addr
            # Convert to signed number.
            if offset >> (self._ida.bit_size - 1):  # Is the hi-bit set?
                offset -= (1 << self._ida.bit_size)
            return offset


class IDAx86Phrase(Phrase):
    """
    Defines a x86 phrase/displacement.
    e.g.
        [ebp-eax*2+0x100]
        [ebp+4]
    """

    def __init__(self, ida: IDA, insn_t: "ida_ua.insn_t", op_t: "ida_ua.op_t"):
        self._ida = ida
        self._insn_t = insn_t
        self._op_t = op_t
        self._width = ida.bit_size // 8

    @cached_property
    def base(self) -> Optional[IDARegister]:
        """
        The base register.
        e.g.
            [ebp+ecx*2+var_8] -> ebp
        """
        base_reg = self._ida._ida_intel.x86_base_reg(self._insn_t, self._op_t)
        if base_reg == -1:
            return None
        return IDARegister(self._ida, base_reg, self._width)

    @cached_property
    def index(self) -> Optional[IDARegister]:
        """
        The index register
        e.g.
            [ebp+ecx*2+var_8] -> ecx
        """
        index_reg = self._ida._ida_intel.x86_index_reg(self._insn_t, self._op_t)
        if index_reg == -1:
            return None
        return IDARegister(self._ida, index_reg, self._width)

    @cached_property
    def scale(self) -> int:
        """
        The scaling factor for the index.
        NOTE: This should default to 0 if index * scale is not supported in the processor. (ARM)

        e.g.
            [ebp+ecx*2+var_8] -> 2
        """
        return 1 << self._ida._ida_intel.sib_scale(self._op_t)

    @cached_property
    def offset(self) -> int:
        """
        The offset or displacement.
        This could be a register or immediate.

        e.g.
            [ebp+ecx*2+var_8] -> var_8 -> 8
        """
        offset = self._op_t.addr
        # Convert to signed number.
        if offset >> (self._ida.bit_size - 1):  # Is the hi-bit set?
            offset -= (1 << self._ida.bit_size)
        return offset