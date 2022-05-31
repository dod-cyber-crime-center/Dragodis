from __future__ import annotations

from typing import List, TYPE_CHECKING

from dragodis.exceptions import NotExistError
from dragodis.ida.operand import IDAOperand, IDAx86Operand, IDAARMOperand
from dragodis.interface.types import FlowType
from dragodis.interface.instruction import (
    Instruction, x86Instruction, ARMInstruction, ARMConditionCode
)
from dragodis.utils import cached_property
cached_property = property  # FIXME: cached property disabled for now.

if TYPE_CHECKING:
    from dragodis.ida.flat import IDA

# Used for typing.
# noinspection PyUnreachableCode
if False:
    import ida_ua


# TODO: Perhaps have a local helper utility that pulls and caches all the instruction
#    objects for the function, ready to be accessed?
class IDAInstruction(Instruction):
    _Operand = IDAOperand

    def __init__(self, ida: IDA, addr: int):
        super().__init__(ida)
        self._ida = ida
        self._addr = addr
        insn_t = self._ida._ida_helpers.get_instruction(addr)
        if not insn_t:
            raise NotExistError(f"Instruction does not exist at: {hex(addr)}")
        self._insn_t = insn_t

    @property
    def address(self):
        return self._addr

    @cached_property
    def flow_type(self) -> FlowType:
        if self._ida._ida_idp.is_call_insn(self._insn_t):
            return FlowType.call
        elif self._ida._ida_idp.is_ret_insn(self._insn_t):
            return FlowType.terminal

        refs = self._ida._idautils.CodeRefsFrom(self.address, 0)
        has_refs = bool(next(refs, False))
        if not has_refs:
            return FlowType.fall_through

        # Checking for conditional/unconditional jump is a bit more involved with IDA.
        # We are going to need to check if the code reference is a "flow" or not.
        next_head = self._ida._idc.next_head(self.address)
        if self._ida._idc.is_flow(self._ida._idc.get_full_flags(next_head)):
            return FlowType.conditional_jump
        else:
            return FlowType.unconditional_jump

    @cached_property
    def mnemonic(self) -> str:
        return (self._ida._ida_ua.ua_mnem(self.address) or "").lower()

    @cached_property
    def root_mnemonic(self) -> str:
        return self._insn_t.get_canon_mnem().lower()

    @cached_property
    def operands(self) -> List[IDAOperand]:
        return [
            self._Operand(self, self._ida, self.address, index, op)
            for index, op in self._ida._ida_helpers.get_operands(self.address)
        ]

    @cached_property
    def text(self) -> str:
        return self._ida._idc.GetDisasm(self.address)

    @cached_property
    def stack_depth(self) -> int:
        return self._ida._idc.get_spd(self.address)

    @cached_property
    def stack_delta(self) -> int:
        # NOTE: IDA gives the delta in relation to the previous instruction,
        #   but we want the delta that this instructions applies.
        delta = self._ida._idc.get_sp_delta(self._ida._idc.next_head(self.address))
        if delta is None:
            delta = 0
        return delta


class IDAx86Instruction(IDAInstruction, x86Instruction):
    _Operand = IDAx86Operand


class IDAARMInstruction(IDAInstruction, ARMInstruction):
    _Operand = IDAARMOperand

    @cached_property
    def update_flags(self) -> bool:
        return bool(self._insn_t.auxpref & self._ida._ida_arm.aux_cond)

    @cached_property
    def condition_code(self) -> ARMConditionCode:
        condition = self._ida._ida_arm.get_cond(self._insn_t)
        return ARMConditionCode(condition)

    @cached_property
    def writeback(self) -> bool:
        return bool(
            self._insn_t.auxpref & (
                self._ida._ida_arm.aux_postidx
                | self._ida._ida_arm.aux_wback
                | self._ida._ida_arm.aux_wbackldm
            )
            or self.mnemonic in ("push", "pop")
        )

    @cached_property
    def pre_indexed(self) -> bool:
        return self.writeback and not self._insn_t.auxpref & self._ida._ida_arm.aux_postidx

    @cached_property
    def post_indexed(self) -> bool:
        return self.writeback and bool(self._insn_t.auxpref & self._ida._ida_arm.aux_postidx)


IDAInstruction._x86Instruction = IDAx86Instruction
IDAInstruction._ARMInstruction = IDAARMInstruction
