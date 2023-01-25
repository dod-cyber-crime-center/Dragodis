
from __future__ import annotations
from typing import List, TYPE_CHECKING, Optional

from dragodis.exceptions import NotExistError
from dragodis.ida.operand import IDAOperand, IDAx86Operand, IDAARMOperand
from dragodis.interface.types import FlowType
from dragodis.interface.instruction import (
    Instruction, x86Instruction, ARMInstruction, ARMConditionCode
)

if TYPE_CHECKING:
    from dragodis.ida.flat import IDAFlatAPI


# TODO: Perhaps have a local helper utility that pulls and caches all the instruction
#    objects for the function, ready to be accessed?
class IDAInstruction(Instruction):
    _Operand = IDAOperand

    def __init__(self, ida: IDAFlatAPI, addr: int):
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

    @property
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

    @property
    def mnemonic(self) -> str:
        return (self._ida._ida_ua.ua_mnem(self.address) or "").lower()

    @property
    def root_mnemonic(self) -> str:
        return self._insn_t.get_canon_mnem().lower()

    @property
    def operands(self) -> List[IDAOperand]:
        return [
            self._Operand(self, self._ida, self.address, index, op)
            for index, op in self._ida._ida_helpers.get_operands(self.address)
        ]

    @property
    def text(self) -> str:
        return self._ida._idc.GetDisasm(self.address)

    @property
    def stack_depth(self) -> int:
        return self._ida._idc.get_spd(self.address)

    @property
    def stack_delta(self) -> int:
        # NOTE: IDA gives the delta in relation to the previous instruction,
        #   but we want the delta that this instructions applies.
        delta = self._ida._idc.get_sp_delta(self._ida._idc.next_head(self.address))
        if delta is None:
            delta = 0
        return delta


class IDAx86Instruction(IDAInstruction, x86Instruction):
    _Operand = IDAx86Operand

    @property
    def rep(self) -> Optional[str]:
        if self.data[0] in (0xF2, 0xF3):
            text = self.text.lower()
            # Existence of byte prefix doesn't necessarily mean we have a rep prefix.
            # Double confirm by looking at the text itself.
            if text.startswith("rep"):
                rep, _, _ = text.partition(" ")
                return rep
        return None


class IDAARMInstruction(IDAInstruction, ARMInstruction):
    _Operand = IDAARMOperand

    @property
    def update_flags(self) -> bool:
        return bool(self._insn_t.auxpref & self._ida._ida_arm.aux_cond)

    @property
    def condition_code(self) -> ARMConditionCode:
        condition = self._ida._ida_arm.get_cond(self._insn_t)
        return ARMConditionCode(condition)

    @property
    def writeback(self) -> bool:
        return bool(
            self._insn_t.auxpref & (
                self._ida._ida_arm.aux_postidx
                | self._ida._ida_arm.aux_wback
                | self._ida._ida_arm.aux_wbackldm
            )
            or self.mnemonic in ("push", "pop")
        )

    @property
    def pre_indexed(self) -> bool:
        return self.writeback and not self._insn_t.auxpref & self._ida._ida_arm.aux_postidx

    @property
    def post_indexed(self) -> bool:
        return self.writeback and bool(self._insn_t.auxpref & self._ida._ida_arm.aux_postidx)


IDAInstruction._x86Instruction = IDAx86Instruction
IDAInstruction._ARMInstruction = IDAARMInstruction
