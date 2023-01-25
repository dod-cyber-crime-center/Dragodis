from __future__ import annotations
import logging
from typing import List, Optional, TYPE_CHECKING

from dragodis.exceptions import NotExistError
from dragodis.ghidra.operand import GhidraOperand, GhidraARMOperand, Ghidrax86Operand
from dragodis.ghidra.utils import convert_flow_type
from dragodis.interface.instruction import Instruction, x86Instruction, ARMInstruction

if TYPE_CHECKING:
    from dragodis.interface.types import FlowType
    from dragodis.ghidra.flat import GhidraFlatAPI
    import ghidra


logger = logging.getLogger(__name__)


class GhidraInstruction(Instruction):
    _Operand = GhidraOperand

    # TODO: Update as necessary.
    _arm_data_root_mnemonics = [
        "ldr",
        "str",
        "stm",
        "swp",
    ]

    def __init__(self, ghidra: GhidraFlatAPI, instruction: "ghidra.program.model.listing.Instruction"):
        super().__init__(ghidra)
        self._ghidra = ghidra
        self._instruction = instruction

    @property
    def address(self) -> int:
        return self._instruction.getAddress().getOffset()

    @property
    def flow_type(self) -> FlowType:
        return convert_flow_type(self._instruction.getFlowType())

    @property
    def mnemonic(self) -> str:
        # Using lower() to keep consistent with IDA.
        return str(self._instruction.getMnemonicString()).lower()

    @property
    def root_mnemonic(self) -> str:
        # For ARM architectures, pull the second constructor object to get the true
        # base mnemonic without prefixes.
        if self._ghidra.processor_name == "ARM":
            from ghidra.app.plugin.processors.sleigh import SleighDebugLogger
            sleigh_logger = SleighDebugLogger(
                self._ghidra._program,
                self._instruction.getAddress(),
                SleighDebugLogger.SleighDebugMode.MASKS_ONLY
            )
            params = sleigh_logger.getConstructorLineNumbers()
            if len(params) >= 2:
                root_mnem, found, _ = params[1].partition("(")
                if not found:
                    return self.mnemonic
                root_mnem = root_mnem.lower()

                # Some instructions will still include postfixes, such as "ldrb" instead of "ldr".
                # We'll need to manually remove these.
                for root in self._arm_data_root_mnemonics:
                    if root_mnem.startswith(root):
                        return root

                return root_mnem

        return self.mnemonic

    @property
    def operands(self) -> List[GhidraOperand]:
        # HACK: Ignore if operands are implied based on mnemonic.
        # (This is done to better match how IDA does it.)
        if "ES:" in self.text:
            logger.debug(f"Ignoring implied operands at 0x%X: %s", self.address, self.text)
            return []
        return [
            self._Operand(self._ghidra, self, index)
            for index in range(self._instruction.getNumOperands())
        ]

    @property
    def text(self) -> str:
        return str(self._instruction)

    @property
    def stack_depth(self) -> int:
        from ghidra.app.cmd.function import CallDepthChangeInfo
        addr = self._instruction.getAddress()
        func = self._ghidra._listing.getFunctionContaining(addr)
        info = CallDepthChangeInfo(func)
        depth = info.getDepth(addr)
        if depth == func.UNKNOWN_STACK_DEPTH_CHANGE:
            depth = 0
        return depth

    @property
    def stack_delta(self) -> int:
        delta = 0
        flow_type = self._instruction.getFlowType()
        if flow_type.isCall() and flow_type.isUnConditional():
            # the delta we are looking for is actually stored in the function and not the instruction
            flows = self._instruction.getFlows()
            if not flows:
                return delta
            if len(flows) == 1:
                func = self._ghidra._flatapi.getFunctionAt(flows[0])
                # If function has a call fixup, getStackPurgeSize() will be wrong.
                # In this case, we will just calculate from the next instruction's stack depth.
                if func.getCallFixup():
                    next_insn = self.line.next.instruction
                    delta = next_insn.stack_depth - self.stack_depth
                else:
                    delta = func.getStackPurgeSize()
            else:
                logger.warning(f'unexpected number of flows: {flows}')
        else:
            from ghidra.app.cmd.function import CallDepthChangeInfo
            addr = self._instruction.getAddress()
            func = self._ghidra._listing.getFunctionContaining(addr)
            info = CallDepthChangeInfo(func)
            delta = info.getInstructionStackDepthChange(self._instruction)
            if delta == func.UNKNOWN_STACK_DEPTH_CHANGE:
                delta = 0
        return delta


class GhidraARMInstruction(GhidraInstruction, ARMInstruction):
    _Operand = GhidraARMOperand


class Ghidrax86Instruction(GhidraInstruction, x86Instruction):
    _Operand = Ghidrax86Operand

    @property
    def mnemonic(self) -> str:
        mnemonic = super().mnemonic
        # Strip off .rep* prefix if there.
        mnemonic, _, _ = mnemonic.partition(".rep")
        return mnemonic

    @property
    def rep(self) -> Optional[str]:
        if self.data[0] in (0xF2, 0xF3):
            mnemonic = str(self._instruction.getMnemonicString()).lower()
            # Existence of byte prefix doesn't necessarily mean we have a rep prefix.
            # Double confirm by looking at the text itself.
            if ".rep" in mnemonic:
                _, _, rep = mnemonic.partition(".")
                return rep
        return None


GhidraInstruction._ARMInstruction = GhidraARMInstruction
GhidraInstruction._x86Instruction = Ghidrax86Instruction
