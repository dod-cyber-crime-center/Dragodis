from __future__ import annotations
from typing import List, TYPE_CHECKING

from dragodis.exceptions import NotExistError
from dragodis.ghidra.operand import GhidraOperand, GhidraARMOperand, Ghidrax86Operand
from dragodis.ghidra.utils import convert_flow_type
from dragodis.interface.instruction import Instruction, x86Instruction, ARMInstruction

if TYPE_CHECKING:
    from dragodis.interface.types import FlowType
    from dragodis.ghidra.flat import Ghidra
    import ghidra


class GhidraInstruction(Instruction):
    _Operand = GhidraOperand

    # TODO: Update as necessary.
    _arm_data_root_mnemonics = [
        "ldr",
        "str",
        "stm",
        "swp",
    ]

    def __init__(self, ghidra: Ghidra, instruction: "ghidra.program.model.listing.Instruction"):
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


GhidraInstruction._ARMInstruction = GhidraARMInstruction
GhidraInstruction._x86Instruction = Ghidrax86Instruction
