
from __future__ import annotations

import abc
from typing import Optional, TYPE_CHECKING, Union, Tuple

import capstone

from dragodis.interface.types import OperandType, ARMShiftType

if TYPE_CHECKING:
    from dragodis.interface.instruction import Instruction
    from dragodis.interface.operand_value import OperandValue, Register
    from dragodis.interface.variable import Variable


class Operand(metaclass=abc.ABCMeta):
    """
    Operands represent the actual operands of instructions. Operand objects
    contain information about the important attributes of operands such as type
    and value.
    """

    def __init__(self, instruction: Instruction):
        """
        :param instruction: The underlying instruction for this operand.
        """
        self.instruction = instruction

    def __str__(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return f"<Operand 0x{self.address:08x}:{self.index} - {self.text}>"

    @property
    def _capstone_op(self) -> Union[capstone.arm.ArmOp, capstone.x86.X86Op]:
        return self.instruction._capstone_insn.operands[self.index]

    @property
    @abc.abstractmethod
    def address(self) -> int:
        """
        The address of the instruction the operand is found in.
        """

    @property
    @abc.abstractmethod
    def index(self) -> int:
        """
        Index of operand as found in the instruction.
        """

    @property
    @abc.abstractmethod
    def text(self) -> str:
        """
        Disassembled text for operand.
        """

    @property
    @abc.abstractmethod
    def type(self) -> OperandType:
        """
        Type of operand.
        """

    @property
    @abc.abstractmethod
    def value(self) -> OperandValue:
        """
        An object that represents the contents of the operand
        based on the type.

        :return: An OperandValue object.
        """

    # TODO: Rename to "size" instead?
    @property
    @abc.abstractmethod
    def width(self) -> int:
        """
        Based on the data type it contains, the size of the operand's value in bytes
        """

    @property
    @abc.abstractmethod
    def variable(self) -> Optional[Variable]:
        """
        Obtains the variable referenced within the operand.
        Returns None, if no variable is referenced.
        """

    # TODO: Add more attributes for pulling individual components for phrases.


class ARMOperand(Operand):
    """
    ARM based operand.
    """

    _capstone_shift_map = {
        capstone.arm.ARM_SFT_ASR: (ARMShiftType.ASR, False),
        capstone.arm.ARM_SFT_LSL: (ARMShiftType.LSL, False),
        capstone.arm.ARM_SFT_LSR: (ARMShiftType.LSR, False),
        capstone.arm.ARM_SFT_ROR: (ARMShiftType.ROR, False),
        capstone.arm.ARM_SFT_RRX: (ARMShiftType.RRX, False),
        capstone.arm.ARM_SFT_ASR_REG: (ARMShiftType.ASR, True),
        capstone.arm.ARM_SFT_LSL_REG: (ARMShiftType.LSL, True),
        capstone.arm.ARM_SFT_LSR_REG: (ARMShiftType.LSR, True),
        capstone.arm.ARM_SFT_ROR_REG: (ARMShiftType.ROR, True),
        capstone.arm.ARM_SFT_RRX_REG: (ARMShiftType.RRX, True),
    }

    @property
    def _capstone_op(self) -> capstone.arm.ArmOp:
        """
        Convenience function for getting capstone implementation of operand.
        """
        return self.instruction._capstone_insn.operands[self.index]

    # TODO: Should shifted information be stored in a ShiftedRegister OperandValue type instead?
    @property
    def shift(self) -> Tuple[ARMShiftType, Union[int, Register]]:
        """
        The shift type and shift amount (which can be a constant or another register)
        (Should default to LSL with a shift count of 0 for non-shifted operands.)

        Defaults to using capstone.
        """
        op = self._capstone_op

        if op.shift.type == capstone.arm.ARM_SFT_INVALID:
            return ARMShiftType.LSL, 0  # not shifted

        try:
            shift_type, is_reg = self._capstone_shift_map[op.shift.type]
        except KeyError:
            raise NotImplementedError(f"Unsupported shift type: {op.shift.type}")

        if is_reg:
            reg_name = self.instruction._capstone_insn.reg_name(op.shift.value)
            shift_count = self.instruction._api.get_register(reg_name)
        else:
            shift_count = op.shift.value

        return shift_type, shift_count


class x86Operand(Operand):
    """
    x86 based operand.
    """

    @property
    def _capstone_op(self) -> capstone.x86.X86Op:
        """
        Convenience function for getting capstone implementation of operand.
        """
        return self.instruction._capstone_insn.operands[self.index]
