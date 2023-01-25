
from __future__ import annotations
import abc
from enum import IntEnum, auto
from typing import TYPE_CHECKING, List, Iterable, Type, Optional

import capstone

from dragodis.interface.types import FlowType
from dragodis.interface.operand import Operand, ARMOperand, x86Operand

if TYPE_CHECKING:
    from dragodis.interface import Reference, FlatAPI, Line, Variable


class Instruction(metaclass=abc.ABCMeta):
    """
    Instruction objects represent the actual assembly code of a line of code.
    """
    # Subclasses should update these to change which class gets used
    # depending on detected processor.
    _Operand: Type[Operand] = Operand
    _ARMInstruction: Type[Instruction] = None
    _x86Instruction: Type[Instruction] = None

    def __new__(cls, api: FlatAPI, *args, **kwargs):
        """
        During instantiation, the Instruction constructor will dynamically
        choose the correct class based on detected processor.
        """
        if api.processor_name.startswith("ARM"):
            klass = cls._ARMInstruction
        elif api.processor_name.startswith("x86"):
            klass = cls._x86Instruction
        else:
            klass = cls

        self = super().__new__(klass)
        self.__init__(api, *args, **kwargs)
        return self

    def __init__(self, api: FlatAPI):
        self._api = api

    def __repr__(self):
        return (
            f"<Instruction 0x{self.address:08x}"
            f" - {self.text}"
            f">"
        )

    def __str__(self):
        """Displays instruction text"""
        return self.text

    @property
    def _capstone_insn(self) -> capstone.CsInsn:
        """
        Obtains the capstone instruction disassembly.
        This is used to subsidize some of the processor specific functions,
        in the case the backend disassembler can't handle getting the information.

        :raises RuntimeError: If we fail to disassemble the undelying bytes
            of the function. (Which shouldn't happen.)
        """
        # Default to using capstone to pull this information.
        for insn in self._api._capstone_dis.disasm(self.data, 0x1000):
            return insn
        raise RuntimeError(f"Failed to disassemble instruction at: 0x{self.start:08X}")

    @property
    @abc.abstractmethod
    def address(self) -> int:
        """
        The start address of the instruction.
        """

    @property
    def line(self) -> Line:
        """
        The defined line for this instruction.
        """
        return self._api.get_line(self.address)

    @property
    def data(self) -> bytes:
        """
        The bytes that make up this instruction.
        """
        return self.line.data

    @property
    @abc.abstractmethod
    def flow_type(self) -> FlowType:
        """
        The type of of code flow for the instruction.
        """

    @property
    def is_call(self) -> bool:
        """
        Is the instruction a call instruction
        """
        return self.flow_type == FlowType.call

    @property
    def is_jump(self) -> bool:
        """
        Is the instruction an indirect jump instruction
        """
        return self.flow_type in (FlowType.conditional_jump, FlowType.unconditional_jump)

    @property
    def is_return(self) -> bool:
        """
        Is the instruction a return instruction
        """
        return self.flow_type == FlowType.terminal

    @property
    @abc.abstractmethod
    def mnemonic(self) -> str:
        """
        The instruction's mnemonic.

        The output text is disassembler specific, but all implementations
        will likely be similar. However, each implementation should do its best
        to follow the official mnemonics as much as possible.
        Mnemonic should always be lowercase to keep consistency.

        :return: String representation of the mnemonic
        """

    @property
    @abc.abstractmethod
    def root_mnemonic(self) -> str:
        """
        The instruction's root mnemonic which doesn't include any pre/post-fix modifications.
        (e.g. the "bl" in "blne")
        """

    @property
    @abc.abstractmethod
    def operands(self) -> List[Operand]:
        """
        Returns a list of `Operand` objects contained within the instruction.
        Order of operands in list should match the index of the operands.
        """

    # TODO: The following were originally decided based on what was available to IDA.
    #   Look into adding more such as is_jump, is_fall_through, tc.

    # TODO: Should we have an InstructionType class?

    @property
    @abc.abstractmethod
    def text(self) -> str:
        """
        The disassembled assembly code for the instruction.

        WARNING: The output text is disassembler specific and therefore may
        vary in appearance based on disassembler used.

        :return: String representation of instruction
        """

    @property
    def references_from(self) -> Iterable[Reference]:
        """
        Iterates cross references from the specified address.

        :param int addr: Address to get references from
        :yield: `Reference` objects.
        """
        yield from self._api.references_from(self.address)

    @property
    def references_to(self) -> Iterable[Reference]:
        """
        Iterates cross references to the specified address.

        :param int addr: Address to get references to
        :yield: `Reference` objects.
        """
        yield from self._api.references_to(self.address)

    @property
    @abc.abstractmethod
    def stack_depth(self) -> int:
        """
        The depth of stack pointer at the beginning of the instruction.
        This is relative to the start of the function.
        (This is usually the number after the address in list view of the disassembler,
        but negative.)
        """

    @property
    @abc.abstractmethod
    def stack_delta(self) -> int:
        """
        The change in stack depth if the instruction was applied.
        """

    @property
    def variables(self) -> Iterable[Variable]:
        """
        Iterates the variables in the instruction.
        """
        for operand in self.operands:
            if variable := operand.variable:
                yield variable


class ARMConditionCode(IntEnum):
    INVALID = -1
    EQ = 0       # 0000 Z                        Equal
    NE = auto()  # 0001 !Z                       Not equal
    CS = auto()  # 0010 C                        Unsigned higher or same
    CC = auto()  # 0011 !C                       Unsigned lower
    MI = auto()  # 0100 N                        Negative
    PL = auto()  # 0101 !N                       Positive or Zero
    VS = auto()  # 0110 V                        Overflow
    VC = auto()  # 0111 !V                       No overflow
    HI = auto()  # 1000 C & !Z                   Unsigned higher
    LS = auto()  # 1001 !C | Z                   Unsigned lower or same
    GE = auto()  # 1010 (N & V) | (!N & !V)      Greater or equal
    LT = auto()  # 1011 (N & !V) | (!N & V)      Less than
    GT = auto()  # 1100 !Z & ((N & V)|(!N & !V)) Greater than
    LE = auto()  # 1101 Z | (N & !V) | (!N & V)  Less than or equal
    AL = auto()  # 1110 Always
    NV = auto()  # 1111 Never


class ARMInstruction(Instruction):
    _Operand = ARMOperand

    @property
    def update_flags(self) -> bool:
        """
        Whether the condition flags are updated on the result of the operation.
        (S postfix)
        """
        # Default to using capstone.
        return self._capstone_insn.update_flags

    @property
    def condition_code(self) -> ARMConditionCode:
        """
        Returns the condition flag.
        """
        # Default to using capstone.
        cc = self._capstone_insn.cc
        return ARMConditionCode(ARMConditionCode.INVALID + cc)

    @property
    def writeback(self) -> bool:
        """
        Whether the instruction contains an operand that updates itself
        before or after the value is obtained.
        """
        # Default to using capstone.
        # We count push and pop instructions as having a writeback because
        # some disassemblers interpret these as stmdb or ldmia opcodes with sp!
        insn = self._capstone_insn
        return insn.mnemonic.lower() in ("push", "pop") or insn.writeback

    @property
    def pre_indexed(self) -> bool:
        """
        Whether the instruction has a pre-indexed writeback.
        Ie, the register is updated before evaluation:

        .. code::

            [R1, 8]!
        """
        return self.writeback and "!" in self.text

    @property
    def post_indexed(self) -> bool:
        """
        Whether the instruction has a post-indexed writeback.
        Ie, the register is updated after evaluation:

        .. code::

            [R1], 8
        """
        return self.writeback and "!" not in self.text


class x86Instruction(Instruction):
    _Operand = x86Operand

    @property
    @abc.abstractmethod
    def rep(self) -> Optional[str]:
        """
        Rep prefix applied to instruction if provided.

        .. code::

            rep
            repne
        """


Instruction._ARMInstruction = ARMInstruction
Instruction._x86Instruction = x86Instruction
