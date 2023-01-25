"""
Interface for Ghidra operands.
"""
from __future__ import annotations

from enum import IntFlag
from typing import TYPE_CHECKING, Optional, Tuple

from dragodis.exceptions import NotExistError
from dragodis.ghidra.variable import GhidraVariable, GhidraGlobalVariable
from dragodis.interface.operand import Operand, OperandType, ARMOperand, x86Operand
from dragodis.ghidra.operand_value import (
    OperandValue, GhidraRegister, GhidraImmediate, GhidraMemoryReference,
    GhidraRegisterList, GhidraPhrase,
)

# Used for typing.
if TYPE_CHECKING:
    from dragodis.ghidra.flat import GhidraFlatAPI
    from dragodis.ghidra.instruction import GhidraInstruction
    import ghidra
    import ghidra.app.plugin.processors.generic.Operand


# Stolen from ghidra.program.model.lang.OperandType
class GhidraOperandType(IntFlag):
    READ = 0x1
    WRITE = 0x2
    INDIRECT = 0x4
    IMMEDIATE = 0x8
    RELATIVE = 0x10
    IMPLICIT = 0x20
    CODE = 0x40
    DATA = 0x80
    PORT = 0x100
    REGISTER = 0x200
    LIST = 0x400
    FLAG = 0x800
    TEXT = 0x1000
    ADDRESS = 0x2000
    SCALAR = 0x4000
    BIT = 0x8000
    BYTE = 0x10000
    WORD = 0x20000
    QUADWORD = 0x40000
    SIGNED = 0x80000
    FLOAT = 0x100000
    COP = 0x200000
    DYNAMIC = 0x400000


class GhidraOperand(Operand):

    def __init__(self, ghidra: GhidraFlatAPI, instruction: GhidraInstruction, index: int):
        super().__init__(instruction)
        self._ghidra = ghidra
        # Ghidra doesn't necessarily have an "Operand" type.
        # Characteristics are pulled from the originating Instruction object.
        self._instruction = instruction._instruction
        self._index = index
        # TODO: Ignore validation in interest of speed?
        if index >= self._instruction.getNumOperands():
            raise NotExistError(f"The instruction at {hex(self.address)} as no operand at {index}")

    @property
    def address(self) -> int:
        return self._instruction.getAddress().getOffset()

    @property
    def index(self) -> int:
        return self._index

    # TODO: switch all these to a @cached_property
    @property
    def text(self) -> str:
        # TODO: For pointers, the text represented is the address and not the name as seen
        #   in the GUI.
        #   Figure out how to get a "OperandFieldLocation" object so we can
        #   call .getOperandRepresentation() and get the real representation.
        return str(self._instruction.getDefaultOperandRepresentation(self.index))

    @property
    def type(self) -> OperandType:
        op_type = GhidraOperandType(self._instruction.getOperandType(self.index))

        if GhidraOperandType.DYNAMIC in op_type:
            return OperandType.phrase

        if GhidraOperandType.REGISTER in op_type:
            # If also an ADDRESS, we need to check if there is an extra offset.
            # In which case it should be a phrase instead.
            # e.g. [sp,#local_4]!
            if GhidraOperandType.ADDRESS in op_type and len(self._instruction.getOpObjects(self.index)) > 1:
                return OperandType.phrase
            # In some cases, the operand will just be reported as a register even though it should
            # be interpreted as a dynamic register.
            # Check this by looking for brackets in the text.
            # e.g. the second operand should be seen as a phrase: LEA  ESP=>local_150,[ESP]
            elif (text := self.text) and "[" in text and "]" in text:
                return OperandType.phrase
            else:
                return OperandType.register

        if GhidraOperandType.ADDRESS in op_type:
            if GhidraOperandType.CODE in op_type:
                return OperandType.code
            elif GhidraOperandType.DATA in op_type:
                return OperandType.memory

        # TODO: It doesn't seem like Ghidra ever uses IMMEDIATE.
        #   So we are ignoring it to see if it ever shows up in an error log.
        if GhidraOperandType.SCALAR in op_type:
            return OperandType.immediate

        raise TypeError(f"Unexpected Ghidra OperandType {op_type} for {self.text}")

    @property
    def value(self) -> OperandValue:
        ops = self._instruction.getOpObjects(self.index)

        if not ops:
            # Some instructions return a string instead of an int for immediate values
            # e.g SAR EAX, 1
            if self.text.isdigit():
                return GhidraImmediate(int(self.text))
            else:
                raise ValueError(f"Unknown operand type: {self!r}")

        from ghidra.program.model.lang import Register
        from ghidra.program.model.address import GenericAddress
        from ghidra.program.model.scalar import Scalar

        op_types = [op.getClass() for op in ops]

        # EAX
        if op_types == [Register]:
            # A single register can be a memory access (phrase).
            # e.g. dword ptr [EAX]
            reg = GhidraRegister(ops[0])
            if self.type == OperandType.phrase:
                return GhidraPhrase(base=reg)
            else:
                return reg

        # 0x11
        elif op_types == [Scalar]:
            if self.type == OperandType.memory:
                return GhidraMemoryReference(ops[0].getValue())
            else:
                return GhidraImmediate(ops[0].getValue())

        # LAB_1000101c
        elif op_types == [GenericAddress]:
            return GhidraMemoryReference(ops[0].getOffset())

        # [EBP + 0x8]
        elif op_types == [Register, Scalar]:
            # Ghidra will also have this pattern for registers with a shift.
            # Account for this by checking type.
            if self.type == OperandType.register:
                return GhidraRegister(ops[0])
            else:
                return GhidraPhrase(
                    base=GhidraRegister(ops[0]),
                    offset=ops[1].getSignedValue(),
                )

        # [ECX + EDX*0x1]
        elif op_types == [Register, Register, Scalar]:
            return GhidraPhrase(
                base=GhidraRegister(ops[0]),
                index=GhidraRegister(ops[1]),
                scale=ops[2].getValue(),
            )

        # [ECX + EDX*0x1 + 0xf]
        elif op_types == [Register, Register, Scalar, Scalar]:
            return GhidraPhrase(
                base=GhidraRegister(ops[0]),
                index=GhidraRegister(ops[1]),
                scale=ops[2].getValue(),
                offset=ops[3].getSignedValue(),
            )

        # [r3,r2]
        # FS:[EAX]
        elif op_types == [Register, Register] and self.type != OperandType.register_list:
            return GhidraPhrase(
                base=GhidraRegister(ops[0]),
                offset=GhidraRegister(ops[1]),
            )

        # sp!,{r11 lr}
        elif all(op_type == Register for op_type in op_types):
            return GhidraRegisterList([GhidraRegister(op) for op in ops])

        # TODO: Perhaps "Phrase" should just be part of "MemoryReference"?
        # [EAX*0x4 + DAT_1000b380]
        # dword_1000B380[eax*4]
        elif op_types == [Register, Scalar, Scalar]:
            return GhidraPhrase(
                index=GhidraRegister(ops[0]),
                scale=ops[1].getValue(),
                offset=ops[2].getValue(),
            )

        raise ValueError(f"Unknown operand types: {op_types!r}")

    def _get_referenced_data_size(self, text: str) -> int:
        """
        If operand text is in a "* ptr [..]" format pull the data type name and use that to get the true size.
        """
        data_type_name = text.split()[0]
        if data_type_name == "xmmword":  # xmmword isn't an actual data type.
            return 16
        manager = self._ghidra._program.getDataTypeManager()
        data_type = manager.getDataType(f"/{data_type_name}")
        if not data_type:
            # If we fail to get the data type, try again using the builtins.
            from ghidra.program.model.data import BuiltInDataTypeManager
            manager = BuiltInDataTypeManager.getDataTypeManager()
            data_type = manager.getDataType(f"/{data_type_name}")
            if not data_type:
                raise TypeError(f"Failed to determine referenced data type for operand {self.text}")
        return data_type.getLength()

    @property
    def width(self) -> int:
        op_type = self.type

        if op_type == OperandType.register:
            # We can't call getRegister() here because Ghidra treats registers
            # with shifts to have 2 op objects [Register, Scalar], making
            # getRegister() return None.
            reg = self.value
            return reg.bit_width // 8

        elif op_type in (OperandType.immediate, OperandType.memory, OperandType.code):
            scalar = self._instruction.getScalar(self.index)
            if scalar:
                return scalar.bitLength() // 8

            # We may have a memory address which is a pointer to a standard data type.
            # Pull out the data type's size.
            if op_type == OperandType.memory:
                text = self.text
                if "ptr" in text:
                    return self._get_referenced_data_size(text)

            # Getting standard size of an address.
            addr = self._instruction.getAddress()
            if addr:
                return addr.getSize() // 8

        elif op_type == OperandType.phrase:
            # First determine if operand text is in a "* ptr [..]" format.
            # If so, pull the data type name and use that to get true size.
            # TODO: Figure out if there is a more sane way to do this.
            text = self.text
            if "ptr" in text:
                return self._get_referenced_data_size(text)
            else:
                value = self.value
                base_reg = value.base
                # Account for FS/GS pointers.
                if base_reg.name == "fs":
                    return 4
                elif base_reg.name == "gs":
                    return 8
                else:
                    return base_reg.bit_width // 8

        raise TypeError(f"Unable to get size for operand {self.text} with type: {op_type!r}")

    @property
    def variable(self) -> Optional[GhidraVariable]:
        for ref in self._ghidra._flatapi.getReferencesFrom(self._instruction.getAddress()):
            if ref.isOperandReference() and ref.getOperandIndex() == self.index:
                if ref.isStackReference():
                    stack_offset = ref.getStackOffset()
                    function = self._ghidra.get_function(self.address)
                    stack_frame = function.stack_frame
                    try:
                        return stack_frame[stack_offset]
                    except KeyError:
                        continue
                else:
                    data = self._ghidra._listing.getDataAt(ref.getToAddress())
                    if data:
                        return GhidraGlobalVariable(self._ghidra, data)


class GhidraARMOperand(GhidraOperand, ARMOperand):

    @property
    def type(self) -> OperandType:
        op_type = GhidraOperandType(self._instruction.getOperandType(self.index))

        # If we have a shift in the operand, then this should actually be a
        # register type.
        # Ghidra lazily just calls this type a pure "DYNAMIC".
        if op_type == GhidraOperandType.DYNAMIC:
            text = self.text
            if "[" not in text and any(shift_op in text for shift_op in [
                "asr", "lsl", "lsr", "ror", "rrx", "msl",
                "uxtb", "uxth", "uxtw", "uxtx",
                "sxtb", "sxth", "sxtw", "sxtx",
            ]):
                # TODO: Should we have a shifted_register operand type?
                return OperandType.register

            # If we have {} in the operand text then it is a register list.
            if "{" in text:
                return OperandType.register_list

        # Ghidra has trouble telling the difference between a [0x1234] in ARM vs
        # a 0x1234 in x86. Both are considered as SCALAR + ADDRESS.
        # While technically true, it makes it difficult to tell if we are suppose to
        # dereference it when accessing the operand value.
        # In ARM, if we have a scalar with an address we should treat it as memory.
        # In x86, the base class will treat this as an immediate.
        if op_type == GhidraOperandType.SCALAR | GhidraOperandType.ADDRESS:
            return OperandType.memory

        return super().type

    @property
    def width(self) -> int:
        """
        For ARM, we need to look at the instruction mnemonic to determine the
        predetermined size.
        """
        op_type = self.type

        # Account for size suffix in instruction when pulling phrases.
        if op_type == OperandType.phrase:
            mnemonic = self.instruction.mnemonic
            if len(mnemonic) > 1:
                if mnemonic.endswith("b"):
                    return 1
                elif mnemonic.endswith("h"):
                    return 2

        return super().width


class Ghidrax86Operand(GhidraOperand, x86Operand):
    ...
