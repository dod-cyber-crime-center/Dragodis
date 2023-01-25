
import pytest

import dragodis
from dragodis import OperandType
from dragodis.interface import Register, Phrase, StackVariable, GlobalVariable, RegisterList
from dragodis.interface.types import ARMShiftType


def test_basic(disassembler):
    """
    Tests basic operand properties and general smoke test.
    """
    operand = disassembler.get_operand(0x401042, 0)
    assert operand
    assert operand.address == 0x401042
    assert operand.index == 0
    assert operand.type == OperandType.immediate
    assert operand.value == 2

    operand = disassembler.get_operand(0x40103f, 1)
    assert operand.address == 0x40103f
    assert operand.index == 1
    assert operand.type == OperandType.immediate
    assert operand.value == 8

    # Test invalid index
    with pytest.raises(dragodis.NotExistError):
        disassembler.get_operand(0x401042, 3)

    # Test non-instruction
    with pytest.raises(dragodis.NotExistError):
        disassembler.get_operand(0x40c130, 0)


def _test_operand(disassembler, address, index, text, width):
    """
    Tests core functionality of operand.
    """
    operand = disassembler.get_operand(address, index)
    assert operand.address == address
    assert operand.index == index
    assert operand.text == text
    assert str(operand) == text
    assert operand.width == width


@pytest.mark.parametrize("address,index,text,width", [
    (0x401042, 0, "2", 4),
    (0x40135f, 0, "cl", 1),
    (0x40103f, 0, "esp", 4),
    (0x401044, 0, "offset aVgqvQvpkleUkvj", 4),
    (0x40177a, 0, "byte ptr [esi+0Ch]", 1),
    (0x40177a, 1, "0", 1),  # 1 because the operand it goes into is 1
    (0x4012fe, 1, "[ebp+arg_4]", 4),
    (0x401006, 1, "byte ptr [eax]", 1),
    (0x401003, 1, "[ebp+arg_0]", 4),
])
def test_text_ida(disassembler, address, index, text, width):
    _test_operand(disassembler, address, index, text, width)


@pytest.mark.parametrize("address,index,text,width", [
    (0x401042, 0, "0x2", 4),
    (0x40135f, 0, "CL", 1),
    (0x40103f, 0, "ESP", 4),
    (0x401044, 0, "0x40c010", 4),
    (0x40177a, 0, "byte ptr [ESI + 0xc]", 1),
    (0x40177a, 1, "0x0", 1),  # 1 because the operand it goes into is 1
    (0x4012fe, 1, "[EBP + 0xc]", 4),
    (0x401006, 1, "byte ptr [EAX]", 1),
    (0x401003, 1, "dword ptr [EBP + 0x8]", 4),
])
def test_text_ghidra(disassembler, address, index, text, width):
    _test_operand(disassembler, address, index, text, width)


# TODO: Add more tests as we solve questions brought up in issue #12
def test_value_x86(disassembler):
    # push    2
    # PUSH    0x2
    immediate = disassembler.get_operand_value(0x401042, 0)
    assert immediate == 2
    assert int(immediate) == 2

    # add     esp, 8
    # ADD     ESP,0x8
    immediate = disassembler.get_operand_value(0x40103f, 1)
    assert immediate == 8
    assert int(immediate) == 8
    register = disassembler.get_operand_value(0x40103f, 0)
    assert register and isinstance(register, Register)
    assert register.name == "esp"
    assert register.bit_width == 32
    assert int(register) == -1

    # push    offset aVgqvQvpkleUkvj
    # PUSH    s_Vgqv"qvpkle"ukvj"ig{"2z20_0040c010
    address = disassembler.get_operand_value(0x401044, 0)
    assert address == 0x40c010
    assert int(address) == 0x40c010

    # lea     eax, [ebp+arg_4]
    # LEA     EAX=>Stack[0x8],[EBP + 0xc]
    phrase = disassembler.get_operand_value(0x4012fe, 1)
    assert phrase and isinstance(phrase, Phrase)
    assert phrase.offset == 0xc
    assert phrase.base.name == "ebp"
    assert int(phrase) == 0xc

    # call    sub_401000
    address = disassembler.get_operand_value(0x4010a3, 0)
    assert address == 0x401000
    assert int(address) == 0x401000

    # add     ecx, dword_40DC20[esi*4]
    # ADD     ECX,dword ptr [ESI*0x4 + DAT_0040dc20]
    phrase = disassembler.get_operand_value(0x401965, 1)
    assert phrase and isinstance(phrase, Phrase)
    assert phrase.base is None
    assert phrase.index.name == "esi"
    assert phrase.scale == 4
    assert phrase.offset == 0x40dc20
    assert int(phrase) == 0x40dc20


def test_value_arm(disassembler):
    # Second operand value should be a register type with a shift.
    # movs       r6,r6, asr #0x2
    operand = disassembler.get_operand(0x106A4, 1)
    assert operand.type == OperandType.register
    assert operand.shift == (ARMShiftType.ASR, 2)
    value = operand.value
    assert value and isinstance(value, Register)
    assert value.name == "r6"
    assert operand.width == 4
    assert int(value) == -1


def _test_phrase(disassembler, address, index, phrase):
    operand = disassembler.get_operand(address, index)
    assert operand.type == OperandType.phrase
    value = operand.value
    assert isinstance(value, Phrase)
    base, index, scale, offset = phrase

    if not base:
        assert value.base is None
    else:
        assert isinstance(value.base, Register)
        assert value.base.name == base

    if not index:
        assert value.index is None
    else:
        assert isinstance(value.index, Register)
        assert value.index.name == index

    assert value.scale == scale

    if isinstance(offset, str):
        assert isinstance(value.offset, Register)
        assert value.offset.name == offset
    else:
        assert value.offset == offset


@pytest.mark.parametrize("address,index,phrase", [
    (0x4012fe, 1, ("ebp", None, 1, 0xc)),  # [EBP + 0xc]
    (0x401313, 0, ("ebp", None, 1, -0x1c)),  # dword ptr [EBP + -0x1c]=>local_2
    # TODO: Not a valid phrase, its a register with width of 1
    # (0x401006, 0, ("eax", None, 1, 0)),  # byte ptr [EAX]
    (0x4013be, 0, ("eax", None, 1, 0x400018)),  # word ptr [EAX + 0x400018]
    (0x40154e, 0, ("edx", "eax", 1, 0)),  # dword ptr [EDX + EAX*0x1]
    # TODO: Figure out what GHidra is typing this and then get it to a phrase.
    (0x40156f, 1, (None, "eax", 4, 0x40dc20)),  # dword ptr [EAX*0x4 + DAT_0040dc20]
])
def test_phrase_x86(disassembler, address, index, phrase):
    _test_phrase(disassembler, address, index, phrase)


@pytest.mark.parametrize("address,index,phrase", [
    (0x10418, 1, ("r11", None, 1, -8)),     # [r11,#-0x8]=>local_c
    (0x102f0, 1, ("r12", None, 1, 0xd20)),  # [r12,#0xd20]!=>->__libc_start_main
    (0x10354, 1, ("r3", None, 1, "r2")),    # [r3,r2]=>->__gmon_start__
])
def test_phrase_arm(disassembler, address, index, phrase):
    _test_phrase(disassembler, address, index, phrase)


@pytest.mark.parametrize("address,index,names", [
    # PUSH    {R11,LR}
    # stmdb      sp!,{r11 lr}
    (0x1058C, 0, ["sp", "r11", "lr"]),
    # POP     {R4-R10,PC}
    # ldmia      sp!,{r4 r5 r6 r7 r8 r9 r10 pc}
    (0x106D0, 0, ["sp", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "pc"]),
])
def test_register_list_arm(disassembler, address, index, names):
    """
    Special tests for register list operands.
    """
    instruction = disassembler.get_instruction(address)

    # IDA interprets stmdb and ldmia instructions as "PUSH" and "POP"
    # with the first "sp" register implied.
    if instruction.mnemonic in ("push", "pop") and names[0] == "sp":
        names = names[1:]

    operand = instruction.operands[0]
    assert operand.type == OperandType.register_list
    reg_list = operand.value
    assert isinstance(reg_list, RegisterList)
    assert [reg.name for reg in reg_list] == names
    assert int(reg_list) == -1


@pytest.mark.parametrize("address,index,operand_type", [
    (0x401042, 0, OperandType.immediate),   # 2
    (0x40103f, 0, OperandType.register),    # esp
    (0x40103f, 1, OperandType.immediate),   # 8
    # Offsets are treated as immediate unless explicitly dereferenced by the instruction.
    (0x401044, 0, OperandType.immediate),   # offset aVgqvQvpkleUkv
    (0x4015D3, 1, OperandType.immediate),   # offset unk_40C4F8
    (0x40243C, 0, OperandType.memory),      # dword_40D19C  /  [DAT_0040d19c]
    (0x4012fe, 1, OperandType.phrase),      # [ebp+arg_4]
    (0x40156f, 1, OperandType.phrase),      # dword ptr [EAX*0x4 + DAT_0040dc20]
])
def test_type_x86(disassembler, address, index, operand_type):
    operand = disassembler.get_operand(address, index)
    assert operand.type == operand_type


@pytest.mark.parametrize("address,index,operand_type", [
    (0x106A4, 1, OperandType.register),       # r6, asr #0x2
    (0x1067C, 0, OperandType.register_list),  # sp!,{r4 r5 r6 r7 r8 r9 r10 lr}
    (0x10464, 1, OperandType.immediate),      # #1
    (0x10468, 1, OperandType.memory),         # =string01  /  [->string01]
    (0x10334, 0, OperandType.code),           # __libc_start_main
])
def test_type_arm(disassembler, address, index, operand_type):
    operand = disassembler.get_operand(address, index)
    assert operand.type == operand_type


@pytest.mark.parametrize("address,index,operand_type", [
    (0x103fc, 0, OperandType.register_list),  # {R11}
])
def test_type_ida_arm(disassembler, address, index, operand_type):
    operand = disassembler.get_operand(address, index)
    assert operand.type == operand_type


# TODO: Why is the operand being seen as a register_list?

@pytest.mark.parametrize("address,index,operand_type", [
    (0x103fc, 0, OperandType.register),  # r11
    (0x103fc, 1, OperandType.phrase),    # [sp,#local_4]!
])
def test_type_ghidra_arm(disassembler, address, index, operand_type):
    operand = disassembler.get_operand(address, index)
    assert operand.type == operand_type


@pytest.mark.parametrize("address,index,shift_type,shift_count", [
    (0x106A4, 1, ARMShiftType.ASR, 2),   # R6,ASR#2
    (0x103A4, 1, ARMShiftType.LSR, 31),  # R3,LSR#31
    (0x10698, 1, ARMShiftType.LSL, 0),   # R1  (no shift, default)
])
def test_shift_info_arm(disassembler, address, index, shift_type, shift_count):
    instruction = disassembler.get_instruction(address)
    operand = instruction.operands[index]
    assert operand.shift == (shift_type, shift_count)


def _test_variable(disassembler, address, index, name, size, data_type, location):
    instruction = disassembler.get_instruction(address)
    operand = instruction.operands[index]
    variable = operand.variable
    assert variable
    assert variable.name == name
    assert variable.size == size
    assert variable.data_type.name == data_type
    if isinstance(variable, GlobalVariable):
        assert variable.address == location
    elif isinstance(variable, StackVariable):
        assert variable.stack_offset == location
    else:
        pytest.fail(f"Unexpected variable type: {type(variable)}")


@pytest.mark.parametrize("address,index,name,size,data_type,location", [
    (0x40100d, 1, "arg_4", 1, "char", 8),
    (0x401024, 0, "arg_0", 4, "int", 4),
    (0x4058b4, 0, "lpProcName", 4, "lpcstr", -0x28),
    (0x4058b4, 1, "aGetlastactivep", 19, "char", 0x40a9a0),
    (0x4015a6, 0, "byte_40D1C8", 1, "byte", 0x40d1c8),
    (0x404096, 0, "LeaveCriticalSection", 4, "dword", 0x40A008),
    # TODO: Determine if we should support pointers to code as "variables".
    # (0x40103A, 0, "sub_401000", 4, "dword", 0x401000),
    # (0x40100b, 0, "loc_401029", 1, "byte", 0x401029),
])
def test_variable_ida(disassembler, address, index, name, size, data_type, location):
    _test_variable(disassembler, address, index, name, size, data_type, location)


@pytest.mark.parametrize("address,index,name,size,data_type,location", [
    (0x40100d, 1, "param_2", 1, "byte", 8),
    (0x401024, 0, "param_1", 4, "byte *", 4),
    (0x4058b4, 0, "local_28", 4, "undefined4", -0x28),
    (0x4058b4, 1, "s_GetLastActivePopup_0040a9a0", 19, "string", 0x40a9a0),
    (0x4015a6, 0, "DAT_0040d1c8", 1, "undefined", 0x40d1c8),
    (0x404096, 0, "PTR_LeaveCriticalSection_0040a008", 4, "pointer", 0x40A008),
    # (0x40103A, 0, "FUN_00401000", 4, "dword", 0x401000),
    # (0x40100b, 0, "LAB_00401029", 1, "byte", 0x401029),
])
def test_variable_ghidra(disassembler, address, index, name, size, data_type, location):
    _test_variable(disassembler, address, index, name, size, data_type, location)
