
import pytest

import dragodis


# TODO: Generalize the testing of .text since the actual string could change lot based
#    on options set in the disassembler.
from dragodis import FlowType
from dragodis.interface.instruction import ARMConditionCode


@pytest.mark.parametrize("address,mnemonic,text", [
    (0x401000, "push", {
        "ida": "push    ebp",
        "ghidra": "PUSH EBP",
    }),
    (0x401003, "mov", {
        "ida": "mov     eax, [ebp+arg_0]",
        "ghidra": "MOV EAX,dword ptr [EBP + 0x8]",
    })
])
def test_basic(disassembler, address, mnemonic, text):
    text = text[disassembler.name.lower()]
    instruction = disassembler.get_instruction(address)

    assert instruction.address == address
    assert instruction.mnemonic == mnemonic
    assert instruction.text == text


@pytest.mark.parametrize("address,num_operands", [
    (0x401030, 1),
    (0x401031, 2),
    (0x401142, 0),
    (0x40655e, 1),  # Hidden operand?
    (0x406623, 1),
])
def test_operands(disassembler, address, num_operands):
    instruction = disassembler.get_instruction(address)
    operands = instruction.operands
    assert len(operands) == num_operands
    for index, operand in enumerate(operands):
        assert operand.address == address
        assert operand.index == index


# TODO: Instead having these is_*() type functions, we should probably have
#   an "InstructionType" or "FlowType" that tells the user what type of flow the function
#    has?
@pytest.mark.parametrize("address,flow_type", [
    (0x401003, FlowType.fall_through),
    (0x40103a, FlowType.call),
    (0x40100b, FlowType.conditional_jump),
    (0x401027, FlowType.unconditional_jump),
    (0x40102a, FlowType.terminal),
])
def test_flow_type(disassembler, address, flow_type):
    instruction = disassembler.get_instruction(address)
    assert instruction.flow_type == flow_type


@pytest.mark.parametrize("address,root_mnem", [
    (0x40100D, "movsx"),
    # original has "rep movsd" or "MOVSD.REP"
    # NOTE: not requiring the "d" to be removed since that is not possible for Ghidra to detect.
    (0x405c5a, ("movsd", "movs")),
])
def test_root_mnemonic_x86(disassembler, address, root_mnem):
    instruction = disassembler.get_instruction(address)
    if isinstance(root_mnem, tuple):
        assert instruction.root_mnemonic in root_mnem
    else:
        assert instruction.root_mnemonic == root_mnem


@pytest.mark.parametrize("address,root_mnem", [
    (0x10444, "b"),  # from "bne"
    (0x10424, "ldr"),  # from "ldrb"
])
def test_root_mnemonic_arm(disassembler, address, root_mnem):
    instruction = disassembler.get_instruction(address)
    assert instruction.root_mnemonic == root_mnem


@pytest.mark.parametrize("address,rep", [
    (0x4047aa, "rep"),  # rep movsd
    (0x408590, "rep"),  # rep stosd
    (0x40858a, None),   # mov
])
def test_rep_x86(disassembler, address, rep):
    instruction = disassembler.get_instruction(address)
    assert instruction.rep == rep


@pytest.mark.parametrize("address,condition_code", [
    (0x106cc, ARMConditionCode.NE),  # bne
    (0x103e0, ARMConditionCode.NE),  # ldmiane  (popne for IDA)
    (0x103b0, ARMConditionCode.EQ),  # bxeq
    (0x1039c, ARMConditionCode.AL),  # ldr
])
def test_condition_codes_arm(disassembler, address, condition_code):
    instruction = disassembler.get_instruction(address)
    assert instruction.condition_code == condition_code


@pytest.mark.parametrize("address,writeback,pre_indexed,post_indexed", [
    (0x1069C, False, False, False),  # MOV     R9, R2
    (0x106bc, True, False, True),    # LDR     R3, [R5],#4
    (0x102D4, True, True, False),    # LDR     PC, [LR,#8]!
    # TODO: Figure this one out.
    (0x103fc, True, True, False),    # PUSH    {R11}         / str     r11,[sp,#local_4]!
    (0x102C8, True, True, False),    # PUSH    {LR}          / str        lr,[sp,#-0x4]!
    (0x106d0, True, True, False),    # POP     {R4-R10,PC}   / ldmia      sp!,{r4 r5 r6 r7 r8 r9 r10 pc}])
])
def test_writeback_arm(disassembler, address, writeback, pre_indexed, post_indexed):
    instruction = disassembler.get_instruction(address)
    assert instruction.writeback == writeback
    assert instruction.pre_indexed == pre_indexed
    assert instruction.post_indexed == post_indexed


@pytest.mark.parametrize("address,stack_depth,stack_delta", [
    (0x401030, 0, -4),  # beginning of function
    (0x401031, -4, 0),
    (0x401033, -4, -4),
    (0x401035, -8, -4),
    (0x40103a, -0xc, 0),
    (0x40103f, -0xc, 8),
    (0x401042, -4, -4),
    (0x401142, 0, 0),   # end of function
])
def test_stack_depth_delta(disassembler, address, stack_depth, stack_delta):
    instruction = disassembler.get_instruction(address)
    assert instruction.stack_depth == stack_depth
    assert instruction.stack_delta == stack_delta
