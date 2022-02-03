
import pytest


def _test_stack_frame(disassembler, address, variables):
    function = disassembler.get_function(address)
    stack_frame = function.stack_frame
    assert len(stack_frame) == len(variables)
    # First test iterating through members.
    actual_vars = [(var.stack_offset, var.name, var.data_type.name) for var in stack_frame]
    assert actual_vars == variables
    # Then test obtaining them through indexing.
    for stack_offset, name, data_type in variables:
        var = stack_frame[stack_offset]
        assert var.stack_offset == stack_offset
        assert var.name == name
        var = stack_frame[name]
        assert var.stack_offset == stack_offset
        assert var.name == name


@pytest.mark.parametrize("address,variables", [
    (0x401000, [
        (4, "arg_0", "int"),
        (8, "arg_4", "char"),
    ]),
    (0x4044F4, [
        (-0x14, "var_10", "int"),
        (-0xc, "var_8", "int"),
        (-8, "var_4", "char"),
    ])
])
def test_stack_frame_ida(disassembler, address, variables):
    _test_stack_frame(disassembler, address, variables)


@pytest.mark.parametrize("address,variables", [
    (0x103FC, [
        (-0xd, "var_9", "char"),
        (-0xc, "var_8", "int"),
        # IDA is missing variable at -4 since it interprets PUSH mnemonics instead of
        # explicitly defining the STR instruction.
        # e.g:  str  r11,[sp,#local_4]!
    ])
])
def test_stack_frame_arm_ida(disassembler, address, variables):
    _test_stack_frame(disassembler, address, variables)


@pytest.mark.parametrize("address,variables", [
    (0x401000, [
        (4, "param_1", "byte *"),
        (8, "param_2", "byte"),
    ]),
    (0x4044F4, [
        (-0x14, "local_14", "undefined4"),
        (-0xc, "local_c", "undefined4"),
        (-8, "local_8", "undefined1"),
        (4, "param_1", "int"),  # (Ghidra also thinks there is an argument)
    ])
])
def test_stack_frame_ghidra(disassembler, address, variables):
    _test_stack_frame(disassembler, address, variables)


@pytest.mark.parametrize("address,variables", [
    (0x103FC, [
        (-0xd, "local_d", "undefined1"),
        (-0xc, "local_c", "undefined4"),
        (-4, "local_4", "undefined4"),
    ])
])
def test_stack_frame_arm_ghidra(disassembler, address, variables):
    _test_stack_frame(disassembler, address, variables)
