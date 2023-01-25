import pytest

import dragodis
from dragodis import CommentType
from dragodis import interface


def test_disassembler_info_ida_all(disassembler):
    assert disassembler.name == "IDA"


def test_disassembler_info_ghidra_all(disassembler):
    assert disassembler.name == "Ghidra"


def test_processor_info(disassembler):
    assert disassembler.bit_size == 32
    assert disassembler.processor_name == "x86"
    assert disassembler.compiler_name in ("Visual C++", "visualstudio:unknown")
    assert disassembler.is_big_endian == False


def test_processor_info_arm(disassembler):
    assert disassembler.bit_size == 32
    assert disassembler.processor_name == "ARM"
    assert disassembler.compiler_name in ("GNU C++", "unknown")  # TODO: Ghidra fails to figure this one out.
    assert disassembler.is_big_endian == False


def test_addressing_ida(disassembler):
    assert disassembler.min_address == 0x401000
    assert disassembler.max_address == 0x40f000


def test_addressing_ghidra(disassembler):
    assert disassembler.min_address == 0x400000
    # Ghidra 10.2.* includes a new "tdb" memory block which increases the max address size.
    # https://github.com/NationalSecurityAgency/ghidra/issues/4790
    assert disassembler.max_address in (0x40ed47, 0xffdfffff)


def test_entry_point_x86(disassembler):
    assert disassembler.entry_point == 0x4014e0


def test_entry_point_arm(disassembler):
    assert disassembler.entry_point == 0x1030c


def test_base_address_x86(disassembler):
    assert disassembler.base_address == 0x400000


def test_base_address_arm(disassembler):
    assert disassembler.base_address == 0x10000


def test_file_offset(disassembler):
    assert disassembler.get_file_offset(0x4063b7) == 0x57b7
    assert disassembler.get_virtual_address(0x57b7) == 0x4063b7
    assert disassembler.get_file_offset(0x40c000) == 0xae00
    assert disassembler.get_virtual_address(0xae00) == 0x40c000
    with pytest.raises(dragodis.NotExistError):
        disassembler.get_file_offset(0x1)
    with pytest.raises(dragodis.NotExistError):
        disassembler.get_virtual_address(0xc001)


def test_is_loaded(disassembler):
    assert disassembler.is_loaded(0x4063b7)
    assert not disassembler.is_loaded(0x117f7d8)


def test_lines(disassembler):
    # Test getting a line
    line = disassembler.get_line(0x40116A)
    assert line
    assert line.address == 0x40116A

    # Test code section
    expected = [
        0x401003, 0x401006, 0x401009, 0x40100B, 0x40100D, 0x401011, 0x401014,
        0x401017, 0x401019, 0x40101C, 0x40101E, 0x401021, 0x401024, 0x401027,
    ]
    assert [line.address for line in disassembler.lines(start=0x401003, end=0x401029)] == expected
    assert list(disassembler.line_addresses(start=0x401003, end=0x401029)) == expected

    # Test data section
    if disassembler.name.lower() == "ida":
        expected = [
            0x40c000,
            0x40c00d,
            0x40c010,
            0x40c02a,
            0x40c02c,
            0x40c059,
            0x40c05c,
            0x40c080,
            0x40c0a0,
            0x40c0c3,
        ]
    # Ghidra doesn't have the concept of alignment bytes and instead treats them as individual
    # undefined bytes.
    elif disassembler.name.lower() == "ghidra":
        expected = [
            0x40c000,
            *range(0x40c00d, 0x40c010),
            0x40c010,
            *range(0x40c02a, 0x40c02c),
            0x40c02c,
            *range(0x40c059, 0x40c05c),
            0x40c05c,
            0x40c080,
            0x40c0a0,
            *range(0x40c0c3, 0x40c0e8),
        ]

    assert [line.address for line in disassembler.lines(start=0x40C000, end=0x40C0E8)] == expected
    assert list(disassembler.line_addresses(start=0x40C000, end=0x40C0E8)) == expected


def test_references(disassembler):
    refs = list(disassembler.references_to(0x40c15c))
    assert len(refs) == 2
    assert all(ref.to_address == 0x40c15c for ref in refs)
    assert sorted(ref.from_address for ref in refs) == [0x4010f8, 0x401242]

    refs = list(disassembler.references_from(0x401242))
    assert len(refs) == 1
    assert refs[0].from_address == 0x401242
    assert refs[0].to_address == 0x40c15c


# # TODO: Add test for duplicate name
# # TODO: Figure out how to manage the resetting of data addresses.
# #   - when I set aTsudfs it will actually set to asc_40C130
# #   - Is there a way to control the way IDA names strings? (or get the original string name?)
# #       - (Remember, we can check the LineType!!!!)
#
# # TODO: Set this unit test to be generic from the dissassembler.
# @pytest.mark.parametrize(
#     "addr,expected",
#     [
#         # Function address
#         (0x401030, {"ida": "sub_401030", "ghidra": "FUN_00401030"}),
#         # Data address
#         (0x40c130, {"ida": ("aTsudfs", "asc_40C130"), "ghidra": "s_tSUdFS_0040c130"}),
#         # No original name (in the middle of unknown data)
#         (0x40c14f, {"ida": None, "ghidra": None}),
#     ]
# )
# def test_name(disassembler, addr, expected):
#     expected_names = expected[disassembler.name.lower()]
#     if not isinstance(expected_names, tuple):
#         expected_names = (expected_names,)
#
#     assert disassembler.get_name(addr) in expected_names
#     disassembler.set_name(addr, "test_name")
#     assert disassembler.get_name(addr) == "test_name"
#     # Setting name to None or empty string should reset it.
#     disassembler.set_name(addr, None)
#     assert disassembler.get_name(addr) in expected_names


@pytest.mark.parametrize("address,is_defined", [
    (0x401030, True),   # function address
    (0x40c130, True),   # data address
    (0x40c14f, False),  # undefined address
])
def test_name(disassembler, address, is_defined):
    # Different disassemblers are going to give different names, so we aren't
    # going to test what those names actually are.
    original_name = disassembler.get_name(address)
    if is_defined:
        assert original_name and isinstance(original_name, str)
    else:
        assert original_name is None

    disassembler.set_name(address, "test_name")
    assert disassembler.get_name(address) == "test_name"

    # Setting name to None or empty string should reset it.
    disassembler.set_name(address, None)
    assert disassembler.get_name(address) == original_name

    # Test duplicate name generation.

    # TODO: Test duplicate name generation.


@pytest.mark.parametrize("address", [
    0x401030,  # function address
    0x401035,  # code address
    0x40c130,  # data address
    0x40c14f,  # undefined address
])
@pytest.mark.parametrize("comment,comment_type", [
    ("eol comment", CommentType.eol),
    ("This is an\nanterior comment", CommentType.anterior),
    ("This is a\nposterior comment", CommentType.posterior),
    ("This is a\nplate comment", CommentType.plate),
    ("repeatable comment", CommentType.repeatable),
], ids=["eol", "anterior", "posterior", "plate", "repeatable"])
def test_comment(disassembler, address, comment, comment_type):
    # Test setting comment
    assert disassembler.get_comment(address, comment_type=comment_type) is None
    disassembler.set_comment(address, comment, comment_type=comment_type)
    assert disassembler.get_comment(address, comment_type=comment_type) == comment
    # Test resetting comment
    disassembler.set_comment(address, None, comment_type=comment_type)
    assert disassembler.get_comment(address, comment_type=comment_type) is None


def test_get_function(disassembler):
    # Test getting a Function object
    func = disassembler.get_function(0x401030)
    assert func
    assert isinstance(func, interface.Function)
    assert func.start == 0x401030

    # Test getting same function not at entrypoint
    func = disassembler.get_function(0x401035)
    assert func
    assert isinstance(func, interface.Function)
    assert func.start == 0x401030

    # Test invalid function
    with pytest.raises(dragodis.NotExistError):
        disassembler.get_function(0x40c130)

    # Test getting multiple functions
    # Number of functions are different for each disassembler, but we should
    # get at least 200.
    funcs = list(disassembler.functions())
    assert len(funcs) > 200


def test_get_function_by_name(disassembler):
    func = disassembler.get_function_by_name("printf")
    assert func
    assert func.start == 0x4012a0
    assert "printf" in func.name


def test_functions(disassembler):
    # Test getting all functions
    funcs = list(disassembler.functions())
    # NOTE: Exact number of functions is highly dependent on the disassembler and
    # it's default analysis settings and could change in future versions.
    # Therefore, just test that we have decent amount of functions and some expected functions are
    # there.
    assert len(funcs) >= 200  # IDA had 220 and Ghidra had 226
    func_names = [func.name for func in funcs]
    func_addrs = [func.start for func in funcs]
    assert "_printf" in func_names
    assert 0x401030 in func_addrs

    # TODO: more tests

    # Test getting functions in subsections
    funcs = list(disassembler.functions(start=0x4003fa, end=0x40129f))
    assert len(funcs) == 3
    assert sorted(func.start for func in funcs) == [0x401000, 0x401030, 0x401150]

    # TODO: Should we be including the function where end is in the middle of the function?
    funcs = list(disassembler.functions(end=0x401049))
    assert len(funcs) == 2
    assert sorted(func.start for func in funcs) == [0x401000, 0x401030]

    # Start at almost the end so we only produce the "RtlUnwind" function.
    # (Using any earlier address will already produce inconsistent results with which functions exist)
    funcs = list(disassembler.functions(start=0x409b0c))
    assert len(funcs) == 1
    assert funcs[0].name == "RtlUnwind"
    assert funcs[0].start == 0x409b0e


def test_get_instruction(disassembler):
    addr = 0x401035

    # Test getting instruction at start.
    insn = disassembler.get_instruction(addr)
    assert insn
    assert insn.address == addr

    # Test getting instruction with address within.
    insn = disassembler.get_instruction(addr + 2)
    assert insn
    assert insn.address == addr

    # Test invalid instruction.
    with pytest.raises(dragodis.NotExistError):
        disassembler.get_instruction(0x40c130)


def test_get_mnemonic(disassembler):
    assert disassembler.get_mnemonic(0x401035) == "push"
    assert disassembler.get_mnemonic(0x40103f) == "add"
    assert disassembler.get_mnemonic(0x4010a3) == "call"

    # Test non-instruction
    with pytest.raises(dragodis.NotExistError):
        disassembler.get_mnemonic(0x40c130)


def test_get_operand(disassembler):
    operand = disassembler.get_operand(0x401042, 0)
    assert operand
    assert operand.address == 0x401042
    assert operand.index == 0


def test_get_operand_type(disassembler):
    operand = disassembler.get_operand(0x401042, 0)
    assert disassembler.get_operand_type(0x401042, 0) == operand.type


def test_get_operand_value(disassembler):
    operand = disassembler.get_operand(0x401042, 0)
    assert disassembler.get_operand_value(0x401042, 0) == operand.value


def test_get_byte(disassembler):
    # Code section
    assert disassembler.get_byte(0x401035) == 0x68
    assert disassembler.get_byte(0x401036) == 0x00

    # Data section
    assert disassembler.get_byte(0x40c000) == 0x49
    assert disassembler.get_byte(0x40c001) == 0x64


def test_get_bytes(disassembler):
    # Code section
    assert disassembler.get_bytes(0x401035, 2) == b"\x68\x00"

    # Data section
    assert disassembler.get_bytes(0x40c000, 2) == b"Id"


def test_find_bytes(disassembler):
    assert disassembler.find_bytes(b"\x83\xC4\x08\x33\xC0") == 0x401299
    assert disassembler.find_bytes(b"\xDE\xAD\xBE\xEF") == -1
    assert disassembler.find_bytes(b"\x83\xC4\x08\x33\xC0", start=disassembler.min_address) == 0x401299
    assert disassembler.find_bytes(b"\x83\xC4\x08\x33\xC0", start=0x4015A6) == -1
    assert disassembler.find_bytes(b"\x83\xC4\x08\x33\xC0", start=0x4015A6, reverse=True) == 0x401299
    assert disassembler.find_bytes(b"\x83\xC4\x08\x33\xC0", reverse=True) == 0x401299


# TODO: currently disabled.
# def test_get_string_bytes(disassembler):
#     # Code section
#     assert disassembler.get_string_bytes(0x401035) == b"\x68\x00"
#
#     # Data Section
#     assert disassembler.get_string_bytes(0x40c000) == b"Idmmn!Vnsme\x00"


def test_get_qword(disassembler):
    # Code section
    assert disassembler.get_qword(0x401035) == 0xffc1e80040c00068

    # Data section
    assert disassembler.get_qword(0x40c000) == 0x6e56216e6d6d6449


def test_get_dword(disassembler):
    # Code section
    assert disassembler.get_dword(0x401035) == 0x40c00068

    # Data section
    assert disassembler.get_dword(0x40c000) == 0x6d6d6449


def test_get_word(disassembler):
    # Code section
    assert disassembler.get_word(0x401035) == 0x68

    # Data section
    assert disassembler.get_word(0x40c000) == 0x6449
