
import pytest

import dragodis
from dragodis import LineType, CommentType, interface


@pytest.mark.parametrize("address,line_type,value,size,data", [
    (0x401003, LineType.code, None, 3, b"\x8b\x45\x08"),
    (0x40c0c4, LineType.undefined, 0x5c, 1, b"\x5c"),
    (0x40ec38, LineType.unloaded, None, 1, b""),
    (0x40c000, LineType.string, "Idmmn!Vnsme ", 13, b"Idmmn!Vnsme \x00"),
    (0x40b8bc, LineType.word, 0x186, 2, b"\x86\x01"),
    (0x40b8be, LineType.string, "GetCommandLineA", 16, b"GetCommandLineA\x00"),
    (0x40b784, LineType.dword, 0xb7ac, 4, b"\xac\xb7\x00\x00"),
    (0x40a838, LineType.string16, "KERNEL32.DLL", 26,
        b"K\x00E\x00R\x00N\x00E\x00L\x003\x002\x00.\x00D\x00L\x00L\x00\x00\x00"),
])
def test_basic(disassembler, address, line_type, value, size, data):
    """
    Basic test for getting line type, value, size, and data
    """
    line = disassembler.get_line(address)
    assert line.address == address
    assert line.type == line_type
    assert line.size == size
    assert line.data == data
    if line_type == LineType.code:
        assert isinstance(line.value, interface.Instruction)
    else:
        assert line.value == value


def test_align_type_and_value(disassembler):
    """
    For alignment bytes, the disassembler may mark it as either LineType.undefined
    or LineType.align depending on the disassembler and analysis options.
    Therefore, for this special case test both possibilities.

    For IDA, alignment bytes are detected by default.
    For Ghidra, alignment bytes are not detected by default.
        The "Condense Filler Bytes" analysis options must be enabled.
    """
    line = disassembler.get_line(0x40102b)
    assert line.type in (LineType.align, LineType.undefined)

    if line.type == LineType.undefined:
        assert line.size == 1
        assert line.value == 0xCC
        # If not already alignment, test setting alignment to prove
        # the disassembler can properly handle alignment bytes.
        line.type = LineType.align

    assert line.size == 5
    assert line.data == b"\xCC" * 5
    assert line.value == b"\xCC" * 5


@pytest.mark.parametrize("address,new_type,value", [
    (0x40c0f0, LineType.undefined, 0x43),
    # FIXME: Inconsistencies in precision between disassemblers.
    #   Determine appropriate standard for handling floats.
    pytest.param(0x40c0f0, LineType.float, 7.157251582566349e+22, marks=pytest.mark.xfail),
    (0x40c0f0, LineType.dword, 0x65727f43),
    (0x40c0f0, LineType.word, 0x7f43),
    # NOTE: Disassembler will end up pulling a different amount of bytes based on disassembler.
    (0x40c000, LineType.string, "Idmmn!Vnsme "),
])
def test_setting_type(disassembler, address, new_type, value):
    """
    Tests setting line to a new type and it's effects on the value.
    """
    line = disassembler.get_line(address)
    orig_value = line.value
    orig_type = line.type

    # Test setting a new type and how it affects the value.
    line.type = new_type
    assert line.type == new_type
    assert line.value == value

    # Reset
    line.type = orig_type
    assert line.type == orig_type
    assert line.value == orig_value


@pytest.mark.parametrize("address,data,value", [
    # (0x401003, None),    # TODO: Add setting new instruction
    (0x40c0c4, b"\xff", 0xff),  # undefined
    (0x40ec38, b"", None),  # unloaded
    (0x40c000, b"hello\x00", "hello"),  # string
    (0x40b8bc, b"\x01\x00", 0x1),  # word
    (0x40b8be, b"hello\x00", "hello"),  # string
    (0x40b784, b"\xef\xcd\xab\x00", 0xabcdef),  # dword
    (0x40a838, b"h\x00e\x00l\x00l\x00o\x00\x00\x00", "hello"),  # string16
])
def test_setting_data_and_value(disassembler, address, data, value):
    """
    Tests setting line to a new value or data and its affect on the other.
    Also insures the line type doesn't get changed.
    """
    line = disassembler.get_line(address)
    orig_value = line.value
    orig_data = line.data
    orig_type = line.type

    # Test setting the value
    line.value = value
    assert line.value == value
    assert line.data == data
    assert line.type == orig_type
    line.value = orig_value
    assert line.value == orig_value
    assert line.data == orig_data
    assert line.type == orig_type

    # Test setting the data
    line.data = data
    assert line.data == data
    assert line.value == value
    assert line.type == orig_type
    line.data = orig_data
    assert line.data == orig_data
    assert line.value == orig_value
    assert line.type == orig_type


def test_setting_value_with_new_type(disassembler):
    """
    Tests that setting a value could trigger a change in type
    based on the type of value set.
    """
    line = disassembler.get_line(0x40c000)
    orig_value = line.value
    orig_data = line.data

    # Originally a string
    assert line.type == LineType.string
    assert isinstance(orig_value, str)

    # Setting value with an int, should change it to a dword.
    line.value = 0xabcd
    assert line.type == LineType.dword
    assert line.value == 0xabcd
    assert line.data == b"\xcd\xab\x00\x00"

    # Setting value as a float, should change it to a float.
    line.value = 4.5
    assert line.type == LineType.float
    assert line.value == 4.5

    # Setting value as single byte sets it to byte type.
    line.value = b"\x01"
    assert line.type == LineType.byte
    assert line.value == 0x1
    assert line.data == b"\x01"

    # Setting back to original string, should put it back as a string.
    line.value = orig_value
    assert line.type == LineType.string
    assert line.value == orig_value
    assert line.data == orig_data


def test_name(disassembler):
    """
    Tests getting and seting a name on a line.
    """
    line = disassembler.get_line(0x40c0c4)
    orig_name = line.name
    assert orig_name
    line.name = "new_name"
    assert line.name == "new_name"
    line.name = None
    assert line.name == orig_name


def test_prev_next(disassembler):
    """
    Tests getting previous and next line.
    """
    # Test getting next line of instruction.
    line = disassembler.get_line(0x401035)
    assert line.prev.address == 0x401033
    assert line.next.address == 0x40103a

    # Test getting next line of undefined data.
    line = disassembler.get_line(0x40c0c4)
    assert line.prev.address == 0x40c0c3
    # TODO: Look into standardizing this.
    # IDA treats all undefined data in chunks.
    if disassembler.name.lower() == "ida":
        assert line.next.address == 0x40c114  # Jumps to next defined item.
    # Ghidra treats each individual byte of undefined data as a separate line.
    elif disassembler.name.lower() == "ghidra":
        assert line.next.address == 0x40c0c5  # Just the next byte
    else:
        pytest.fail(f"Update test for disassembler: {disassembler.name}")


def test_instruction(disassembler):
    line = disassembler.get_line(0x401035)
    assert line.instruction
    assert isinstance(line.instruction, interface.Instruction)
    line = disassembler.get_line(0x40c0c4)
    assert line.instruction is None


@pytest.mark.parametrize("address", [
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
    """
    Tests getting and setting comments
    NOTE: This is more or less a copy of the test in test_flat.py
    """
    # Test setting comment
    line = disassembler.get_line(address)
    assert line.get_comment(comment_type=comment_type) is None
    line.set_comment(comment, comment_type=comment_type)
    assert line.get_comment(comment_type=comment_type) == comment
    # Test resetting comment
    line.set_comment(None, comment_type=comment_type)
    assert line.get_comment(comment_type=comment_type) is None
