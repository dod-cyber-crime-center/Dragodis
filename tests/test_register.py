
import pytest

from dragodis.interface import Register


@pytest.mark.parametrize("address,index,name,width", [
    (0x401001, 0, "ebp", 32),      # mov     ebp, esp
    (0x401009, 0, "ecx", 32),      # test    ecx, ecx
    (0x40101C, 1, "cl", 8),        # mov     [edx], cl
    (0x402F73, 0, "esi", 32),      # add     esi, ebx
])
def test_basic(disassembler, address, index, name, width):
    register = disassembler.get_operand_value(address, index)
    assert isinstance(register, Register)
    assert register.name == name
    assert register.bit_width == width


def test_get_register(disassembler):
    reg = disassembler.get_register("ecx")
    assert isinstance(reg, Register)
    assert reg.name == "ecx"
    assert reg.bit_width == 32


def test_equality(disassembler):
    # test    ecx, ecx
    ecx1 = disassembler.get_operand_value(0x401009, 0)
    ecx2 = disassembler.get_operand_value(0x401009, 1)
    assert ecx1 == ecx2

    # add     esi, ebx
    esi = disassembler.get_operand_value(0x402F73, 0)
    ebx = disassembler.get_operand_value(0x402F73, 1)
    assert esi != ebx

    # 0x401009: test    ecx, ecx
    # 0x40101C: mov     [edx], cl
    ecx = disassembler.get_operand_value(0x401009, 0)
    cl = disassembler.get_operand_value(0x40101C, 1)
    assert ecx != cl


@pytest.mark.parametrize("register,mask", [
    ("al", 0xFF),
    ("ah", 0xFF00),
    ("eax", 0xFFFFFFFF),
    ("eip", 0xFFFFFFFF),
    ("esp", 0xFFFFFFFF)
])
def test_mask(disassembler, register, mask):
    reg = disassembler.get_register(register)
    assert reg.mask == mask


@pytest.mark.parametrize("register,base", [
    ("al", "eax"),
    ("ah", "eax"),
    ("eax", "eax"),
    ("eip", "eip"),
    ("esp", "esp"),
    ("fs", "fs")
])
def test_base(disassembler, register, base):
    reg = disassembler.get_register(register)
    assert reg.base == disassembler.get_register(base)
