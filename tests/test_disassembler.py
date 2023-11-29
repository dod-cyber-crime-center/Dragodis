
import pathlib
import shutil

import pytest

import dragodis


def test_teleport_ida(disassembler):
    # Test basic
    @disassembler.teleport
    def teleported(addr):
        import idc
        return idc.get_strlit_contents(addr)
    assert teleported(0x40C000) == b"Idmmn!Vnsme "

    # Test disassembler gets converted to local version.
    @disassembler.teleport
    def teleported(dis):
        from dragodis.ida.disassembler import IDALocalDisassembler
        return isinstance(dis, IDALocalDisassembler)
    assert teleported(disassembler)


@pytest.mark.parametrize("backend", ["ida", "ghidra"])
def test_shellcode_x86(shared_datadir, backend):
    input_path = shared_datadir / "strings_x86 .text[00401000,0040102a].bin"

    try:
        with dragodis.open_program(str(input_path), backend, processor=dragodis.PROCESSOR_X86) as dis:
            assert dis.processor_name == "x86"
            insn = dis.get_instruction(0x0d)
            assert insn.mnemonic == "movsx"
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))


@pytest.mark.parametrize("backend", ["ida", "ghidra"])
def test_shellcode_arm(shared_datadir, backend):
    input_path = shared_datadir / "strings_arm .text[000103fc,0001045b].bin"

    try:
        with dragodis.open_program(str(input_path), backend, processor=dragodis.PROCESSOR_ARM) as dis:
            assert dis.processor_name == "ARM"
            # Need to manually define as code in IDA.
            if backend == "ida":
                dis._ida_ua.create_insn(0x14)
            insn = dis.get_instruction(0x14)
            assert insn.mnemonic == "strb"
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))
