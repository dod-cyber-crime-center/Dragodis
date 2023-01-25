
import dragodis


def test_create_reference(disassembler):
    ref = disassembler.create_reference(0x401014, 0x40100d, dragodis.ReferenceType.code_jump)
    assert ref
    assert ref.from_address == 0x401014
    assert ref.to_address == 0x40100d
    assert ref.type == dragodis.ReferenceType.code_jump

    insn = disassembler.get_instruction(0x40100d)
    assert ref in list(insn.references_to)
    insn = disassembler.get_instruction(0x401014)
    assert ref in list(insn.references_from)
