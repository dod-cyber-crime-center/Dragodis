
import pytest

import dragodis


# TODO: Find and test more complex examples, such as fragmented functions or functions that
#   don't start at minimum address.
# TODO: Test a function where the last instruction is more than 1 bytes to ensure proper
#   end address is realized.
@pytest.mark.parametrize("address,start,end", [
    (0x401030, 0x401030, 0x401143),
    (0x401030 + 10, 0x401030, 0x401143),
    (0x401beb, 0x40189c, 0x402413),
])
def test_start_end(disassembler, address, start, end):
    func = disassembler.get_function(address)
    assert func
    assert func.start == start
    assert func.end == end
    assert address in func


def test_name(disassembler):
    # Test a library function, which should have the same name regardless of disassembler.
    func = disassembler.get_function(0x4012a0)
    assert func.name == "_printf"
    func.name = "new_func_name"
    assert func.name == "new_func_name"
    func.name = None
    assert func.name != "new_func_name"
    # disassembler should reset default naming scheme since we lose the analysis information.
    assert "4012" in func.name


def test_comment(disassembler):
    func = disassembler.get_function(0x401030)
    func.set_comment("regular comment")
    assert func.get_comment() == "regular comment"
    func.set_comment("repeatable comment", dragodis.CommentType.repeatable)
    assert func.get_comment() == "regular comment"
    assert func.get_comment(dragodis.CommentType.repeatable) == "repeatable comment"
    func.set_comment(None)
    assert func.get_comment() is None
    func.set_comment(None, dragodis.CommentType.repeatable)
    assert func.get_comment(dragodis.CommentType.repeatable) is None

    # Test invalid comment type for a function.
    with pytest.raises(ValueError):
        func.set_comment("test", dragodis.CommentType.posterior)


def test_references(disassembler):
    func = disassembler.get_function(0x401000)
    refs = list(func.references_to)
    # Number of references can be 18 or 20 depending if the disassembler counts the referent in the PE header due to being the first function in the text section.
    assert len(refs) in (18, 20)
    assert all(ref.to_address == 0x401000 for ref in refs)
    assert sorted(ref.from_address for ref in refs if ref.is_code) == [
        0x40103a,
        0x401049,
        0x401058,
        0x401067,
        0x401076,
        0x401085,
        0x401094,
        0x4010a3,
        0x4010b2,
        0x4010c1,
        0x4010d0,
        0x4010df,
        0x4010ee,
        0x4010fd,
        0x40110c,
        0x40111b,
        0x40112a,
        0x401139,
    ]

    refs = list(func.references_from)
    assert len(refs) == 0


def test_call_references(disassembler):
    func = disassembler.get_function(0x401000)
    assert list(func.calls_to) == [
        0x40103a,
        0x401049,
        0x401058,
        0x401067,
        0x401076,
        0x401085,
        0x401094,
        0x4010a3,
        0x4010b2,
        0x4010c1,
        0x4010d0,
        0x4010df,
        0x4010ee,
        0x4010fd,
        0x40110c,
        0x40111b,
        0x40112a,
        0x401139,
    ]
    assert list(func.calls_from) == []
    callers = list(func.callers)
    assert len(callers) == 1
    assert callers[0].start == 0x401030
    assert list(func.callees) == []

    func = disassembler.get_function(0x401030)
    assert list(func.calls_to) == [
        0x401153,
    ]
    assert list(func.calls_from) == [
        (0x40103a, 0x401000),
        (0x401049, 0x401000),
        (0x401058, 0x401000),
        (0x401067, 0x401000),
        (0x401076, 0x401000),
        (0x401085, 0x401000),
        (0x401094, 0x401000),
        (0x4010a3, 0x401000),
        (0x4010b2, 0x401000),
        (0x4010c1, 0x401000),
        (0x4010d0, 0x401000),
        (0x4010df, 0x401000),
        (0x4010ee, 0x401000),
        (0x4010fd, 0x401000),
        (0x40110c, 0x401000),
        (0x40111b, 0x401000),
        (0x40112a, 0x401000),
        (0x401139, 0x401000),
    ]
    callers = list(func.callers)
    assert len(callers) == 1
    assert callers[0].start == 0x401150
    callees = list(func.callees)
    assert len(callees) == 1
    assert callees[0].start == 0x401000


def test_instructions(disassembler):
    func = disassembler.get_function(0x401000)
    instructions = list(func.instructions())
    assert [instruction.address for instruction in instructions] == [
        0x401000, 0x401001, 0x401003, 0x401006, 0x401009, 0x40100b,
        0x40100d, 0x401011, 0x401014, 0x401017, 0x401019, 0x40101c,
        0x40101e, 0x401021, 0x401024, 0x401027, 0x401029, 0x40102a,
    ]
    instructions = list(func.instructions(start=0x40101e))
    assert [instruction.address for instruction in instructions] == [
        0x40101e, 0x401021, 0x401024, 0x401027, 0x401029, 0x40102a,
    ]
    instructions = list(func.instructions(end=0x40100b))
    assert [instruction.address for instruction in instructions] == [
        0x401000, 0x401001, 0x401003, 0x401006, 0x401009,
    ]
    instructions = list(func.instructions(start=0x40100b, end=0x40101e))
    assert [instruction.address for instruction in instructions] == [
        0x40100b, 0x40100d, 0x401011, 0x401014, 0x401017, 0x401019,
        0x40101c,
    ]


def test_source_code_ghidra(disassembler):
    func = disassembler.get_function(0x401000)
    assert func.source_code == """
void __cdecl FUN_00401000(byte *param_1,byte param_2)

{
  for (; *param_1 != 0; param_1 = param_1 + 1) {
    *param_1 = *param_1 ^ param_2;
  }
  return;
}

"""


def test_source_code_ida(disassembler):
    func = disassembler.get_function(0x401000)
    assert func.source_code == """\
_BYTE *__cdecl sub_401000(_BYTE *a1, char a2)
{
  _BYTE *result; // eax

  while ( 1 )
  {
    result = a1;
    if ( !*a1 )
      break;
    *a1++ ^= a2;
  }
  return result;
}
"""


def test_data(disassembler):
    func = disassembler.get_function(0x401000)
    assert func.data == (
        b"\x55"
        b"\x8B\xEC"
        b"\x8B\x45\x08"
        b"\x0F\xBE\x08"
        b"\x85\xC9"
        b"\x74\x1C"
        b"\x0F\xBE\x55\x0C"
        b"\x8B\x45\x08"
        b"\x0F\xBE\x08"
        b"\x33\xCA"
        b"\x8B\x55\x08"
        b"\x88\x0A"
        b"\x8B\x45\x08"
        b"\x83\xC0\x01"
        b"\x89\x45\x08"
        b"\xEB\xDA" 
        b"\x5D"
        b"\xC3"
    )


@pytest.mark.parametrize("address,result", [
    (0x401000, False),
    (0x4012a0, True),
])
def test_is_library(disassembler, address, result):
    func = disassembler.get_function(address)
    assert func.is_library == result
