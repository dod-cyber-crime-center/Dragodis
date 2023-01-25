
import pytest

from dragodis import NotExistError
from dragodis.interface.function_argument_location import StackLocation


def test_signature(disassembler):
    func = disassembler.get_function(0x401000)
    signature = func.signature
    assert signature.name
    assert signature.name == func.name


def test_signature_for_import(disassembler):
    """
    Tests getting a function signature for an external import.
    """
    address = 0x40a0c4
    # First show, we can't get the function normally.
    with pytest.raises(NotExistError):
        disassembler.get_function(address)
    # Now show we can still get the function signature because it is an import.
    signature = disassembler.get_function_signature(address)
    assert signature.name == "HeapReAlloc"


@pytest.mark.parametrize("address,declaration", [
    (0x401000, "_BYTE *__cdecl sub_401000(_BYTE *a1, char a2);"),
    (0x40a0c4, "LPVOID __stdcall HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);")
])
def test_signature_declaration_ida(disassembler, address, declaration):
    signature = disassembler.get_function_signature(address)
    assert signature.declaration == declaration


@pytest.mark.parametrize("address,declaration", [
    (0x401000, "undefined cdecl FUN_00401000(byte * param_1, byte param_2)"),
    (0x40a0c4, "LPVOID stdcall HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)")
])
def test_signature_declaration_ghidra(disassembler, address, declaration):
    signature = disassembler.get_function_signature(address)
    assert signature.declaration == declaration


@pytest.mark.parametrize("address,calling_convention", [
    (0x401000, "__cdecl"),
    (0x40a0c4, "__stdcall"),
])
def test_calling_convention(disassembler, address, calling_convention):
    signature = disassembler.get_function_signature(address)
    # test getting calling convention
    assert signature.calling_convention == calling_convention
    # Ghidra doesn't include the "__" in declaration
    assert calling_convention.lstrip("_") in signature.declaration
    # test changing calling convention
    signature.calling_convention = "fastcall"
    assert signature.calling_convention == "__fastcall"
    assert "fastcall" in signature.declaration
    # reset
    signature.calling_convention = calling_convention
    assert signature.calling_convention == calling_convention


@pytest.mark.parametrize("address,return_types", [
    (0x401150, ("int", "undefined4")),
    (0x40a0c4, ("lpvoid", "LPVOID")),
])
def test_return_type(disassembler, address, return_types):
    signature = disassembler.get_function_signature(address)
    # test getting the return type
    orig_type = signature.return_type
    assert str(orig_type) in return_types
    # test setting the return type
    signature.return_type = "char *"
    assert str(signature.return_type) == "char *"
    # reset and test setting with DataType object.
    signature.return_type = orig_type
    assert signature.return_type == orig_type


def test_parameters(disassembler):
    signature = disassembler.get_function_signature(0x401000)
    assert len(signature.parameters) == 2

    param_0 = signature.parameters[0]
    assert param_0.ordinal == 0
    assert param_0.size == 4
    assert "byte *" in param_0.data_type.name.casefold()
    assert isinstance(param_0.location, StackLocation)
    assert param_0.location.stack_offset == 0

    param_1 = signature.parameters[1]
    assert param_1.ordinal == 1
    assert param_1.size == 1
    assert param_1.data_type.name in ("byte", "char")
    assert isinstance(param_1.location, StackLocation)
    assert param_1.location.stack_offset == 4


def test_parameter_info_ida(disassembler):
    signature = disassembler.get_function_signature(0x401000)
    param_0 = signature.parameters[0]
    assert param_0.name == "a1"
    assert param_0.data_type.name == "byte *"
    assert param_0.declaration == "_BYTE * a1"


def test_applied_function_signature_ida(disassembler):
    """
    Test that new signature has been applied back to disassembly view within IDB.
    """
    address = 0x401000
    ida_typeinf = disassembler._ida_typeinf
    ida_nalt = disassembler._ida_nalt

    tif = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tif, address)
    assert str(tif) == ""

    # The act of getting the function signature will use and apply the signature from the decompiler.
    disassembler.get_function_signature(address)
    tif = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tif, address)
    assert str(tif) == "_BYTE *__cdecl(_BYTE *a1, char a2)"


def test_parameter_info_ghidra(disassembler):
    signature = disassembler.get_function_signature(0x401000)
    param_0 = signature.parameters[0]
    assert param_0.name == "param_1"
    assert param_0.data_type.name == "byte *"
    assert param_0.declaration == "[byte * param_1@Stack[0x4]:4]"


def test_modifying_parameters(disassembler):
    signature = disassembler.get_function_signature(0x401000)

    param_0 = signature.parameters[0]
    assert param_0.ordinal == 0

    orig_name = param_0.name
    assert orig_name in ("a1", "param_1")
    param_0.name = "newname"
    assert param_0.name == "newname"
    assert "newname" in signature.declaration
    param_0.name = orig_name

    assert "byte" in param_0.data_type.name.casefold()

    param_0.data_type = "char *"
    assert param_0.data_type.name.casefold() == "char *"
    assert "char *" in signature.declaration.casefold()

    param_0.data_type = "int"
    assert param_0.data_type.name.casefold() == "int"
    assert param_0.data_type.size == 4
    assert "int" in signature.declaration.casefold()

    param_0.data_type = "qword"
    assert param_0.data_type.name.casefold() == "qword"
    assert param_0.data_type.size == 8
    assert "qword" in signature.declaration.casefold()

    # Test inserting a new parameter in the front and see if our param_0
    # variable updates correctly.
    new_param = signature.insert_parameter(0, "int")
    assert new_param.ordinal == 0
    assert param_0.ordinal == 1

    # Remove parameter to reset state.
    signature.remove_parameter(0)
    assert len(signature.parameters) == 2


def test_replace_parameters(disassembler):
    signature = disassembler.get_function_signature(0x401000)
    orig_parameters = signature.parameters
    assert len(orig_parameters) == 2
    orig_param_info = [(param.name, param.data_type.name) for param in orig_parameters]
    # Must pull before modifying, otherwise we get a NotExistsError when trying to access it.
    orig_data_types = signature.parameter_types

    signature.replace_parameters(["int", "char", "int"])
    parameters = signature.parameters
    assert len(parameters) == 3
    assert [param.data_type.name for param in parameters] == ["int", "char", "int"]

    signature.replace_parameters(orig_data_types)
    parameters = signature.parameters
    assert len(parameters) == 2
    assert [(param.name, param.data_type.name) for param in parameters] == orig_param_info


def test_add_parameter(disassembler):
    signature = disassembler.get_function_signature(0x401000)
    assert len(signature.parameters) == 2
    new_param = signature.add_parameter("int")
    assert len(signature.parameters) == 3
    assert new_param == signature.parameters[2]
    assert new_param.data_type.name == "int"
    assert new_param.data_type.size == 4
    assert "int" in signature.declaration.casefold()

    # Remove parameter to reset state.
    signature.remove_parameter(2)
    assert len(signature.parameters) == 2


def test_remove_parameter(disassembler):
    signature = disassembler.get_function_signature(0x401000)
    orig_declaration = signature.declaration
    removed_param_type = signature.parameters[1].data_type.name
    assert len(signature.parameters) == 2
    with pytest.raises(NotExistError):
        signature.remove_parameter(3)
    signature.remove_parameter(1)
    assert len(signature.parameters) == 1
    assert len(signature.declaration) < len(orig_declaration)

    # Add parameter back to reset state.
    signature.add_parameter(removed_param_type)
    assert len(signature.parameters) == 2


def test_remove_parameter_negative(disassembler):
    """
    Test to ensure negative indexing works.
    """
    signature = disassembler.get_function_signature(0x401000)
    orig_declaration = signature.declaration
    removed_param_type = signature.parameters[1].data_type.name
    assert len(signature.parameters) == 2
    signature.remove_parameter(-1)
    assert len(signature.parameters) == 1
    assert len(signature.declaration) < len(orig_declaration)

    # Add parameter back to reset state.
    signature.add_parameter(removed_param_type)
    assert len(signature.parameters) == 2


def test_insert_parameter(disassembler):
    signature = disassembler.get_function_signature(0x401000)
    assert len(signature.parameters) == 2
    with pytest.raises(ValueError):
        signature.insert_parameter(5, "int")
    new_param = signature.insert_parameter(1, "int")
    assert len(signature.parameters) == 3
    assert new_param == signature.parameters[1]
    assert new_param.data_type.name == "int"
    assert "int" in signature.declaration.casefold()

    # Remove parameter to reset state.
    signature.remove_parameter(1)
    assert len(signature.parameters) == 2


def test_insert_parameter_negative(disassembler):
    """
    Test to ensure negative indexing works.
    """
    signature = disassembler.get_function_signature(0x401000)
    assert len(signature.parameters) == 2
    new_param = signature.insert_parameter(-1, "int")
    assert len(signature.parameters) == 3
    assert new_param == signature.parameters[1]
    assert new_param.data_type.name == "int"
    assert "int" in signature.declaration.casefold()

    # Remove parameter to reset state.
    signature.remove_parameter(1)
    assert len(signature.parameters) == 2
