
import pytest


# TODO: Better support pointers
@pytest.mark.parametrize("name,size", [
    ("char", 1),
    ("byte", 1),
    ("int", 4),
    ("dword", 4),
    ("word", 2),
    ("short", 2),
    ("char *", 4),
])
def test_get_data_type(disassembler, name, size):
    data_type = disassembler.get_data_type(name)
    assert data_type
    assert data_type.name == name
    assert data_type.size == size
