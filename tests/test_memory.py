
import pytest


@pytest.mark.parametrize("address,data", [
    # test reading loaded.
    (0x00401000, b"\x55\x8B\xEC"),
    (0x00401035, b"\x68\x00\xC0\x40\x00"),
    (0x0040C000, b"Idmmn!Vnsme \x00"),
    # TODO: Not supported in Ghidra
    # # test reading unloaded.
    # (0x0040E1AA, b"\x00\x00\x00\x00\x00"),
    # test reading partial unloaded and loaded.
    (0x0040A10c, (b"\x00" * 16) + b"\xF0\x14"),
])
def test_read(disassembler, address, data):
    with disassembler.open_memory(address, address + len(data) + 10) as memory:
        assert memory.tell_address() == address
        assert memory.read(len(data)) == data
        assert memory.tell_address() == address + len(data)
    assert disassembler.get_bytes(address, len(data)) == data


@pytest.mark.parametrize("address,data", [
    # test reading loaded.
    (0x10544, b"\x28\x10\x02\x00"),
    (0x21028, b"Idmmn!Vnsme \x00"),
])
def test_read_arm(disassembler, address, data):
    with disassembler.open_memory(address, address + len(data) + 10) as memory:
        assert memory.tell_address() == address
        assert memory.read(len(data)) == data
        assert memory.tell_address() == address + len(data)
    assert disassembler.get_bytes(address, len(data)) == data



@pytest.mark.parametrize("address", [
    # 0x00401000,  # code section  # TODO: Patching code this way doesn't work for Ghidra.
    0x0040C000,  # data section
])
def test_write(disassembler, address):
    """
    Tests patching and un-patching bytes.
    (Currently only works for data sections.)
    """
    orig_data = disassembler.get_bytes(address, 4)
    new_data = b"\xde\xad\xbe\xef"
    with disassembler.open_memory(address, address + 4) as memory:
        assert memory.write(new_data) == 4
        memory.seek(0)
        assert memory.read() == new_data

        # Ensure we can read that same data the normal way.
        assert disassembler.get_bytes(address, 4) == new_data

        # Reset
        memory.seek(0)
        assert memory.reset(4) == 4
        memory.seek(0)
        assert memory.read() == orig_data
        assert disassembler.get_bytes(address, 4) == orig_data


def test_write_uninitialized(disassembler):
    address = 0x0040D200
    with disassembler.open_memory(address, address + 4) as memory:
        with pytest.raises(IOError):
            memory.write(b"\xde\xad\xbe\xef")


def test_empty_memory(disassembler):
    with disassembler.open_memory(0x123, 0x123) as memory:
        assert memory.tell_address() == 0x123
        assert memory.read() == b""
        assert memory.tell_address() == 0x123
