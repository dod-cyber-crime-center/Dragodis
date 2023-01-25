
import pytest

from dragodis import SegmentType, SegmentPermission


def test_basic(disassembler):
    if disassembler.name.lower() == "ida":
        expected_segments = [
            (0x00401000, 0x0040A000, ".text", True, SegmentPermission.read | SegmentPermission.execute),
            (0x0040A000, 0x0040A110, ".idata", False, SegmentPermission.read),
            (0x0040A110, 0x0040C000, ".rdata", True, SegmentPermission.read),
            (0x0040C000, 0x0040F000, ".data", True, SegmentPermission.read | SegmentPermission.write),
        ]
    elif disassembler.name.lower() == "ghidra":
        expected_segments = [
            (0x00400000, 0x00400400, "Headers", True, SegmentPermission.read),
            (0x00401000, 0x00409C00, ".text", True, SegmentPermission.read | SegmentPermission.execute),
            (0x0040A000, 0x0040BE00, ".rdata", True, SegmentPermission.read),
            (0x0040C000, 0x0040D200, ".data", True, SegmentPermission.read | SegmentPermission.write),
            (0x0040D200, 0x0040ed48, ".data", False, SegmentPermission.read | SegmentPermission.write),
        ]
    else:
        raise NotImplementedError

    actual_segments = list(disassembler.segments)
    # Ghidra 10.2.* sometimes includes an extra "tdb" memory block... we are just going ignore that.
    actual_segments = [seg for seg in actual_segments if seg.name != "tdb"]
    print(actual_segments)
    assert len(actual_segments) == len(expected_segments)
    for segment, expected_segments in zip(actual_segments, expected_segments):
        start, end, name, initialized, permissions = expected_segments
        assert segment
        assert hex(segment.start) == hex(start)
        assert hex(segment.end) == hex(end)
        assert segment.name == name
        assert segment.initialized == initialized
        assert segment.permissions == permissions
        assert start in segment
        assert start + 1 in segment

        # Test direct retrieval
        # Doesn't work for the Ghidra segment duplicate.
        if name == ".data" and not initialized:
            continue
        segment2 = disassembler.get_segment(name)
        assert segment2 == segment
        segment3 = disassembler.get_segment(start)
        assert segment3 == segment


def test_create_segment(disassembler):
    orig_segments = list(disassembler.segments)
    segment = disassembler.create_segment(".test", 0x1234, 256)
    assert segment
    assert segment.name == ".test"
    assert segment.start == 0x1234
    assert segment.end == 0x1234 + 256
    assert not segment.initialized

    segments = list(disassembler.segments)
    assert len(segments) == len(orig_segments) + 1
    assert any(seg.name == ".test" for seg in segments)


def test_data(disassembler):
    # Test pulling from loaded memory.
    segment = disassembler.get_segment(".text")
    with segment.open() as memory:
        assert memory.read(0x20) == (
            b"\x55\x8B\xEC\x8B\x45\x08\x0F\xBE\x08\x85\xC9\x74\x1C\x0F\xBE\x55"
            b"\x0C\x8B\x45\x08\x0F\xBE\x08\x33\xCA\x8B\x55\x08\x88\x0A\x8B\x45"
        )

        # Test seeking and then pulling different data.
        memory.seek_address(0x00401141)
        assert memory.read(4) == b"\x5d\xc3\xcc\xcc"

    assert segment.get_bytes(0x00401141, 4) == b"\x5d\xc3\xcc\xcc"
