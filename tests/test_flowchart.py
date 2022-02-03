
import pytest

from dragodis import FlowType


@pytest.mark.parametrize("address,block_list", [
    (0x004011AA, [
        (0x00401150, 0x004012A0, FlowType.terminal),
    ]),
    (0x004035BB, [
        (0x00403597, 0x004035AB, FlowType.conditional_jump),
        (0x004035AB, 0x004035B1, FlowType.conditional_jump),
        (0x004035B1, 0x004035B3, FlowType.call),
        (0x004035B3, 0x004035BA, FlowType.conditional_jump),
        (0x004035BA, 0x004035BD, FlowType.terminal),
    ]),
    (0x00401000, [
        (0x00401000, 0x00401003, FlowType.fall_through),
        (0x00401003, 0x0040100D, FlowType.conditional_jump),
        (0x0040100D, 0x00401029, FlowType.unconditional_jump),
        (0x00401029, 0x0040102B, FlowType.terminal),
    ]),
])
def test_blocks_start_end_flow_type(disassembler, address, block_list):
    flowchart = disassembler.get_flowchart(address)
    assert flowchart
    assert len(flowchart) == len(block_list)
    assert [(block.start, block.end, block.flow_type) for block in flowchart.blocks] == block_list


@pytest.mark.parametrize("address,blocks_to,blocks_from", [
    (0x401003, [0x401000, 0x40100D], [0x40100D, 0x401029]),
    (0x401029, [0x401003], []),
    (0x4035B3, [0x4035AB, 0x4035B1], [0x4035AB, 0x4035BA]),
    pytest.param(
        0x402cfe, [0x402cce, 0x402cf0], [0x402d3a],
        marks=pytest.mark.xfail(reason="Ghidra fails to analyze _invoke_watson as a no return function.")
    ),
])
def test_blocks_to_from(disassembler, address, blocks_to, blocks_from):
    block = disassembler.get_basic_block(address)
    assert block
    assert sorted([b.start for b in block.blocks_to]) == blocks_to
    assert sorted([b.start for b in block.blocks_from]) == blocks_from


def test_equality(disassembler):
    flowchart = disassembler.get_flowchart(0x004035BB)
    flowchart2 = disassembler.get_flowchart(0x004035AB)
    assert flowchart and flowchart2
    assert flowchart == flowchart2


def test_get_block(disassembler):
    flowchart = disassembler.get_flowchart(0x004035BB)
    assert flowchart
    found_block = flowchart.get_block(0x004035AD)
    assert found_block
    assert found_block.start == 0x004035AB


@pytest.mark.parametrize("address,lines", [
    (0x00401003, [
        0x00401003, 0x00401006, 0x00401009, 0x0040100B,
    ]),
    (0x004011AA, [
        0x00401150, 0x00401151, 0x00401153, 0x00401158, 0x0040115D, 0x00401162, 0x00401167,
        0x0040116A, 0x0040116F, 0x00401174, 0x00401179, 0x0040117C, 0x00401181, 0x00401186,
        0x0040118B, 0x0040118E, 0x00401193, 0x00401198, 0x0040119D, 0x004011A0, 0x004011A5,
        0x004011AA, 0x004011AF, 0x004011B2, 0x004011B7, 0x004011BC, 0x004011C1, 0x004011C4,
        0x004011C9, 0x004011CE, 0x004011D3, 0x004011D6, 0x004011DB, 0x004011E0, 0x004011E5,
        0x004011E8, 0x004011ED, 0x004011F2, 0x004011F7, 0x004011FA, 0x004011FF, 0x00401204,
        0x00401209, 0x0040120C, 0x00401211, 0x00401216, 0x0040121B, 0x0040121E, 0x00401223,
        0x00401228, 0x0040122D, 0x00401230, 0x00401235, 0x0040123A, 0x0040123F, 0x00401242,
        0x00401247, 0x0040124C, 0x00401251, 0x00401254, 0x00401259, 0x0040125E, 0x00401263,
        0x00401266, 0x0040126B, 0x00401270, 0x00401275, 0x00401278, 0x0040127D, 0x00401282,
        0x00401287, 0x0040128A, 0x0040128F, 0x00401294, 0x00401299, 0x0040129C, 0x0040129E,
        0x0040129F,
    ]),
])
def test_block_lines(disassembler, address, lines):
    block = disassembler.get_basic_block(address)
    assert block
    assert [line.address for line in block.lines()] == lines


def test_flowchart_from_block(disassembler):
    flowchart = disassembler.get_flowchart(0x004011AA)
    block = disassembler.get_basic_block(0x004011AA)
    assert block.flowchart == flowchart


@pytest.mark.parametrize("address,ancestors", [
    # first block
    (0x403597, []),
    # block in the middle with a loop
    (0x4035B1, [
        0x403597,
        0x4035ab,
        0x4035b3,  # loop back
    ]),
    # last block
    (0x4035BB, [
        0x403597,
        0x4035ab,
        0x4035b1,
        0x4035b3,
    ])
])
def test_ancestors(disassembler, address, ancestors):
    flowchart = disassembler.get_flowchart(address)
    block = flowchart.get_block(address)
    assert sorted(b.start for b in block.ancestors) == ancestors


def test_traverse(disassembler):
    flowchart = disassembler.get_flowchart(0x004035BB)

    found_block = flowchart.get_block(0x004035AD)
    assert found_block
    assert found_block.start == 0x004035AB

    blocks = list(flowchart.traverse(start=0x004035AB, reverse=True))
    assert len(blocks) == 2
    assert [(block.start, block.end) for block in blocks] == [
        (0x004035AB, 0x004035B1),
        (0x00403597, 0x004035AB),
    ]

    blocks = list(flowchart.traverse(start=0x004035AB))
    assert len(blocks) == 4
    assert [(block.start, block.end) for block in blocks] == [
        (0x004035AB, 0x004035B1),
        (0x004035BA, 0x004035BD),
        (0x004035B1, 0x004035B3),
        (0x004035B3, 0x004035BA),
    ]

    blocks = list(flowchart.traverse())
    assert len(blocks) == 5
    assert [(block.start, block.end) for block in blocks] == [
        (0x00403597, 0x004035AB),
        (0x004035AB, 0x004035B1),
        (0x004035BA, 0x004035BD),
        (0x004035B1, 0x004035B3),
        (0x004035B3, 0x004035BA),
    ]
    blocks = list(flowchart.traverse(reverse=True))
    assert len(blocks) == 5
    assert [(block.start, block.end) for block in blocks] == [
        (0x004035BA, 0x004035BD),
        (0x004035B3, 0x004035BA),
        (0x00403597, 0x004035AB),
        (0x004035B1, 0x004035B3),
        (0x004035AB, 0x004035B1),
    ]
    blocks = list(flowchart.traverse(dfs=True))
    assert len(blocks) == 5
    assert [(block.start, block.end) for block in blocks] == [
        (0x00403597, 0x004035AB),
        (0x004035AB, 0x004035B1),
        (0x004035B1, 0x004035B3),
        (0x004035B3, 0x004035BA),
        (0x004035BA, 0x004035BD),
    ]
    blocks = list(flowchart.traverse(reverse=True, dfs=True))
    assert len(blocks) == 5
    assert [(block.start, block.end) for block in blocks] == [
        (0x004035BA, 0x004035BD),
        (0x004035B3, 0x004035BA),
        (0x004035B1, 0x004035B3),
        (0x004035AB, 0x004035B1),
        (0x00403597, 0x004035AB),
    ]
