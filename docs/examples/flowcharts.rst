Flowcharts
==========

A Dragodis *Flowchart* represents the graph of basic blocks for a given function.

A *Flowchart* is simply a collection of *BasicBlock* objects that can be obtained from
``.blocks`` or ``.get_block()``.

A *BasicBlock* contains properties and methods for obtaining the start/end address,
flow type, the lines within, as well as other basic blocks that come into or out of the block.

.. code:: python

    >>> flowchart = dis.get_flowchart(0x40100A)
    >>> print(flowchart)
    flowchart[0x00401000]

    >>> print("\n".join(map(str, flowchart.blocks)))
    block[0x00401000 --> 0x00401003]
    block[0x00401003 --> 0x0040100d]
    block[0x0040100d --> 0x00401029]
    block[0x00401029 --> 0x0040102b]

    >>> block = list(flowchart.blocks)[1]
    >>> print(hex(block.start))
    0x401003
    >>> print(hex(block.end))
    0x40100d
    >>> print(block.flow_type)
    FlowType.conditional_jump
    >>> print("\n".join(map(str, block.lines())))
    0x00401003: mov     eax, [ebp+arg_0]
    0x00401006: movsx   ecx, byte ptr [eax]
    0x00401009: test    ecx, ecx
    0x0040100b: jz      short loc_401029

    >>> block2 = flowchart.get_block(block.start)
    >>> print(block == block2)
    True

    >>> print("\n".join(map(str, block.blocks_to)))
    block[0x00401000 --> 0x00401003]
    block[0x0040100d --> 0x00401029]

    >>> print("\n".join(map(str, block.blocks_from)))
    block[0x0040100d --> 0x00401029]
    block[0x00401029 --> 0x0040102b]
