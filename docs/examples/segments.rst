Segments
========


A Dragodis *Segment* represents a continuous block of defined memory.
This usually refers to the defined sections, but can also be used
to reference things like the PE headers depending on the disassembler.


Segments can be obtained using ``.get_segment()`` with either the name
or an address within passed in as an argument.

All segments can be iterated using ``.segments``.

A *Memory* object for the underlying data can be obtained using the ``.open()`` function.


.. code:: python

    >>> segment = dis.get_segment(".text")
    >>> print(segment)
    .text: 0x00401000 --> 0x0040a000

    >>> segment.get_bytes(0x00401141, 4)
    b']\xc3\xcc\xcc'

    >>> segment.permissions
    <SegmentPermission.read|execute: 5>

    >>> with segment.open() as stream:
    ...     stream.seek(4)
    ...     print(stream.read(4))
    4
    b'E\x08\x0f\xbe'

    >>> for segment in dis.segments:
    ...     print(segment.name, hex(segment.start), hex(segment.end))
    .text 0x401000 0x40a000
    .idata 0x40a000 0x40a110
    .rdata 0x40a110 0x40c000
    .data 0x40c000 0x40f000
