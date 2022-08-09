Lines
=====

A Dragodis *Line* represents a line as it would be seen in a disassembler.
Lines can be either code or data.

.. code:: python

    >>> line = dis.get_line(0x401014)
    >>> print(line)
    0x00401014: movsx   ecx, byte ptr [eax]
    >>> print(hex(line.address))
    0x401014

    >>> print(line.data)
    b'\x0f\xbe\x08'

    >>> line.name = "my_line"
    >>> print(line.name)
    my_line

    >>> line = line.next
    >>> print(hex(line.address))
    0x401017


Lines can be obtained by calling the ``.get_line(address)`` function found in
the flat API.  An iterator over every line of a binary can be obtained through using the
``.lines(start=None, end=None, reverse=False)`` function found in the flat API.