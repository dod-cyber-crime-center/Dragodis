References
==========

A Dragodis *Reference* represents a reference to or from an address found
in a disassembler.

.. code:: python

    >>> refs = dis.references_to(0x401000)
    >>> for ref in refs:
    ...     print(f"{hex(ref.from_address)}, {ref.is_code}, {ref.is_data}")
    0x40103a, True, False
    0x401049, True, False
    0x401058, True, False
    0x401067, True, False
    0x401076, True, False
    0x401085, True, False
    0x401094, True, False
    0x4010a3, True, False
    0x4010b2, True, False
    0x4010c1, True, False
    0x4010d0, True, False
    0x4010df, True, False
    0x4010ee, True, False
    0x4010fd, True, False
    0x40110c, True, False
    0x40111b, True, False
    0x40112a, True, False
    0x401139, True, False

References can be obtained through the ``.references_to(address)`` and
``.references_from(address)`` functions found in the flat API.  *Function* objects
also provide the ``.references_to`` and ``.references_from`` attributes as a
means of getting references.