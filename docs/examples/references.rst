References
==========

A Dragodis *Reference* represents a reference to or from an address found
in a disassembler.

.. code:: python

    >>> refs = dis.references_to(0x401000)
    >>> for ref in refs:
    ...     print(ref)
    code_call: 0x0040103a --> 0x00401000
    code_call: 0x00401049 --> 0x00401000
    code_call: 0x00401058 --> 0x00401000
    code_call: 0x00401067 --> 0x00401000
    code_call: 0x00401076 --> 0x00401000
    code_call: 0x00401085 --> 0x00401000
    code_call: 0x00401094 --> 0x00401000
    code_call: 0x004010a3 --> 0x00401000
    code_call: 0x004010b2 --> 0x00401000
    code_call: 0x004010c1 --> 0x00401000
    code_call: 0x004010d0 --> 0x00401000
    code_call: 0x004010df --> 0x00401000
    code_call: 0x004010ee --> 0x00401000
    code_call: 0x004010fd --> 0x00401000
    code_call: 0x0040110c --> 0x00401000
    code_call: 0x0040111b --> 0x00401000
    code_call: 0x0040112a --> 0x00401000
    code_call: 0x00401139 --> 0x00401000

References can be obtained through the ``.references_to(address)`` and
``.references_from(address)`` functions found in the flat API.  *Function* objects
also provide the ``.references_to`` and ``.references_from`` attributes as a
means of getting references.