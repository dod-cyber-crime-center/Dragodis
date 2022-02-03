Instructions
============

A Dragodis *Instruction* represents the assembly code of a line of code in
a disassembler.

.. code:: python

    >>> insn = dis.get_instruction(0x401014)
    >>> print(insn)
    movsx   ecx, byte ptr [eax]

    >>> print(insn.mnemonic)
    movsx

    >>> print(insn.is_call)
    False


Instructions can be obtained by calling the ``.instructions(start=None, end=None, reverse=False)``
method of *Function* objects and iterating through all or a subset of the instructions found
within that function.  Instructions can also be obtained by calling the ``.get_instruction(address)``
function found in the flat API.  Lastly, the ``.instruction`` attribute of *Line* objects
can be called to get an *Instruction* if the line represents an instruction.