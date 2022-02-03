Registers
=========

A Dragodis *Register* object represents a pure register found in disassembled
code.  *Register* objects provide the name and bit width of the underlying register.

*Register* objects can be obtained by calling ``.get_operand_value()`` on pure
register operands or ``.value()`` on *Operand* objects that represent pure registers.

*Register* objects can also be found within other operand value objects
such as *Phrase* objects.

.. code:: python

    >>> instruction = dis.get_instruction(0x401009)
    >>> print(instruction)
    test    ecx, ecx

    >>> reg1 = instruction.operands[0].value
    >>> print(reg1.name)
    ecx
    >>> print(reg1.bit_width)
    32

    >>> reg2 = dis.get_operand(0x401009, 1).value
    >>> print(reg2.name)
    ecx
    >>> print(reg2.bit_width)
    32
    >>> print(reg1 == reg2)
    True
