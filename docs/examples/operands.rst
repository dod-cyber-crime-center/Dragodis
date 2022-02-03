Operands
========

A Dragodis *Operand* represents an operand of an instruction.

.. code:: python

    >>> instruction = dis.get_instruction(0x40101E)
    >>> print(instruction)
    mov     eax, [ebp+arg_0]

    >>> op0, op1 = instruction.operands
    >>> print(f"{op0}, {op1}")
    eax, [ebp+arg_0]

    >>> print(f"0x{op0.address:08x}, 0x{op1.address:08x}")
    0x0040101e, 0x0040101e

    >>> print(f"{op0.value}, [{op1.value.base.name} + {op1.value.offset}]")
    eax, [ebp + 8]

    >>> print(f"{op0.type!r}, {op1.type!r}")
    <OperandType.register: 2>, <OperandType.phrase: 6>

    >>> print(f"{op0.width}, {op1.width}")
    4, 4


Operands can be obtained through the flat API using the ``.get_operand(address)``
function.  A list of the operands of an instruction can be retrieved by calling the
``.operands`` attribute of *Instruction* objects.
