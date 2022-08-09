Variables
=========

A Dragodis *Variable* represents any global or stack based labeled data.
A variable can be pulled by address or from another object such as a function or operand.

.. code:: python

    >>> var = dis.get_variable(0x40C000)
    >>> print(var)
    0x0040c000: char aIdmmnVnsme
    >>> print(hex(var.address))
    0x40c000
    >>> print(var.name)
    aIdmmnVnsme
    >>> print(var.size)
    13
    >>> print(var.data_type)
    char
    >>> print(var.data_type.size)
    1

    >>> insn = dis.get_instruction(0x401035)
    >>> print(insn)
    push    offset aIdmmnVnsme; "Idmmn!Vnsme "
    >>> print(insn.operands[0].variable)
    0x0040c000: char aIdmmnVnsme

    >>> func = dis.get_function(0x401030)
    >>> for var in func.variables:
    ...     print(var)
    0x0040c000: char aIdmmnVnsme
    0x0040c010: char aVgqvQvpkleUkvj
    0x0040c02c: char aWkfRvjHAqltmEl
    0x0040c05c: char aKeoMwWpvkjcEjE
    0x0040c080: char aDflaGpwkvMjiVL
    0x0040c0a0: char aEgruGhbBiauCge
    0x0040c0c4: byte unk_40C0C4
    0x0040c0f0: byte unk_40C0F0
    0x0040c114: char asc_40C114
    0x0040c120: char aQfbwfsqlFppb
    0x0040c130: char aTsudfs
    0x0040c138: byte unk_40C138
    0x0040c140: byte unk_40C140
    0x0040c15c: char aAkjdgbaKjgdbjk
    0x0040c174: byte unk_40C174
    0x0040c19c: byte unk_40C19C
    0x0040c1c4: byte unk_40C1C4
    0x0040c1f8: char aLmfoghknlmgfoh
