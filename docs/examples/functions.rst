Functions
=========

A Dragodis *Function* represents a function in a disassembler and provides
an easy way to interact with the various attributes of functions.

.. code:: python

    >>> func = dis.get_function(0x40100A)
    >>> print(func)
    <Function 0x00401000 - sub_401000>

    >>> print(hex(func.start))
    0x401000
    >>> print(hex(func.end))
    0x40102b

    >>> # Give function a custom name.
    >>> func.name = "get_key"
    >>> print(func)
    <Function 0x00401000 - get_key>
    >>> print(func.name)
    get_key

    >>> # Reset function name to default given by disassembler.
    >>> func.name = None
    >>> print(func.name)
    sub_401000

    >>> # Set comment on function.
    >>> func.set_comment("Interesting Function")
    >>> print(func.get_comment())
    Interesting Function

    >>> # Reset comment on function.
    >>> func.set_comment(None)


Functions can be obtained by calling the ``.get_function(address)`` of the flat API.
An iterator over all or a subset of all of the functions of a binary can be obtained
by calling ``dis.functions(start=None, end=None)``.

