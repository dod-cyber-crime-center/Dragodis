Functions
=========

A Dragodis *Function* represents a function in a disassembler and provides
an easy way to interact with the various attributes of functions.

.. code:: python

    >>> func = dis.get_function(0x40100A)
    >>> print(func)
    sub_401000()
    >>> signature = func.signature
    >>> print(signature)
    _BYTE *__cdecl sub_401000(_BYTE *a1, char a2);
    >>> print(signature.return_type)
    byte *
    >>> orig_type = signature.return_type
    >>> signature.return_type = "int"
    >>> print(signature)
    INT __cdecl sub_401000(_BYTE *a1, char a2);
    >>> signature.return_type = orig_type
    >>> print(signature.calling_convention)
    __cdecl
    >>> for param in signature.parameters:
    ...     print(param)
    stack[0x0]: _BYTE * a1
    stack[0x4]: char a2

    >>> # Changing the calling convention also updates parameter locations.
    >>> signature.calling_convention = "fastcall"
    >>> for param in signature.parameters:
    ...     print(param)
    ecx: _BYTE * a1
    dl: char a2
    >>> signature.calling_convention = "cdecl"

    >>> print(func.source_code)
    _BYTE *__cdecl sub_401000(_BYTE *a1, char a2)
    {
      _BYTE *result; // eax
    <BLANKLINE>
      while ( 1 )
      {
        result = a1;
        if ( !*a1 )
          break;
        *a1++ ^= a2;
      }
      return result;
    }
    <BLANKLINE>

    >>> print(hex(func.start))
    0x401000
    >>> print(hex(func.end))
    0x40102b

    >>> # Give function a custom name.
    >>> func.name = "get_key"
    >>> print(func)
    get_key()
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

