Memory
======

A Dragodis *Memory* object represents a specific window of memory data
which acts like a file-like object.
This object can be used to read (and sometimes write) data from the underlying
data within the memory window.

The *Memory* object can be obtained by calling ``.open_memory()`` as a context
manager.

Data can be read using ``read()``, written using ``write()``, as well ``reset()``
can be used to revert data back to the original bytes of the sample.
As well, ``seek()``, ``seek_address()``, ``tell()``, and ``tell_address()`` are
available for navigation based on relative window offset or address.

NOTE: Depending on the disassembler and section of memory, writing data may cause
an ``IOError``.


.. code:: python

    >>> with dis.open_memory(start=0x40c000, end=0x40c114) as memory:
    ...     # Read data.
    ...     _ = memory.seek_address(0x40c0f0)
    ...     offset = memory.tell()
    ...     print(memory.read(8))
    ...
    ...     # Write new data.
    ...     _ = memory.seek(offset)
    ...     _ = memory.write(b"hello!!!")
    ...     _ = memory.seek(offset)
    ...     print(memory.read(8))
    ...
    ...     # Undo patch.
    ...     _ = memory.seek(offset)
    ...     _ = memory.reset(8)
    ...     _ = memory.seek(offset)
    ...     print(memory.read(8))
    b'C\x7frer7c\x7f'
    b'hello!!!'
    b'C\x7frer7c\x7f'
