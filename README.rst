********
Dragodis
********

Dragodis is a Python framework which allows for the creation of
universal disassembler scripts.  Dragodis currently only supports
IDA and Ghidra, but has plans to support additional disassemblers
in the future.  Dragodis only supports Python 3.

The name `Dragodis` comes from the combination of `Dragoman`, a professional
interpreter, and `Disassembler`.

Dragodis was created due to a need of the ability to run IDA scripts in
Ghidra. Many scripts for automated analysis will work fine in most disassemblers.
Eliminating the need to use disassemblers which require licenses for automated
analysis is ideal.

There are other benefits of a universal disassembler API as well. Many reverse
engineers have a preferred disassembler. Dragodis allows for simple transfers
of scripts between users of different disassemblers. Dragodis also aims to provide
a cleaner and easier to use API than those provided by other disassemblers.


Usage
=====

To use Dragodis, simply pass in the path to your input binary file into either the ``IDA`` or ``Ghidra`` class.
This will create an instance of the disassembler with the given input file analyzed.

.. code-block:: python

   import dragodis

   with dragodis.Ghidra(r"C:\strings.exe") as ghidra:
       print(ghidra.get_dword(0x401000))


.. code-block:: python

   import dragodis

   with dragodis.IDA(r"C:\strings.exe") as ida:
       print(ida.get_dword(0x401000))


A disassembler can also be run without using a context manager using the `start()` and `stop()` functions.

.. code-block:: python

   import dragodis

   ghidra = dragodis.Ghidra(r"C:\strings.exe")
   ghidra.start()
   ghidra.get_dword(0x401000)
   ghidra.stop()


Alternatively, you can use ``open_program()`` to choose the disassembler more dynamically by providing
the disassembler name in the ``disassembler`` parameter or by setting the ``DRAGODIS_DISASSEMBLER``
environment variable.

.. code-block:: python

    import dragodis

    with dragodis.open_program(r"C:\strings.exe", disassembler="ida") as ida:
        print(ida.get_dword(0x401000))


It is highly recommended to use the ``DRAGODIS_DISASSEMBLER`` environment variable to ensure your scripts
are cross compatible without any modification. As well, to give the user the power to choose
which disassembler they would like to use.

*NOTE: A ``dragodis.NotInstalledError`` will be thrown if the disassembler chosen is not properly installed.*

.. code-block:: python

    import os
    os.environ["DRAGODIS_DISASSEMBLER"] = "ida"

    import dragodis

    with dragodis.open_program(r"C:\strings.exe") as dis:
        print(f"Disassembler used: {dis.name}")
        print(dis.get_dword(0x401000))
