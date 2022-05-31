
Changelog
=========

`Unreleased`_
--------------

- Fixed connection issues with running IDA disassembler in Linux.
- Add auto detection of 64bit size for IDA.
- Changed ``Function.instructions()`` implementation to use flowchart.
- Added ``Function.lines()`` function.
- Added ``Disassembler.instructions()`` function.
- Added ``Disassembler.find_bytes()`` function.
- Added ability to use dragodis locally in underlying disassembler.
- Added ``Disassembler.teleport()`` function to run a function within the underlying disassembler.


`0.2.0`_ - 2022-02-03
---------------------

- Updated IDA disassembler to use `rpyc <rpyc.readthedocs.io/en/latest>`_.
- Updated support to IDA 7.7
- Updated Ghidra disassembler to use `pyhidra <github.com/Defense-Cyber-Crime-Center/pyhidra>`_.
- Added proper handling when a disassembler isn't setup/installed.
- Renamed ``dragodis.open()`` to ``dragodis.open_program()``
- Updated README
- Interface has been completely refactored.
- Added support for:
    - Flowcharts
    - Function Signatures
    - Insturctions
    - Memory
    - Operands
    - Operand value types
    - References
    - Imports/Export symbols
    - Stack/Global variables
    - Segments


0.1.0 - 2020-11-25
------------------

- Initial release


.. _Unreleased: https://github.com/Defense-Cyber-Crime-Center/dragodis/compare/0.2.0...HEAD
.. _0.2.0: https://github.com/Defense-Cyber-Crime-Center/dragodis/compare/0.1.0...0.2.0
