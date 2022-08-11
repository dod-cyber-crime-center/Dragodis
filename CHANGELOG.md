# Changelog


## [0.5.1] - 2022-08-11
- Fix issue with non-rep instructions incorrectly throwing an AssertionError.


## [0.5.0] - 2022-08-10

- Fixed getting non-user defined exports in Ghidra.
- Fixed issue getting KeyError if Ghidra isn't setup.
- Updated documentation.
- Added `FunctionSignature.calling_convention` get/set property.
- Added `FunctionSignature.return_type` get/set property.
- Fixed issue with `ida_hexrays.DecompilationFailure` getting thrown. Switched to logging warning instead.
- Fixed issue with incorrect immediate operand value being produced with IDA, sometimes causing an OverflowError.
- Added `Instruction.rep` property for x86 instructions.
- Fixed issue with incorrectly getting NotExistError in IDA when base address is zero.


## [0.4.0] - 2022-06-28

- Added `Symbol.references_to` to get references to imports or exports.
- Added `Disassembler.get_import()` and `Disassembler.get_export()` functions.
- Added `BACKEND_GHIDRA` and `BACKEND_IDA` constants.
- Miscellaneous bugfixes for Ghidra support.


## [0.3.0] - 2022-06-01

- Fixed connection issues with running IDA disassembler in Linux.
- Add auto detection of 64bit size for IDA.
- Changed `Function.instructions()` implementation to use flowchart.
- Added `Function.lines()` function.
- Added `Disassembler.instructions()` function.
- Added `Disassembler.find_bytes()` function.
- Added ability to use dragodis locally in underlying disassembler.
- Added `Disassembler.teleport()` function to run a function within the underlying disassembler.


## [0.2.0] - 2022-02-03

- Updated IDA disassembler to use [rpyc](https://rpyc.readthedocs.io/en/latest).
- Updated support to IDA 7.7
- Updated Ghidra disassembler to use [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra).
- Added proper handling when a disassembler isn't setup/installed.
- Renamed `dragodis.open()` to `dragodis.open_program()`
- Updated README
- Interface has been completely refactored.
- Added support for:
  : - Flowcharts
    - Function Signatures
    - Insturctions
    - Memory
    - Operands
    - Operand value types
    - References
    - Imports/Export symbols
    - Stack/Global variables
    - Segments


## 0.1.0 - 2020-11-25

- Initial release


[Unreleased]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.5.1...HEAD
[0.5.1]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.1.0...0.2.0
