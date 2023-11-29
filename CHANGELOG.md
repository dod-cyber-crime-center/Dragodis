# Changelog

## [0.8.0] - 2023-11-29
- Updated Ghidra support to 10.3.2 and 10.4
- Added automatic activation of virtualenv within IDA process if one is detected.
- Added `Disassembler.create_function()` for defining a new function.
- Added `Disassembler.undefine()` and `Function.undefine()` for clearing any defined bytes at a given address range.
- Added `default` argument for most `get_*()` functions.
- Added `end` argument to `find_bytes()`.
- Changed `Segment.lines()` to be a function instead of a property.
- Changed `Function` name setting to use `ida_name.force_name` to avoid errors on duplicate names. (Better matches Ghidra behavior)


## [0.7.2] - 2023-02-21
- Tested on Ghidra 10.2.3
- Fixed support for fpu operands using IDA.
- Removed caching of IDA netref modules to fix memory leak issues.


## [0.7.1] - 2023-02-07
- Add missing [CM_CC_SPECIALE](https://hex-rays.com/products/ida/support/idapython_docs/ida_typeinf.html#ida_typeinf.CM_CC_SPECIALE) enum for a usercall with an ellipse - @ddash-ct


## [0.7.0] - 2023-01-25
- Add equality handling for `Function` objects based on start address.
- Added `Disassembler.create_segment()` for creating a basic segment memory block.
- Added `Disassembler.create_reference()` for creating memory cross-references.
- For convenience, `OperandValue` objects can now be cast with `int()` to get a sane value based on type. This helps to match the original functionality of IDA's get_operand_value().
  - WARNING: For some operand types like single registers a -1 will be returned.
- Added `strings()` function to disassembler API.
- Added `.base_address` and `.entry_point` properties to disassembler API.
- Added `Reference.is_call` convenience property.
- Added `Disassembler.get_function_by_name()` convenience function.
- Added `Disassembler.is_loaded()` convenience function.
- Improved performance for `get_import()` when using IDA.
- Removed garbage collection disabling workaround from IDA disassembler.
- Add `Import.calls_to` convenience property.
- Fixed getting function signatures in IDA to ensure data types and parameter names from the decompiler are propagated back to the listing view. (This fixes the "Failed to get stack information" error in rugosa.)
- Sort `__usercall` function arguments to provide consistent ordering between disassemblers.
- Improved getting functions in Ghidra.
- Fixed functions with missing arguments in Ghidra due to the use of custom calling parameter storage.
- Added `base` and `mask` properties to `Register`.
- Fixed support for operands with segment registers (e.g. `fs:[eax]`)
  - These will be presented as phrase types with the segment register as the base.
- Added ability to set the processor during instantiation. (See [documentation](README.md#specifying-processor-type) for more information)


## [0.6.0] - 2022-11-22
- Tested for IDA 8.0
- Changes to `Import` objects to handle changes in IDA 8.0
  - Added `Import.thunk_address` property to obtain an import's address to a thunk function if it exists.
  - `Import.address` property will no longer include thunk addresses. It will always be the original function pointer.
  - `Import.references_to` will now include references to both the original function pointer and the thunk function.
- Increased default timeout for IDA remote calls to better handle samples with longer analysis time.
- Add `timeout` option when initializing disassembler. (Does nothing if not using IDA remotely)
- Include all operands, explicit and implied, for all instructions
- Fix operand width calculation in Ghidra for xmmword pointers.
- Fix bug in Ghidra when getting stack offset for a function argument without a calling convention.


## [0.5.3] - 2022-10-05
- Fixed logging for teleported functions using IDA.
- Fixed incorrectly getting unsigned phrase offsets using Ghidra.
- Fixed `stack_delta` calculation in Ghidra when an instruction has a call fixup.
- Added translation table in README.


## [0.5.2] - 2022-09-13
- Fixed very slow processing times when pulling segment information in IDA.
- Updated segment interface to properly include uninitialized segments.
- Uninitialized segments will now return an empty byte string.


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
  - Flowcharts
  - Function Signatures
  - Instructions
  - Memory
  - Operands
  - Operand value types
  - References
  - Imports/Export symbols
  - Stack/Global variables
  - Segments


## 0.1.0 - 2020-11-25

- Initial release


[Unreleased]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.8.0...HEAD
[0.8.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.7.2...0.8.0
[0.7.2]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.7.1...0.7.2
[0.7.1]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.7.0...0.7.1
[0.7.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.5.3...0.6.0
[0.5.3]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.5.2...0.5.3
[0.5.2]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/dod-cyber-crime-center/dragodis/compare/0.1.0...0.2.0
