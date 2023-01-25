# Dragodis

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


## Install

Use pip to install dragodis:

```console
pip install dragodis
```

Then follow the instructions [here](./docs/install.md) to install a backend disassembler.


## Usage

To use Dragodis, simply pass in the path to your input binary file into either the `IDA` or `Ghidra` class.
This will create an instance of the disassembler with the given input file analyzed.

```python
import dragodis

with dragodis.Ghidra(r"C:\strings.exe") as ghidra:
    print(ghidra.get_dword(0x401000))
```

```python
import dragodis

with dragodis.IDA(r"C:\strings.exe") as ida:
    print(ida.get_dword(0x401000))
```

A disassembler can also be run without using a context manager using the `start()` and `stop()` functions.

```python
import dragodis

ghidra = dragodis.Ghidra(r"C:\strings.exe")
ghidra.start()
ghidra.get_dword(0x401000)
ghidra.stop()
```

Alternatively, you can use `open_program()` to choose the disassembler more dynamically by providing
the disassembler name in the `disassembler` parameter or by setting the `DRAGODIS_DISASSEMBLER`
environment variable.

```python
import dragodis

with dragodis.open_program(r"C:\strings.exe", disassembler="ida") as ida:
    print(ida.get_dword(0x401000))
```

It is highly recommended to use the `DRAGODIS_DISASSEMBLER` environment variable to ensure your scripts
are cross compatible without any modification. As well, to give the user the power to choose
which disassembler they would like to use.


```{note} 
A "NotInstalledError" will be thrown if the disassembler chosen is not properly installed.
```

```python
import os
os.environ["DRAGODIS_DISASSEMBLER"] = "ida"

import dragodis

with dragodis.open_program(r"C:\strings.exe") as dis:
    print(f"Disassembler used: {dis.name}")
    print(dis.get_dword(0x401000))
```

If you are locally within the disassembler's interpreter (the output window for IDA or pyhidraw interpreter in Ghidra)
then you can initialize a disassembler object by directly acccessing the object:

```python
# If in IDA
import dragodis
dis = dragodis.IDA()

# If in Ghidra
import dragodis
dis = dragodis.Ghidra()
```

We can also directly call scripts using the `open_program()` function locally in the disassembler.
When this happens, the input file path provided must match the detected input file path by the disassembler.


### Specifying Processor Type

The processor type can be specified during initialization of the `Disassembler` object or through `open_program()`. 
This can be useful when loading shellcode.

When using `open_program()` with any backend disassembler supported, use a `dragodis.PROCESSOR_*` flag which will get converted
to a sane default for the respective disassembler.

```python
import dragodis
with dragodis.open_program(r"C:\input.exe", processor=dragodis.PROCESSOR_ARM) as dis:
    ...
```

If using a specific disassembler, any option that disassembler supports can be passed in.
(Consult the documentation for the respective disassembler to know how to format the argument.)

```python
# IDA
import dragodis
ida = dragodis.IDA(r"C:\input", processor="arm:ARMv7-M")

# Ghidra
import dragodis
ghidra = dragodis.Ghidra(r"C:\input", processor="ARM:LE:32:v7")
```

Alternatively, we can automatically choose the correct processor for the default disassembler chosen by the user 
with some initial checks.

```python
import dragodis

PROCESSOR = {
    dragodis.BACKEND_IDA: "arm:ARMv7-M",
    dragodis.BACKEND_GHIDRA: "ARM:LE:32:v7",
}[dragodis.BACKEND_DEFAULT]

with dragodis.open_program(r"C:\input", processor=PROCESSOR) as dis:
    ...
```


## Disassembler API Translation Map

As a reference, the following tables provide a rough mapping between the general equivalent API calls for Dragodis and each supported
disassembler. 

*NOTE: These are rough translations between equivalent disassembler API functions to help you transition 
from using either IDA or Ghidra to using Dragodis.
They are not always direct translations.
For brevity, some details and differences in results get glossed over here. Please see the source code for more information.*


## Basics
| Dragodis*                            | IDA                                                    | Ghidra                                                                           | 
|--------------------------------------|--------------------------------------------------------|----------------------------------------------------------------------------------|
| dis.processor_name                   | ida_ida.inf_get_procname()                             | currentProgram.getLanguage().getProcessor()                                      |
| dis.compiler_name                    | ida_typeinf.get_compiler_name(ida_ida.inf_get_cc_id()) | currentProgram.getCompiler()                                                     |
| dis.bit_size                         | ida_ida.inf_get_app_bitness()                          | currentProgram.getDefaultPointerSize() * 8                                       |
| dis.is_big_endian                    | ida_ida.inf_is_be()                                    | currentProgram.getLanguage().isBigEndian()                                       |
| dis.min_address                      | ida_ida.inf_get_min_ea()                               | currentProgram.getMinAddress()                                                   |
| dis.max_address                      | ida_ida.inf_get_max_ea()                               | currentProgram.getMaxAddress()                                                   |
| dis.base_address                     | ida_nalt.get_imagebase()                               | currentProgram.getImageBase()                                                    |
| dis.get_virtual_address(file_offset) | ida_loader.get_fileregion_ea(file_offset)              | currentProgram.getMemory().locateAddressesForFileOffset(file_offset)             |
| dis.get_file_offset(address)         | ida_loader.get_fileregion_offset(address)              | currentProgram.getMemory().getAddressSourceInfo(toAddr(address)).getFileOffset() |
| dis.entry_point                      | ida_ida.inf_get_start_ip()                             | *(export with name "entry" or "_start")*                                         |


### Data
| Dragodis*                                                                               | IDA                                                                                                                                         | Ghidra                                                                                                                                           | 
|-----------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| dis.get_byte(address)                                                                   | ida_bytes.get_wide_byte(address)                                                                                                            | getByte(toAddr(address))                                                                                                                         |
| dis.get_bytes(address, size)                                                            | ida_bytes.get_bytes(address, size)                                                                                                          | getBytes(toAddr(address), size)                                                                                                                  |
| dis.find_bytes(b"\xde\xad\xbe\xef", start)                                              | idc.find_binary(start, idc.SEARCH_DOWN, "DE AD BE EF")                                                                                      | currentProgram.getMemory().findBytes(start, b"\xde\xad\xbe\xef", None, True, monitor)                                                            | 
| dis.find_bytes(b"\xde\xad\xbe\xef", start, reverse=True)                                | idc.find_binary(start, idc.SEARCH_UP, "DE AD BE EF")                                                                                        | currentProgram.getMemory().findBytes(start, b"\xde\xad\xbe\xef", None, False, monitor)                                                           |
| dis.get_word(address)                                                                   | ida_bytes.get_wide_word(address)                                                                                                            | getShort(toAddr(address))                                                                                                                        |
| dis.get_dword(address)                                                                  | ida_bytes.get_wide_dword(address)                                                                                                           | getInt(toAddr(address))                                                                                                                          |
| dis.get_qword(address)                                                                  | ida_bytes.get_qword(address)                                                                                                                | getLong(toAddr(address))                                                                                                                         |
| dis.get_string_bytes(address)                                                           | idc.get_strlit_contents(address)                                                                                                            | *complex: see source code*                                                                                                                       |
| dis.lines(start_address, end_address)<br>dis.line_addresses(start_address, end_address) | idautils.Heads(start_address, end_address)                                                                                                  | currentProgram.getListing().getCodeUnits(address_set, True)                                                                                      |  
| line = dis.get_line(address)                                                            | *N/A*                                                                                                                                       | code_unit = currentProgram.getListing().getCodeUnitContaining(toAddr(address))                                                                   |
| line.address<br>dis.get_line_address(address)                                           | idc.get_item_head(address)                                                                                                                  | code_unit.getAddress()                                                                                                                           |
| line.name<br>dis.get_name(address)                                                      | ida_name.get_name(address)                                                                                                                  | code_unit.getLabel()                                                                                                                             |
| line.name = "new_name"                                                                  | ida_name.set_name(address, "new_name")                                                                                                      | symbol = code_unit.getPrimarySymbol(); symbol.setName("new_name", symbol.getSource())                                                            |        
| line.size                                                                               | ida_bytes.get_item_size(address)                                                                                                            | code_unit.getLength()                                                                                                                            |
| line.type                                                                               | ida_bytes.get_flags(address)                                                                                                                | code_unit.getClass()<br>code_unit.getDataType().getName()                                                                                        |
| line.type = LineType.dword                                                              | idc.create_dword(address)                                                                                                                   | createDWord(address)                                                                                                                             |
| line.data                                                                               | ida_bytes.get_bytes(address, ida_bytes.get_item_size(address))                                                                              | code_unit.getBytes()                                                                                                                             |
| line.data = b"new data"                                                                 | ida_bytes.patch_bytes(address, b"new data")                                                                                                 | setBytes(code_unit.getAddress(), b"new data")                                                                                                    |
| line.get_comment()<br>dis.get_comment(address)                                          | ida_bytes.get_cmt(address, 0)                                                                                                               | code_unit.getComment(0)                                                                                                                          |
| line.set_comment("new comment")                                                         | ida_bytes.set_cmt(address, "new comment", 0)                                                                                                | code_unit.setComment(0, "new comment")                                                                                                           |
| line.next<br>dis.next_line_address(address)                                             | idc.next_head(address)                                                                                                                      | currentProgram.getListing().getCodeUnitAfter(code_unit.getAddress())                                                                             |
| line.prev<br>dis.prev_line_address(address)                                             | idc.prev_head(address)                                                                                                                      | currentProgram.getListing().getCodeUnitBefore(code_unit.getAddress())                                                                            |
| line.undefine()                                                                         | ida_bytes.del_items(address)                                                                                                                | clearListing(code_unit.getAddress())                                                                                                             |
| line.value                                                                              | ida_bytes.get_wide_byte(address)<br>ida_bytes.get_wide_word(address)<br>*etc.*                                                              | code_unit.getValue()                                                                                                                             |
| line.value = new_value                                                                  | ida_bytes.patch_byte(address, new_value)<br>ida_bytes.patch_word(address, new_value)<br>ida_bytes.patch_dword(address, new_value)<br>*etc.* | setByte(code_unit.getAddress(), new_value)<br>setShort(code_unit.getAddress(), new_value)<br>setInt(code_unit.getAddress(), new_value)<br>*etc.* |
| data_type = dis.get_data_type("dword")                                                  | data_type = ida_typeinf.tinfo_t(); data_type.get_named_type(ida_typeinf.get_idati(), "dword")                                               | data_type = DataTypeParser(None, DataTypeParser.AllowedDataTypes.valueOf("ALL")).parse("dword")                                                  |
| data_type.name                                                                          | *N/A*                                                                                                                                       | data_type.getName()                                                                                                                              |
| data_type.size                                                                          | ida_bytes.get_data_elsize(address, ida_bytes.get_flags(address) & ida_bytes.DT_TYPE)                                                        | data_type.getLength()                                                                                                                            |


### Cross-References
| Dragodis*                                                                                                          | IDA                                                                                                            | Ghidra                                                                                                                                   | 
|--------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| dis.references_from(address)<br>dis.get_line(address).references_from<br>dis.get_function(address).references_from | idautils.XrefsFrom(address)                                                                                    | getReferencesFrom(toAddr(address))                                                                                                       |
| dis.references_to(address)<br>dis.get_line(address).references_to<br>dis.get_function(address).references_to       | idautils.XrefsTo(address)                                                                                      | getReferencesTo(toAddr(address))                                                                                                         |
| ref.from_address                                                                                                   | ref.frm                                                                                                        | ref.getFromAddress()                                                                                                                     |
| ref.to_address                                                                                                     | ref.to                                                                                                         | ref.getToAddress()                                                                                                                       |
| ref.type                                                                                                           | ref.type                                                                                                       | ref.getReferenceType()                                                                                                                   |
| ref.is_code                                                                                                        | ref.iscode                                                                                                     | not ref.getReferenceType().isData()                                                                                                      |
| ref.is_data                                                                                                        | not ref.iscode                                                                                                 | ref.getReferenceType().isData()                                                                                                          |
| dis.create_reference(from_address, to_address, dragodis.ReferenceType.*)                                           | ida_xref.add_cref(from_address, to_address, idc.fl_*)<br>ida_xref.add_dref(from_address, to_address, idc.dr_*) | currentProgram.getReferenceManager().addMemoryReference(toAddr(from_address), toAddr(to_address), RefType.*, SourceType.USER_DEFINED, 0) |


### Imports/Exports
| Dragodis*             | IDA                                                                                          | Ghidra                                                          | 
|-----------------------|----------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| dis.imports           | \[ida_nalt.enum_import_names(i, callback) for i in range(ida_nalt.get_import_module_qty())\] | currentProgram.getSymbolTable().getExternalSymbols()            |
| dis.exports           | \[ida_entry.get_entry_ordinal(i) for i in range(ida_entry.get_entry_qty())\]                 | currentProgram.getSymbolTable().getExternalEntryPointIterator() |
| import_.address       | *returned in callback*                                                                       | symbol.getAddress()                                             |
| import_.name          | *returned in callback*                                                                       | symbol.getName()                                                |
| import_.namespace     | ida_nalt.get_import_module_name(i)                                                           | symbol.getParentSymbol().getName()                              |
| import_.references_to | idautils.XrefsTo(address)                                                                    | symbol.getReferences()                                          |
| export.address        | ida_entry.get_entry(ordinal)                                                                 | symbol.getAddress()                                             |
| export.name           | ida_entry.get_entry_name(ordinal)                                                            | symbol.getName()                                                |
| export.references_to  | idautils.XrefsTo(ida_entry.get_entry(ordinal))                                               | symbol.getReferences()                                          |


### Functions
| Dragodis*                                             | IDA                                                                                                                                                        | Ghidra                                                                           | 
|-------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| dis.functions()                                       | idautils.Functions()                                                                                                                                       | currentProgram.getListing().getFunctions(True)                                   |
| func = dis.get_function(address)                      | func = ida_funcs.get_func(address)                                                                                                                         | func = getFunctionContaining(toAddr(address))                                    |
| func.start                                            | func.start_ea                                                                                                                                              | func.getEntryPoint()                                                             |
| func.end                                              | func.end_ea                                                                                                                                                | func.getBody().getMaxAddress()                                                   |
| func.name<br>dis.get_name(address)                    | ida_funcs.get_func_name(address)                                                                                                                           | func.getName()                                                                   |
| func.name = "new_name"                                | ida_name.set_name(address, "new_name")                                                                                                                     | func.setName("new_name", SourceType.USER_DEFINED)                                |
| func.get_comment()                                    | ida_funcs.get_func_cmt(func, 0)                                                                                                                            | func.getComment()                                                                |
| func.set_comment("new comment")                       | ida_funcs.set_func_cmt(func, "new comment", 0)                                                                                                             | func.setComment("new comment")                                                   |
| dis.get_flowchart(address)<br>func.flowchart          | ida_gdl.FlowChart(func)                                                                                                                                    | BasicBlockModel(currentProgram).getCodeBlocksContaining(func.getBody(), monitor) |
| func.stack_frame                                      | ida_frame.get_frame(func)                                                                                                                                  | func.getStackFrame()                                                             |
| dis.get_function_signature(address)<br>func.signature | tif = ida_typeinf.tinfo_t()<br>ida_nalt.get_tinfo(tif, address)<br>func_type_data = ida_typeinf.func_type_data_t()<br>tif.get_func_details(func_type_data) | func.getSignature()                                                              |

### Instructions
| Dragodis*                                  | IDA                                                       | Ghidra                                                                                               | 
|--------------------------------------------|-----------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| insn = dis.get_instruction(address)        | insn = ida_ua.insn_t(); ida_ua.decode_insn(insn, address) | insn = currentProgram.getListing().getCodeUnitAt(toAddr(address))                                    |
| insn.is_call                               | ida_idp.is_call_insn(insn)                                | insn.getFlowType().isCall()                                                                          |
| insn.is_jump                               | *complex: see source code*                                | insn.getFlowType().isJump()                                                                          |
| insn.is_return                             | ida_idp.is_ret_insn(insn)                                 | insn.getFlowType().isTerminal()                                                                      |
| insn.mnemonic<br>dis.get_mnemonic(address) | ida_ua.ua_mnem(address)                                   | insn.getMnemonicString()                                                                             |
| insn.text                                  | idc.GetDisasm(address)                                    | str(insn)                                                                                            |
| insn.operands                              | insn.ops                                                  | *N/A: See operands section*                                                                          |
| insn.stack_depth                           | idc.get_spd(address)                                      | CallDepthChangeInfo(currentProgram.getListing().getFunctionContaining(insn.getAddress())).getDepth() |
| insn.stack_delta                           | idc.get_sp_delta(address)                                 | *complex: see source code*                                                                           |

### Operands

*`insn` pulled as described above*

| Dragodis*                                                                     | IDA                                                                 | Ghidra                        | 
|-------------------------------------------------------------------------------|---------------------------------------------------------------------|-------------------------------|
| operand = dis.get_operand(address, index)<br>operand = insn.operands\[index\] | operand = insn.ops\[index\]                                         | *N/A*                         |
| operand.type<br>dis.get_operand_type(address, index)                          | idc.get_operand_type(address, index)                                | insn.getOperandType(index)    |
| operand.width                                                                 | ida_ua.get_dtype_size(operand.dtype)                                | *complex: see source code*    |
| operand.value<br>dis.get_operand_value(address, index)                        | *(depends on type)*<br>operand.addr<br>operand.reg<br>operand.value | insn.getOpObjects(index)      |
| *(phrase operand)*<br>operand.value.base                                      | operand.reg<br>ida_intel.x86_base_reg(insn, operand)                | insn.getOpObjects(index)\[0\] |
| *(phrase operand)*<br>operand.value.index                                     | ida_intel.x86_index_reg(insn, operand)                              | insn.getOpObjects(index)\[1\] |
| *(phrase operand)*<br>operand.value.scale                                     | 1 << ida_intel.sib_scale(operand)                                   | insn.getOpObjects(index)\[2\] |
| *(phrase operand)*<br>operand.value.offset                                    | operand.addr<br>idc.get_operand_value(address, index)               | insn.getOpObjects(index)\[3\] |
| *(register operand)*<br>operand.value                                         | operand.reg<br>idc.get_operand_value(address, index)                | insn.getOpObjects(index)\[0\] |
| *(immediate operand)*<br>operand.value                                        | operand.value<br>idc.get_operand_value(address, index)              | insn.getOpObjects(index)\[0\] |
| *(memory reference operand)*<br>operand.value                                 | operand.addr<br>idc.get_operand_value(address, index)               | insn.getOpObjects(index)\[0\] |


### Registers
| Dragodis*                          | IDA                                                                      | Ghidra                                       | 
|------------------------------------|--------------------------------------------------------------------------|----------------------------------------------|
| register = dis.get_register("eax") | register = ida_idp.reg_info_t(); ida_idp.parse_reg_name(register, "eax") | register = currentProgram.getRegister("eax") |
| register.name                      | ida_idp.get_reg_name(register.reg, register.size)                        | register.getName()                           |
| register.bit_width                 | register.size * 8                                                        | register.getBitLength()                      |


### Segments
| Dragodis*                                                             | IDA                                                                                   | Ghidra                                                                                                                          | 
|-----------------------------------------------------------------------|---------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| dis.segments                                                          | \[ida_segment.getnseg(n) for n in range(ida_segment.get_segm_qty())\]                 | currentProgram.getMemory().getBlocks()                                                                                          |
| segment = dis.get_segment(name)<br>segment = dis.get_segment(address) | segment = ida_segment.get_segm_by_name(name)<br>segment = ida_segment.getseg(address) | memory_block = currentProgram.getMemory().getBlock(name)<br>memory_block = currentProgram.getMemory().getBlock(toAddr(address)) |
| segment.name                                                          | ida_segment.get_segm_name(segment)                                                    | memory_block.getName()                                                                                                          |
| segment.start                                                         | segment.start_ea                                                                      | memory_block.getStart()                                                                                                         |
| segment.end                                                           | segment.end_ea                                                                        | memory_block.getEnd()                                                                                                           |
| segment.initialized                                                   | ida_bytes.is_loaded(segment.start_ea)                                                 | memory_block.isInitialized()                                                                                                    |
| segment.bit_size                                                      | segment.abits()                                                                       | memory_block.getStart().getSize()                                                                                               |
| segment.permissions                                                   | segment.perm                                                                          | memory_block.isRead()<br>memory_block.isWrite()<br>memory_block.isExecute()<br>memory_block.isVolatile()                        |
| dis.create_segment(".new_seg", 0x1234, 256)                           | ida_segment.add_segm(0, 0x1234, 0x1334, ".new_seg", "XTRN")                           | currentProgram.getMemory().createUninitializedBlock(".new_seg", toAddr(0x1234), 256, False)                                     |


### Strings
| Dragodis*                 | IDA                                                           | Ghidra                                |
|---------------------------|---------------------------------------------------------------|---------------------------------------|
| dis.strings(min_length=5) | finder = idautils.Strings(); finder.setup(minlen=5); list(sc) | findStrings(None, 5, 1, False, True)  |


\* `dis` in the dragodis column represents the open disassembler object retrieved from `dragodis.open_program()`
