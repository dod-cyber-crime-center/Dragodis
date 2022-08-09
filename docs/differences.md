# Differences Between Disassemblers

Given the nature of the project, there is bound to be some variance
in the way that different disassemblers handle certain situations.
Some of these situations may be simple to work around, while others may require
more effort to work around.  Understanding these differences will aid in creating
better scripts that won't stop working when switching from one disassembler to another.

Some of the differences that have been found so far include: 
- When it comes to alignment, IDA combines all of the bytes into one line, Ghidra separates each byte into its own line.
- There may be differences between the min and max addresses of binaries between Ghidra and IDA.
- The initial current address may be different in Ghidra and IDA.
- IDA and Ghidra have different naming conventions for various components of the disassembly such as
  functions.  IDA names functions `sub_XXXXXX` by default, while Ghidra names functions
  `FUN_00XXXXXX` by default.

If you **do** need to write disassembler specific code, you can check the `.name` attribute of the
disassembler.

```python
if dis.name == "IDA":
    # do IDA specific thing
elif dis.name == "Ghidra":
    # do Ghidra specific thing
else:
    raise ValueError(f"{dis.name} disassembler is not supported.")
```
