"""
Stores global constants used in dragodis
"""
import os

# backend disassembler names
BACKEND_GHIDRA = "Ghidra"
BACKEND_IDA = "IDA"

_default = os.environ.get("DRAGODIS_DISASSEMBLER", "")
if _default.lower() == BACKEND_GHIDRA.lower():
    _default = BACKEND_GHIDRA
elif _default.lower() == BACKEND_IDA.lower():
    _default = BACKEND_IDA
elif _default:
    valid = [BACKEND_GHIDRA, BACKEND_IDA]
    raise ValueError(f"Invalid DRAGODIS_DISASSEMBLER set: '{_default}'. Should be one of: {','.join(valid)}")
BACKEND_DEFAULT = _default or None
