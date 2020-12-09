"""
Ghidra Dissassembler
"""

import os
import platform
import subprocess
import time
import tempfile
import shutil

from decorator import decorator
from functools import lru_cache
from typing import List

import ghidra_bridge
from dragodis import base
from dragodis.base import OperandType
from dragodis.exceptions import NotExistError


# Ghidra Operand Flags
DYNAMIC = 0x400000
ADDR = 0x2000
SCALAR = 0x4000
REGISTER = 0x200
IMMEDIATE = 0x8
CODE = 0x40
DATA = 0x80


def _addr_to_int(addr):
    """Converts a Ghidra Address Object to its integer representation."""
    return int(str(addr), 16)


@decorator
def normalize_addr(func, *args, **kwargs):
    addr = func(*args, **kwargs)
    if addr is None:
        return None
    if "ghidra.program.model.address" not in str(addr.getClass()):
        raise TypeError
    return _addr_to_int(addr)


class Ghidra(base.Disassembler):
    def __init__(self, input_path, ghidra_path=None):
        """
        Initializes Ghidra disassembler.

        :param input_path: Path of binary to process.
        :param ghidra_path: Path to Ghidra directory.
            This may also be set using the environment variable GHIDRA_DIR
        """
        super().__init__(input_path)
        self._ghidra_path = ghidra_path or os.environ["GHIDRA_DIR"]

        self._script_path = os.path.expanduser(
            os.path.join("~", "ghidra_scripts", "ghidra_bridge_server.py")
        )
        if not os.path.exists(self._script_path):
            raise IOError(
                f"Ghidra bridge server is not installed. Please follow README for installation instructions."
            )

        analyzeHeadless = "analyzeHeadless"
        if "Windows" in platform.platform():
            analyzeHeadless += ".bat"
        self._ghidra_exe = os.path.join(self._ghidra_path, "support", analyzeHeadless)

        self._project_path = self.input_path + "_ghidra_project"
        self._new_file = not os.path.exists(self._project_path)
        if self._new_file:
            os.mkdir(self._project_path)

        self._process = None
        self._bridge = None
        self._listing = None

        self._running = False

    def start(self):
        if self._running:
            raise ValueError

        # Create the command to start Ghidra with the bridge_server script
        command = [
            self._ghidra_exe,
            self._project_path,
            "dragodis_work",
            "-noanalysis",  # Analysis is started once the bridge has been established
            "-postScript",
            self._script_path,
        ]

        # Import binary if no project currently exists
        # Otherwise process previously imported binary
        if self._new_file:
            command.append(f"-import {self.input_path}")
        else:
            command.append(f"-process")

        command = " ".join(command)

        self._process = subprocess.Popen(command)
        time.sleep(20)  # Wait for ghidra to start

        self._bridge = ghidra_bridge.GhidraBridge(namespace=globals())
        if self._new_file:
            self._bridge.remote_eval("analyzeAll(getCurrentProgram())")
        self._listing = getCurrentProgram().getListing()

        self._running = True

    def stop(self):
        if not self._running:
            return

        self._bridge.remote_shutdown()
        self._running = False

    @property
    def current_location(self) -> int:
        return self._bridge.remote_eval("getState().getCurrentAddress().getOffset()")

    @normalize_addr
    def prev_head(self, addr: int) -> int:
        prev_cu = self._bridge.remote_eval(
            f"getCurrentProgram().getListing().getCodeUnitBefore(toAddr({addr}))"
        )
        if prev_cu is not None:
            return self._bridge.remote_eval("cu.getAddress()", cu=prev_cu)
        raise NotExistError(f"Address head before '{hex(addr)}' does not exist")

    @normalize_addr
    def next_head(self, addr: int) -> int:
        next_cu = self._bridge.remote_eval(
            f"getCurrentProgram().getListing().getCodeUnitAfter(toAddr({addr}))"
        )
        if next_cu is not None:
            return self._bridge.remote_eval("cu.getAddress()", cu=next_cu)
        raise NotExistError(f"Address head after '{hex(addr)}' does not exist")

    @normalize_addr
    def get_head(self, addr: int) -> int:
        curr_cu = self._bridge.remote_eval(
            f"getCurrentProgram().getListing().getCodeUnitContaining(toAddr({addr}))"
        )
        if curr_cu is not None:
            return self._bridge.remote_eval("cu.getAddress()", cu=curr_cu)
        raise NotExistError(f"Address head containing '{hex(addr)}' does not exist")

    def get_heads(self, start: int, end: int) -> int:
        addr_range = self._bridge.remote_eval("createAddressSet()")
        self._bridge.remote_eval(f"x.add(toAddr({start}), toAddr({end}))", x=addr_range)

        code_units = self._bridge.remote_eval(
            "[cu.getAddress() for cu in getCurrentProgram().getListing().getCodeUnits(x, True) \
            if cu is not None]",
            x=addr_range,
        )

        heads = []
        for cu in code_units:
            if cu is None:
                raise RuntimeError(str(addr_range))
            addr = _addr_to_int(cu)
            if addr < end:
                heads.append(addr)

        return heads

    def get_xrefs_to(
        self, addr: int, code: bool = True, data: bool = True
    ) -> List[int]:
        ref_obj = getReferencesTo(toAddr(addr))

        refs = []

        instr = getInstructionAt(toAddr(addr))
        if instr:
            fall_from = instr.getFallFrom()
            if fall_from:
                refs.append(_addr_to_int(fall_from))

        if ref_obj is None:
            return refs

        for ref in ref_obj:
            if code and data:
                pass  # Don't filter references
            else:
                if ref.getReferenceType().isData() and not data:
                    continue
                if not ref.getReferenceType().isData() and not code:
                    continue
            refs.append(_addr_to_int(ref.getFromAddress()))

        return refs

    def get_xrefs_from(
        self, addr: int, code: bool = True, data: bool = True
    ) -> List[int]:
        ref_obj = getReferencesFrom(toAddr(addr))

        refs = []

        instr = getInstructionAt(toAddr(addr))
        if instr:
            fall_through = instr.getFallThrough()
            if fall_through:
                refs.append(_addr_to_int(fall_through))

        if ref_obj is None:
            return refs

        for ref in ref_obj:
            if code and data:
                pass  # Don't filter references
            else:
                if ref.getReferenceType().isData() and not data:
                    continue
                if not ref.getReferenceType().isData() and not code:
                    continue
            refs.append(_addr_to_int(ref.getFromAddress()))

        return refs

    def set_name(self, addr: int, name: str):
        # May need to validate name before creating the label
        if not bool(createLabel(toAddr(addr), name, True)):
            raise ValueError(f"Failed to set {addr} to {name}")

    def get_function_containing(self, addr: int):
        return GhidraFunction.from_addr(self, addr)

    def get_mnemonic_at(self, addr: int) -> str:
        instr = getInstructionAt(toAddr(addr))
        if instr:
            return instr.getMnemonicString().lower()
        raise NotExistError(
            f"{hex(addr)} does not point to the head of a valid instruction"
        )

    def get_operand_type(self, addr: int, idx: int):
        instr = getInstructionAt(toAddr(addr))
        if instr is None:
            raise NotExistError(f"There is no instruction at {hex(addr)}")
        num_ops = instr.getNumOperands()
        if num_ops <= idx:
            raise IndexError(f"The instruction at {addr} has no operand at index {idx}")

        op_type = instr.getOperandType(idx)

        if op_type == DYNAMIC or (
            op_type & DYNAMIC and op_type & ADDR and not op_type & SCALAR
        ):
            return OperandType.phrase
        elif op_type & REGISTER:
            return OperandType.register
        elif op_type & ADDR and (op_type & SCALAR or not op_type & DYNAMIC):
            if op_type & CODE:
                return OperandType.code
            elif op_type & DATA:
                return OperandType.memory
            else:
                return OperandType.immediate
        elif op_type & IMMEDIATE or op_type & SCALAR:
            return OperandType.immediate
        else:
            return op_type

    def get_operand_value(self, addr: int, idx: int) -> int:
        if idx < 0:
            raise IndexError("Index cannot be negative")
        instr = getInstructionAt(toAddr(addr))
        if instr is None:
            raise NotExistError(f"No instruction at {hex(addr)}")
        if idx >= instr.getNumOperands():
            raise IndexError(
                f"Instruction at {hex(addr)} does not have an operand at index {idx}"
            )

        op_objs = instr.getOpObjects(idx)
        if op_objs:
            for op in op_objs:
                if "Scalar" in repr(op):
                    return op.getValue()
                elif "GenericAddress" in repr(op):
                    return op.getOffset()
            return 0
        # Some instructions return a string instead of an int for immediate values
        # e.g SAR EAX, 1
        else:
            op = instr.getDefaultOperandRepresentation(idx)
            if op.isdigit():
                return int(op)
            else:
                raise ValueError(f"Unknown operand type: {op}")

    def get_bytes(self, addr: int, length: int):
        return bytes(getBytes(toAddr(addr), length).tostring(), encoding="latin-1")

    def _get_var_length_unsigned_int(self, addr: int, length: int) -> int:
        # Helper function for methods such as get_dword() and get_byte()
        # Handles endianness
        cu = self._listing.getCodeUnitContaining(toAddr(addr))
        if cu is None:
            return None
        offset = addr - _addr_to_int(cu.getAddress())
        return cu.getBigInteger(offset, length, False)

    def get_qword(self, addr: int) -> int:
        qword = self._get_var_length_unsigned_int(addr, 8)
        if qword is None:
            raise NotExistError(f"Cannot get qword at {hex(addr)}")
        return qword

    def get_dword(self, addr: int) -> int:
        dword = self._get_var_length_unsigned_int(addr, 4)
        if dword is None:
            raise NotExistError(f"Cannot get dword at {hex(addr)}")
        return dword

    def get_word(self, addr: int) -> int:
        word = self._get_var_length_unsigned_int(addr, 2)
        if word is None:
            raise NotExistError(f"Cannot get word at {hex(addr)}")
        return word

    def get_byte(self, addr: int) -> int:
        byte = self._get_var_length_unsigned_int(addr, 1)
        if byte is None:
            raise NotExistError(f"Cannot get byte at {hex(addr)}")
        return byte


class GhidraFunction(base.Function):
    def __init__(self, disassembler, ghidra_func_obj):
        self._disassembler = disassembler
        self._func_obj = ghidra_func_obj

        self._start = _addr_to_int(self._func_obj.getBody().getMinAddress())
        self._end = _addr_to_int(self._func_obj.getBody().getMaxAddress())
        self._name = self._func_obj.getName()

    @classmethod
    @lru_cache(maxsize=1000)
    def from_addr(cls, disassembler, addr: int):
        func = disassembler._bridge.remote_eval(
            f"getFunctionContaining(toAddr({addr}))"
        )
        if func is None:
            raise NotExistError(f"Function containing '{hex(addr)}' does not exist")
        return cls(disassembler, func)

    @property
    def start(self) -> int:
        if self._start is None:
            self._start = _addr_to_int(self._func_obj.getBody().getMinAddress())
        return self._start

    @property
    def end(self) -> int:
        if self._end is None:
            self._end = _addr_to_int(self._func_obj.getBody().getMaxAddress())
        return self._end

    @property
    def name(self) -> str:
        if self._name is None:
            self._name = self._func_obj.getName()
        return self._name

    @name.setter
    def name(self, value: str):
        self._disassembler.set_name(self.start, value)
        self._name = None

    def get_xrefs_to(self, code: bool = True, data: bool = True) -> List[int]:
        return self._disassembler.get_xrefs_to(self.start, code, data)

    def get_heads(self) -> List[int]:
        return self._disassembler.get_heads(self.start, self.end)

    @property
    def args(self) -> List[dict]:
        pass

    @property
    def return_type(self) -> str:
        pass
