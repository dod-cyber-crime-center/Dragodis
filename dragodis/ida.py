import glob
import os
import re
import sys
from functools import lru_cache
import subprocess
import time
from typing import List

import jfx_bridge
import jfx_bridge_ida
from jfx_bridge_ida import install_server

from dragodis import base
from dragodis.base import OperandType
from dragodis.exceptions import NotExistError


# TODO: This doesn't work well because we run into permission errors. We should just instruct the user instead.
# def install(ida_path=None):
#     """
#     Installs the jfx_bridge_ida entry scripts into IDA's python folder so it is visible to IDA.
#     """
#     ida_path = ida_path or os.environ["IDA_DIR"]
#     python_path = os.path.join(ida_path, "python", "3")
#     server_script = os.path.join(python_path, "jfx_bridge_ida_server.py")
#
#     # First check if already installed.
#     # TODO: Determine a way to detect if we need to rerun installation on update.
#     installed = os.path.exists(server_script)
#     if not installed:
#         install_server.do_install(python_path)
#     if not os.path.exists(server_script):
#         raise RuntimeError("IDA installation failed. Please check your permissions.")
#
#     return server_script


class IDA(base.Disassembler):
    def __init__(self, input_path, is_64_bit=False, ida_dir=None):
        """
        Initializes IDA disassembler.

        :param input_path: Path of binary to process.
        :param is_64_bit: Whether input file is 64bit or 32bit
        :param ida_dir: Path to IDA directory.
            This may also be set using the environment variable IDA_DIR
        """
        # TODO: dynamically determine if 64 bit by doing the same thing we did in kordesii.
        super().__init__(input_path)
        self._ida_dir = ida_dir or os.environ["IDA_DIR"]
        self._script_path = os.path.join(
            self._ida_dir, "python", "3", "jfx_bridge_ida_server.py"
        )
        if not os.path.exists(self._script_path):
            raise IOError(
                f"IDA bridge server is not installed. Please follow README for installation instructions."
            )

        # Find ida executable within ida_dir.
        ida_exe_re = re.compile("idaq?64(\.exe)?$" if is_64_bit else "idaq?(\.exe)?$")
        for filename in os.listdir(self._ida_dir):
            if ida_exe_re.match(filename):
                self._ida_exe = os.path.abspath(os.path.join(self._ida_dir, filename))
                break
        else:
            raise IOError(f"Unable to find ida executable within: {self._ida_dir}")

        self._running = False

        self._process = None
        self._bridge = None
        self._idaapi = None
        self._idc = None
        self._idautils = None
        self._ida_bytes = None

    def start(self):
        if self._running:
            raise ValueError(f"IDA disassembler already running.")

        # We need to temporarily change the current directory to be within the ida path so we don't
        # have spaces in script file path.
        # For an unknown reason, IDA hates spaces in its script path.
        orig_cwd = os.getcwd()
        try:
            os.chdir(self._ida_dir)
            script_path = os.path.relpath(self._script_path, self._ida_dir)
            # Create the command to start IDA with the bridge_server script
            command = [
                self._ida_exe,
                "-P",
                "-A",
                f"-S{script_path}",
                f'"{self.input_path}"',
            ]

            command = " ".join(command)

            # TODO: Clean up ida temp files if we fail.
            self._process = subprocess.Popen(command)
        finally:
            os.chdir(orig_cwd)

        time.sleep(5)  # TODO: Get signal from IDA bridge to know when we can set it up.

        self._bridge = jfx_bridge_ida.IDABridge(do_import=False)
        self._idaapi = self._bridge.get_idaapi()
        self._idc = self._bridge.get_idc()
        self._idautils = self._bridge.get_idautils()
        self._ida_bytes = self._bridge.remote_import("ida_bytes")
        self._running = True

    def stop(self):
        if not self._running:
            return

        self._bridge.remote_shutdown()
        self._running = False

    @property
    def current_location(self) -> int:
        return self._bridge.remote_eval("idc.get_screen_ea()")

    def prev_head(self, addr: int) -> int:
        head = self._bridge.remote_eval(f"idc.prev_head({addr})")
        # If ida returns the unsigned value of -1 for some bit length
        if (head - (1 << head.bit_length())) == -1:
            raise NotExistError(f"Address head before '{hex(addr)}' does not exist")
        return head

    def next_head(self, addr: int) -> int:
        head = self._bridge.remote_eval(f"idc.next_head({addr})")
        # If ida returns the unsigned value of -1 for some bit length
        if (head - (1 << head.bit_length())) == -1:
            raise NotExistError(f"Address head after '{hex(addr)}' does not exist")
        return head

    def get_head(self, addr: int) -> int:
        head = self._bridge.remote_eval(f"idc.get_item_head({addr})")
        # If ida returns the unsigned value of -1 for some bit length
        if (head - (1 << head.bit_length())) == -1:
            raise NotExistError(f"Address head containing '{hex(addr)}' does not exist")
        return head

    def get_heads(self, start: int, end: int) -> List[int]:
        return self._bridge.remote_eval(f"list(idautils.Heads({start}, {end}))")

    def get_xrefs_to(
        self, addr: int, code: bool = True, data: bool = True
    ) -> List[int]:
        refs = []

        for xref in self._bridge.remote_eval(f"idautils.XrefsTo({addr})"):
            refs.append(xref.__dict__)

        if code and data:
            pass  # Don't filter out any xrefs
        elif code or data:
            refs = [
                ref
                for ref in refs
                if (ref["iscode"] and code) or (not ref["iscode"] and data)
            ]
        elif not code and not data:
            refs = []

        return [ref["frm"] for ref in refs]

    def get_xrefs_from(
        self, addr: int, code: bool = True, data: bool = True
    ) -> List[int]:
        refs = []

        for xref in self._bridge.remote_eval(f"idautils.XrefsFrom({addr})"):
            refs.append(xref.__dict__)

        if code and data:
            pass  # Don't filter out any xrefs
        elif code or data:
            refs = [
                ref
                for ref in refs
                if (ref["iscode"] and code) or (not ref["iscode"] and data)
            ]
        elif not code and not data:
            refs = []

        return [ref["to"] for ref in refs]

    def set_name(self, addr: int, name: str):
        if not bool(self._bridge.remote_eval(f"idc.set_name({addr}, {name})")):
            raise ValueError(f"Failed to set {addr} to {name}")

    def get_function_containing(self, addr: int):
        return IDAFunction.from_addr(self, addr)

    def get_mnemonic_at(self, addr: int) -> str:
        mnem = self._idc.print_insn_mnem(addr)
        if mnem != "":
            return mnem
        raise NotExistError(
            f"{hex(addr)} does not point to the head of a valid instruction"
        )

    def get_operand_type(self, addr: int, idx: int):
        # TODO: Add exception handling for invalid idx and address
        op_type = self._idc.get_operand_type(addr, idx)

        if op_type == 1:  # o_reg
            return OperandType.register
        elif op_type == 2:  # o_mem
            return OperandType.memory
        elif op_type == 3 or op_type == 4:  # o_phrase or o_displ
            return OperandType.phrase
        elif op_type == 5:  # o_imm
            return OperandType.immediate
        elif op_type == 6 or op_type == 7:  # o_far or o_near
            return OperandType.code
        elif op_type == 0:  # o_void
            return OperandType.void
        else:
            return op_type

    def get_operand_value(self, addr: int, idx: int) -> int:
        if idx < 0:
            raise IndexError("Index cannot be negative")
        instr = self._idautils.DecodeInstruction(addr)
        num_ops = instr.size
        if idx >= num_ops:
            raise IndexError(
                f"Instruction at {hex(addr)} does not have an operand at index {idx}"
            )
        return self._idc.get_operand_value(addr, idx)

    def _bytes_loaded(self, addr: int, num_bytes: int) -> bool:
        # Checks to see if ``num_bytes`` bytes at address ``addr`` are loaded.
        FF_IVL = self._ida_bytes.FF_IVL
        for i in range(num_bytes):
            if (self._ida_bytes.get_full_flags(addr + i) & FF_IVL) == 0:
                return False
        return True

    def get_bytes(self, addr: int, length: int):
        return self._idc.get_bytes(addr, length)

    def get_qword(self, addr: int) -> int:
        if not self._bytes_loaded(addr, 8):
            raise NotExistError(f"Cannot get qword at {hex(addr)}")
        return self._idc.get_qword(addr)

    def get_dword(self, addr: int) -> int:
        if not self._bytes_loaded(addr, 4):
            raise NotExistError(f"Cannot get dword at {hex(addr)}")
        return self._idc.get_wide_dword(addr)

    def get_word(self, addr: int) -> int:
        if not self._bytes_loaded(addr, 2):
            raise NotExistError(f"Cannot get word at {hex(addr)}")
        return self._idc.get_wide_word(addr)

    def get_byte(self, addr: int) -> int:
        if not self._bytes_loaded(addr, 1):
            raise NotExistError(f"Cannot get byte at {hex(addr)}")
        return self._idc.get_wide_byte(addr)


class IDAFunction(base.Function):
    def __init__(self, disassembler, addr):
        self._disassembler = disassembler
        self._addr = addr

        self._start = None
        self._end = None

        self._name = self._disassembler._bridge.remote_eval(
            f"idc.get_func_name({addr})"
        )
        if self._name == "":
            raise NotExistError(f"Function containing '{hex(addr)}' does not exist")

    @classmethod
    @lru_cache(maxsize=1000)
    def from_addr(cls, disassembler, addr: int):
        return cls(disassembler, addr)

    @property
    def start(self) -> int:
        if self._start is None:
            self._start = self._disassembler._bridge.remote_eval(
                f"idc.get_func_attr({self._addr}, FUNCATTR_START)"
            )
        return self._start

    @property
    def end(self) -> int:
        if self._end is None:
            self._end = self._disassembler._bridge.remote_eval(
                f"idc.get_func_attr({self._addr}, FUNCATTR_END)"
            )
        return self._end

    @property
    def name(self) -> str:
        if self._name is None:
            self._name = self._disassembler._bridge.remote_eval(
                f"idc.get_func_name({self.start})"
            )
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
