
from __future__ import annotations
import atexit
import re
import logging
import os
import socket
import subprocess
import sys
import tempfile
import time
import typing
from typing import Callable
import uuid

import rpyc
from rpyc.core.stream import NamedPipeStream, SocketStream

from dragodis.exceptions import DragodisError, NotInstalledError
from dragodis.interface import BackendDisassembler
from dragodis.ida import ida_server

# Used for typing to help Pycharm give us autocompletion.
# To setup, add %IDA_DIR%\python\3 directory into the interpreter path using Pycharm.
if typing.TYPE_CHECKING:
    import idaapi
    import idc
    import idautils
    import ida_bytes
    import ida_funcs
    import ida_gdl
    import ida_name
    import ida_xref
    import ida_ua
    import ida_idp
    import ida_ida
    import ida_lines
    import ida_nalt
    import ida_hexrays
    import ida_segment
    import ida_loader
    import ida_typeinf
    import ida_entry
    import ida_struct
    import ida_frame
    from .sdk import ida_arm
    from .sdk import ida_intel
    from .sdk import ida_helpers

logger = logging.getLogger(__name__)


class _Cached:
    """
    Caches attributes for a given rpyc netref to avoid excess socket calls.
    """

    def __init__(self, netref: rpyc.BaseNetref):
        self._cache = {}
        self._netref = netref

    def __getattribute__(self, name):
        cache = super().__getattribute__("_cache")
        try:
            ret = cache[name]
            return ret
        except KeyError:
            netref = super().__getattribute__("_netref")
            ret = getattr(netref, name)
            cache[name] = ret
            return ret


# TODO: Create a way to handle interfacing with IDA natively instead of through the bridge
#   if we detect we are already in IDA.
#   - Perhaps IDA() class just throws away disassembler?
class IDADisassembler(BackendDisassembler):

    name = "IDA"

    def __init__(self, input_path, is_64_bit=False, ida_path=None):
        """
        Initializes IDA disassembler.

        :param input_path: Path of binary to process.
        :param is_64_bit: Whether input file is 64bit or 32bit
        :param ida_path: Path to IDA directory.
            This may also be set using the environment variable IDA_INSTALL_DIR
        """
        # TODO: dynamically determine if 64 bit by doing the same thing we did in kordesii.
        super().__init__(input_path)
        self._ida_path = ida_path or os.environ.get("IDA_INSTALL_DIR", os.environ.get("IDA_DIR"))
        if not self._ida_path:
            raise NotInstalledError(
                "Failed to get IDA install directory. "
                "Please provide it during instantiation or set the IDA_INSTALL_DIR environment variable."
            )
        self._script_path = ida_server.__file__

        # Find ida executable within ida_dir.
        ida_exe_re = re.compile("idaq?64(\.exe)?$" if is_64_bit else "idaq?(\.exe)?$")
        for filename in os.listdir(self._ida_path):
            if ida_exe_re.match(filename):
                self._ida_exe = os.path.abspath(os.path.join(self._ida_path, filename))
                break
        else:
            raise NotInstalledError(f"Unable to find ida executable within: {self._ida_path}")

        self._running = False

        self._socket_path = None
        self._process = None
        self._bridge = None
        self._BADADDR = 0xFFFFFFFFFFFFFFFF

        self._idaapi = None
        self._idc = None
        self._idautils = None
        self._ida_bytes = None
        self._ida_funcs = None
        self._ida_gdl = None
        self._ida_name = None
        self._ida_ua = None
        self._ida_idp = None
        self._ida_ida = None
        self._ida_lines = None
        self._ida_nalt = None
        self._ida_hexrays = None
        self._ida_segment = None
        self._ida_loader = None
        self._ida_typeinf = None
        self._ida_entry = None
        self._ida_struct = None
        self._ida_frame = None
        self._ida_arm = None
        self._ida_intel = None
        self._ida_helpers = None

        # Used for typing to help Pycharm give us autocompletion.
        # This code shouldn't actually be run.
        # noinspection PyUnreachableCode
        if False:
            self._idaapi = idaapi
            self._idc = idc
            self._idautils = idautils
            self._ida_bytes = ida_bytes
            self._ida_funcs = ida_funcs
            self._ida_gdl = ida_gdl
            self._ida_name = ida_name
            self._ida_ua = ida_ua
            self._ida_idp = ida_idp
            self._ida_ida = ida_ida
            self._ida_lines = ida_lines
            self._ida_nalt = ida_nalt
            self._ida_hexrays = ida_hexrays
            self._ida_segment = ida_segment
            self._ida_loader = ida_loader
            self._ida_typeinf = ida_typeinf
            self._ida_entry = ida_entry
            self._ida_struct = ida_struct
            self._ida_frame = ida_frame
            self._ida_arm = ida_arm
            self._ida_intel = ida_intel
            self._ida_helpers = ida_helpers

    def _initialize_bridge(self):
        """
        Initialize components on bridge.
        """
        # Redirect output.
        self._bridge.modules.sys.stderr = sys.stderr
        self._bridge.modules.sys.stdout = sys.stdout

        # Import IDA modules.
        self._idaapi: idaapi = _Cached(self._bridge.root.getmodule("idaapi"))
        self._idc: idc = _Cached(self._bridge.root.getmodule("idc"))
        self._idautils: idautils = _Cached(self._bridge.root.getmodule("idautils"))
        self._ida_bytes: ida_bytes = _Cached(self._bridge.root.getmodule("ida_bytes"))
        self._ida_funcs: ida_funcs = _Cached(self._bridge.root.getmodule("ida_funcs"))
        self._ida_gdl: ida_gdl = _Cached(self._bridge.root.getmodule("ida_gdl"))
        self._ida_name: ida_name = _Cached(self._bridge.root.getmodule("ida_name"))
        self._ida_xref: ida_xref = _Cached(self._bridge.root.getmodule("ida_xref"))
        self._ida_ua: ida_ua = _Cached(self._bridge.root.getmodule("ida_ua"))
        self._ida_idp: ida_idp = _Cached(self._bridge.root.getmodule("ida_idp"))
        self._ida_ida: ida_ida = _Cached(self._bridge.root.getmodule("ida_ida"))
        self._ida_lines: ida_lines = _Cached(self._bridge.root.getmodule("ida_lines"))
        self._ida_nalt: ida_nalt = _Cached(self._bridge.root.getmodule("ida_nalt"))
        self._ida_hexrays: ida_hexrays = _Cached(self._bridge.root.getmodule("ida_hexrays"))
        self._ida_segment: ida_segment = _Cached(self._bridge.root.getmodule("ida_segment"))
        self._ida_loader: ida_loader = _Cached(self._bridge.root.getmodule("ida_loader"))
        self._ida_typeinf: ida_typeinf = _Cached(self._bridge.root.getmodule("ida_typeinf"))
        self._ida_entry: ida_entry = _Cached(self._bridge.root.getmodule("ida_entry"))
        self._ida_struct: ida_struct = _Cached(self._bridge.root.getmodule("ida_struct"))
        self._ida_frame: ida_frame = _Cached(self._bridge.root.getmodule("ida_frame"))

        # Need to first add our custom sdk package to the path to import custom modules.
        from . import sdk
        self._bridge.modules.sys.path.extend(sdk.__path__)

        self._ida_arm: ida_arm = _Cached(self._bridge.root.getmodule("ida_arm"))
        self._ida_intel: ida_intel = _Cached(self._bridge.root.getmodule("ida_intel"))
        self._ida_helpers: ida_helpers = _Cached(self._bridge.root.getmodule("ida_helpers"))

    @staticmethod
    def unix_connect(socket_path, retry=10) -> rpyc.Connection:
        """
        Connects to bridge using unix socket.
        """
        for i in range(retry):
            try:
                logger.debug(f"Connecting to socket path: {socket_path}, try {i + 1}")
                stream = SocketStream.unix_connect(socket_path)
                link = rpyc.classic.connect_stream(stream)
                assert link.eval("2 + 2") == 4
                logger.debug(f"Connected to {socket_path}")
                return link
            except socket.error:
                time.sleep(1)
                continue

        raise DragodisError(f"Could not connect to {socket_path} after {retry} tries.")

    @staticmethod
    def win_connect(pipe_name, retry=10) -> rpyc.Connection:
        """
        Connects to bridge using Windows named pipe.
        """
        pipe_name = NamedPipeStream.NAMED_PIPE_PREFIX + pipe_name
        import pywintypes
        for i in range(retry):
            try:
                logger.debug(f"Connecting to pipe: {pipe_name}, try {i + 1}")
                stream = NamedPipeStream.create_client(pipe_name)
                link = rpyc.classic.connect_stream(stream)
                assert link.eval("2 + 2") == 4
                logger.debug(f"Connected to {pipe_name}")
                return link
            except pywintypes.error:
                time.sleep(1)
                continue

        raise DragodisError(f"Could not connect to {pipe_name} after {retry} tries.")

    def start(self):
        if self._running:
            raise ValueError(f"IDA disassembler already running.")

        # Create unique named pipe or socket path, depending on OS.
        socket_path = None
        pipe_name = None
        if sys.platform == "win32":
            pipe_name = str(uuid.uuid4())
        else:
            socket_path = tempfile.mktemp()

        # We need to temporarily change the current directory to be within the ida path so we don't
        # have spaces in script file path.
        # For an unknown reason, IDA hates spaces in its script path.
        # TODO: Fix this so we don't need this.
        orig_cwd = os.getcwd()
        try:
            os.chdir(self._ida_path)
            script_path = os.path.relpath(self._script_path, self._ida_path)
            # Create the command to start IDA with the bridge_server script
            command = [
                self._ida_exe,
                "-P",
                "-A",
                f'-S""{script_path}" "{pipe_name or socket_path}""',
                f'-L"{self.input_path}_ida.log"',
                f'"{self.input_path}"',  # Input file MUST be last!
            ]

            command = " ".join(command)
            logger.debug(f"Running IDA with command: {command}")

            # TODO: Clean up ida temp files if we fail.
            self._process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=sys.platform != "win32")
            atexit.register(self._process.kill)
        finally:
            os.chdir(orig_cwd)

        logger.debug(f"Initializing IDA Bridge connection...")
        if socket_path:
            self._bridge = self.unix_connect(socket_path)
            # Remember socket path so we can close it later.
            self._socket_path = socket_path
        elif pipe_name:
            self._bridge = self.win_connect(pipe_name)
        else:
            raise RuntimeError("Unexpected error. Failed to setup socket or pipe.")
        self._initialize_bridge()
        self._running = True
        self._idc.auto_wait()

        logger.debug("IDA Disassembler ready!")

    def stop(self, *exc_info):
        if not self._running:
            return

        logger.debug("Shutting down IDA Bridge server...")
        self._bridge.close()

        if self._socket_path:
            os.remove(self._socket_path)
            self._socket_path = None

        self._running = False
        logger.debug("IDA Bridge server closed.")

    def _async(self, proxy_func) -> Callable[_, rpyc.AsyncResult]:
        """
        Runs the given proxied function asynchronously.
        Good for functions that we don't care to get results back from.
        """
        return rpyc.async_(proxy_func)
