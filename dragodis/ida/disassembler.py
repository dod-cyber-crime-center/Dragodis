
from __future__ import annotations

import pathlib

import atexit
import gc
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
from rpyc.utils import factory

from dragodis.exceptions import DragodisError, NotInstalledError
from dragodis.interface import BackendDisassembler
from dragodis.interface.types import ProcessorType
from dragodis.ida import ida_server, constants
from dragodis.constants import BACKEND_IDA
from dragodis import utils

# Used for typing to help Pycharm give us autocompletion.
# To setup, add %IDA_DIR%\python\3 directory into the interpreter path using Pycharm.
if typing.TYPE_CHECKING:
    import idaapi
    import idc
    import idautils
    import ida_auto
    import ida_bitrange
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
    import ida_search
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


class IDADisassembler(BackendDisassembler):
    """
    Backend IDA disassembler (interface)
    """
    name = BACKEND_IDA

    PROCESSOR_ARM = constants.PROCESSOR_ARM
    PROCESSOR_ARM64 = constants.PROCESSOR_ARM
    PROCESSOR_X86 = constants.PROCESSOR_METAPC
    PROCESSOR_X64 = constants.PROCESSOR_METAPC

    _BADADDR: int
    _idaapi: idaapi
    _idc: idc
    _idautils: idautils
    _ida_auto: ida_auto
    _ida_bitrange: ida_bitrange
    _ida_bytes: ida_bytes
    _ida_funcs: ida_funcs
    _ida_gdl: ida_gdl
    _ida_name: ida_name
    _ida_xref: ida_xref
    _ida_ua: ida_ua
    _ida_idp: ida_idp
    _ida_ida: ida_ida
    _ida_lines: ida_lines
    _ida_nalt: ida_nalt
    _ida_hexrays: ida_hexrays
    _ida_segment: ida_segment
    _ida_loader: ida_loader
    _ida_typeinf: ida_typeinf
    _ida_entry: ida_entry
    _ida_struct: ida_struct
    _ida_frame: ida_frame
    _ida_search: ida_search
    _ida_arm: ida_arm
    _ida_intel: ida_intel
    _ida_helpers: ida_helpers


class IDALocalDisassembler(IDADisassembler):
    """
    Backend used when we are natively in the IDA interpreter.
    """

    def __init__(self, input_path=None, **unused):
        import idc
        super().__init__(idc.get_input_file_path())

        # Input path is not required when inside IDA, but if provided
        # let's use it to validate we are looking at the right file.
        if input_path and pathlib.Path(input_path).resolve() != self.input_path:
            raise ValueError(
                f"Expected input path isn't the same as the file loaded in IDA: {input_path} != {self.input_path}")
        self.start()

    def start(self):
        import idc
        self._BADADDR = idc.BADADDR
        self._idc = idc
        import idaapi
        self._idaapi = idaapi
        import idautils
        self._idautils = idautils
        import ida_auto
        self._ida_auto = ida_auto
        import ida_bitrange
        self._ida_bitrange = ida_bitrange
        import ida_bytes
        self._ida_bytes = ida_bytes
        import ida_funcs
        self._ida_funcs = ida_funcs
        import ida_gdl
        self._ida_gdl = ida_gdl
        import ida_name
        self._ida_name = ida_name
        import ida_xref
        self._ida_xref = ida_xref
        import ida_ua
        self._ida_ua = ida_ua
        import ida_idp
        self._ida_idp = ida_idp
        import ida_ida
        self._ida_ida = ida_ida
        import ida_lines
        self._ida_lines = ida_lines
        import ida_nalt
        self._ida_nalt = ida_nalt
        import ida_hexrays
        self._ida_hexrays = ida_hexrays
        import ida_segment
        self._ida_segment = ida_segment
        import ida_loader
        self._ida_loader = ida_loader
        import ida_typeinf
        self._ida_typeinf = ida_typeinf
        import ida_entry
        self._ida_entry = ida_entry
        import ida_struct
        self._ida_struct = ida_struct
        import ida_frame
        self._ida_frame = ida_frame
        import ida_search
        self._ida_search = ida_search
        from .sdk import ida_arm
        self._ida_arm = ida_arm
        from .sdk import ida_intel
        self._ida_intel = ida_intel
        from .sdk import ida_helpers
        self._ida_helpers = ida_helpers

        idc.auto_wait()


class IDARemoteDisassembler(IDADisassembler):
    """
    Backend disassembler when we are remotely accessing IDA through rpyc.
    """

    _rpyc_config = {
        # Increasing timeout to give IDA more time to analyze larger files.
        "sync_request_timeout": 60
    }

    def __init__(self, input_path, is_64_bit=None, ida_path=None, timeout=None, processor=None, **unused):
        """
        Initializes IDA disassembler.

        :param input_path: Path of binary to process.
        :param is_64_bit: Whether input file is 64bit or 32bit.
            If left as None, this will be determined by analyzing the input file.
        :param ida_path: Path to IDA directory.
            This may also be set using the environment variable IDA_INSTALL_DIR
        :param timeout: Number of seconds to wait for remote results. (defaults to 60)
        :param processor: Processor type (defaults to auto detected)
            (https://hex-rays.com/products/ida/support/idadoc/618.shtml)
        """
        super().__init__(input_path, processor=processor)
        self._ida_path = ida_path or os.environ.get("IDA_INSTALL_DIR", os.environ.get("IDA_DIR"))
        if not self._ida_path:
            raise NotInstalledError(
                "Failed to get IDA install directory. "
                "Please provide it during instantiation or set the IDA_INSTALL_DIR environment variable."
            )
        self._script_path = ida_server.__file__
        if timeout is not None:
            self._rpyc_config = dict(self._rpyc_config)
            self._rpyc_config["sync_request_timeout"] = timeout

        # Determine if 64 bit.
        if is_64_bit is None:
            input_path = str(input_path)
            # First check if input file is a .idb or .i64
            if input_path.endswith(".i64"):
                is_64_bit = True
            elif input_path.endswith(".idb"):
                is_64_bit = False
            elif processor in (ProcessorType.ARM64, ProcessorType.x64):
                is_64_bit = True
            elif processor in (ProcessorType.ARM, ProcessorType.x86):
                is_64_bit = False
            else:
                is_64_bit = utils.is_64_bit(input_path)

        # Find ida executable within ida_dir.
        # TODO: Should we just always open with ida64?
        ida_exe_re = re.compile(r"idaq?64(\.exe)?$" if is_64_bit else r"idaq?(\.exe)?$")
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
        self._root = None
        self._BADADDR = 0xFFFFFFFFFFFFFFFF if is_64_bit else 0xFFFFFFFF

        self._idaapi = None
        self._idc = None
        self._idautils = None
        self._ida_auto = None
        self._ida_bitrange = None
        self._ida_bytes = None
        self._ida_funcs = None
        self._ida_gdl = None
        self._ida_name = None
        self._ida_xref = None
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
        self._ida_search = None
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
            self._ida_auto = ida_auto
            self._ida_bitrange = ida_bitrange
            self._ida_bytes = ida_bytes
            self._ida_funcs = ida_funcs
            self._ida_gdl = ida_gdl
            self._ida_name = ida_name
            self._ida_xref = ida_xref
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
            self._ida_search = ida_search
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
        remote_logger = self._bridge.modules.logging.getLogger()
        remote_logger.parent = logger
        remote_logger.setLevel(logger.getEffectiveLevel())

        # Import IDA modules.
        self._idaapi: idaapi = _Cached(self._bridge.root.getmodule("idaapi"))
        self._idc: idc = _Cached(self._bridge.root.getmodule("idc"))
        self._idautils: idautils = _Cached(self._bridge.root.getmodule("idautils"))
        self._ida_auto: ida_auto = _Cached(self._bridge.root.getmodule("ida_auto"))
        self._ida_bitrange: ida_bitrange = _Cached(self._bridge.root.getmodule("ida_bitrange"))
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
        self._ida_search: ida_search = _Cached(self._bridge.root.getmodule("ida_search"))

        # Need to first add our custom sdk package to the path to import custom modules.
        from . import sdk
        self._bridge.modules.sys.path.extend(sdk.__path__)

        self._ida_arm: ida_arm = _Cached(self._bridge.root.getmodule("ida_arm"))
        self._ida_intel: ida_intel = _Cached(self._bridge.root.getmodule("ida_intel"))
        self._ida_helpers: ida_helpers = _Cached(self._bridge.root.getmodule("ida_helpers"))

    def unix_connect(self, socket_path, retry=10) -> rpyc.Connection:
        """
        Connects to bridge using unix socket.
        """
        for i in range(retry):
            try:
                logger.debug(f"Connecting to socket path: {socket_path}, try {i + 1}")
                stream = SocketStream.unix_connect(socket_path)
                link = factory.connect_stream(stream, rpyc.classic.SlaveService, config=self._rpyc_config)
                link.ping()
                logger.debug(f"Connected to {socket_path}")
                return link
            except socket.error:
                time.sleep(1)
                continue

        raise DragodisError(f"Could not connect to {socket_path} after {retry} tries.")

    def win_connect(self, pipe_name, retry=10) -> rpyc.Connection:
        """
        Connects to bridge using Windows named pipe.
        """
        pipe_name = NamedPipeStream.NAMED_PIPE_PREFIX + pipe_name
        import pywintypes
        for i in range(retry):
            try:
                logger.debug(f"Connecting to pipe: {pipe_name}, try {i + 1}")
                stream = NamedPipeStream.create_client(pipe_name)
                link = factory.connect_stream(stream, rpyc.classic.SlaveService, config=self._rpyc_config)
                link.ping()
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
            socket_path = tempfile.mktemp(prefix="dragodis_")

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
            ]
            if self._processor:
                command.append(f"-p{self._processor}")
            command.append(f'"{self.input_path}"')  # Input file MUST be last!

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
        # Keep a hold of the root remote object to prevent rpyc from prematurely closing on us.
        self._root = self._bridge.root
        self._running = True
        self._idc.auto_wait()

        logger.debug("IDA Disassembler ready!")

    def stop(self, *exc_info):
        if not self._running:
            return

        logger.debug("Shutting down IDA Bridge server...")

        # Before we close the bridge, remove connection to local logger to prevent logs being sent out afterwards.
        self._bridge.modules.logging.getLogger().parent = None

        self._bridge.close()
        self._root = None
        self._bridge = None

        # Wait for server to shutdown completely.
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.error("Failed to properly close IDA process.")
            self._process.kill()

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

    def teleport(self, func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Look for any arguments that pass along the disassembler object itself
            # and replace them with a local instance in IDA.
            # This helps to greatly improve performance.
            new_args = []
            for arg in args:
                if arg is self:
                    self._bridge.execute("import dragodis")
                    terran_dis = self._bridge.eval("dragodis.IDA()")
                    arg = terran_dis
                new_args.append(arg)
            args = tuple(new_args)

            return self._bridge.teleport(func)(*args, **kwargs)

        return wrapper
