
import logging
import os
from typing import TYPE_CHECKING, Optional

import pyhidra

from dragodis.exceptions import NotInstalledError
from dragodis.interface import BackendDisassembler

# Used for typing to help Pycharm give us autocompletion.
if TYPE_CHECKING:
    import ghidra

logger = logging.getLogger(__name__)


class GhidraDisassembler(BackendDisassembler):

    name = "Ghidra"

    def __init__(self, input_path, ghidra_path=None):
        """
        Initializes Ghidra disassembler.

        :param input_path: Path of binary to process.
        :param ghidra_path: Path to Ghidra directory.
            This may also be set using the environment variable GHIDRA_INSTALL_DIR
        """
        super().__init__(input_path)
        ghidra_path = ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR", os.environ.get("GHIDRA_DIR"))
        if not ghidra_path:
            raise NotInstalledError(
                "Failed to get Ghidra install directory. "
                "Please provide it during instantiation or set the GHIDRA_INSTALL_DIR environment variable."
            )
        # Set environment variable for pyhidra.
        os.environ["GHIDRA_INSTALL_DIR"] = ghidra_path

        self._running = False

        # Built on start()
        self._bridge = None
        self._flatapi = None     # type: Optional[ghidra.program.flatapi.FlatProgramAPI]
        self._program = None     # type: Optional[ghidra.program.database.ProgramDB]
        self._listing = None     # type: Optional[ghidra.program.model.listing.Listing]

        # Built on demand
        self.__decomp_api = None
        self.__basic_block_model = None
        self.__monitor = None

    def start(self):
        if self._running:
            raise ValueError(f"Ghidra disassembler already running.")

        logger.debug(f"Starting pyhidra connection to {self.input_path}")
        self._bridge = pyhidra.open_program(self.input_path)
        self._flatapi = self._bridge.__enter__()
        self._program = self._flatapi.getCurrentProgram()
        self._listing = self._program.getListing()

        self._running = True
        logger.debug("Ghidra Disassembler ready!")

    def stop(self, *exc_info):
        logger.debug("Shutting down Ghidra connection...")
        if not self._running:
            return
        self._decomp_api.dispose()
        self._bridge.__exit__(*exc_info)
        self._bridge = None
        self._running = False
        logger.debug("Ghidra connection closed.")

    # region Helper Functions

    @property
    def _decomp_api(self) -> "ghidra.app.decompiler.flatapi.FlatDecompilerAPI":
        if not self.__decomp_api:
            from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
            self.__decomp_api = FlatDecompilerAPI(self._flatapi)
        return self.__decomp_api

    @property
    def _basic_block_model(self) -> "ghidra.program.model.block.BasicBlockModel":
        if not self.__basic_block_model:
            from ghidra.program.model.block import BasicBlockModel
            self.__basic_block_model = BasicBlockModel(self._program)
        return self.__basic_block_model

    @property
    def _monitor(self) -> "ghidra.util.task.TaskMonitor":
        if not self.__monitor:
            from ghidra.util.task import TaskMonitor
            self.__monitor = TaskMonitor.DUMMY
        return self.__monitor


    # endregion
