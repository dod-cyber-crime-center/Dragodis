
import abc
import os
import pathlib
from typing import Union, Callable


class BackendDisassembler(metaclass=abc.ABCMeta):
    """
    Disassembler Interface

    Handles the setup and teardown of a backend disassembler.
    Should be combined as a mixin with a FlatAPI class.
    """

    # This should be filled in.
    # TODO: Enforce with zope.interface
    name = None

    def __init__(self, input_path: Union[str, pathlib.Path]):
        """
        Initialization method.

        This  must perform any initialization, setup, or preparation needed to begin making
        regular calls to the disassembler. For instance, executing the
        disassembler binary, performing initial auto-analysis, and/or
        starting a communications server would all be appropriate actions to
        perform here.

        :param str input_path: The path of the file to process
        :raises NotInstalledError: If the disassembler was not installed on the system.
        """
        self.input_path = pathlib.Path(input_path).resolve()

    def __enter__(self):
        """
        Entry method for context manager interface.
        Used to create a context manager for the disassembler.
        """
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """
        Exit method for context manager interface.
        Used to create a context manager for the disassembler.
        """
        self.stop(*(exc_type, exc_value, exc_traceback))

    def start(self):
        """
        Setup method.

        This should be called before starting analysis. Any setup should be done here.

        This can include spawning a process to handle the disassembler, creating a temporary
        workspace for the disassembler, etc...
        """
        pass

    def stop(self, *exc_info):
        """
        Teardown method.

        This should be called upon completion of analysis. Any teardown should be done here.

        This can include saving a generated file (such as an IDB), deleting temporary directories,
        shutting down spawned processes, etc...
        """
        pass

    def teleport(self, func: Callable) -> Callable:
        """
        Teleports function into the underlying disassembler to do disassembler specific things.
        NOTE: This function only applies for certain disassemblers. For others, this does nothing
        but pass back the same function.

        e.g.
            def my_func(addr):
                import ida_funcs
                func = ida_funcs.get_func(addr)
                return func.start_ea

            if dis.name == "IDA":
                start_addr = dis.teleport(my_func)(0x123)

        :param func: Callback function to run in underlying disassembler.
        :return: A new function which when called will be run in the underlying disassembler.
        """
        return func
