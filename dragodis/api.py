"""
Base interface for dragodis
"""
from __future__ import annotations

# Import available disassemblers so they get registered.
import os
import pathlib
from typing import Union

from .exceptions import NotInstalledError

from .ghidra import Ghidra
from .ida import IDA


# Generic typing for any dragodis supported Disassembler.
Disassembler = Union[IDA, Ghidra]


def open_program(
        file_path: Union[str, pathlib.Path],
        disassembler: str = None,
        **disassembler_args
) -> Disassembler:
    """
    Opens given file in the given disassembler.

    :param file_path: Path to binary file to disassemble.
    :param disassembler: Name of disassembler to use.
        (Defaults to disassembler provided in DRAGODIS_DISASSEMBLER environment variable.)
    :param *disassembler_args: Arguments to pass to disassembler during installation.

    :raises NotInstalledError: If the specified disassembler has not been installed.
    :raises ValueError: If the specified disassembler is not supported.
    """
    file_path = pathlib.Path(file_path)

    disassembler_name = disassembler or os.environ.get("DRAGODIS_DISASSEMBLER", None)
    if not disassembler_name:
        raise ValueError(
            "No disassembler provided. "
            "Please provide disassembler name as an argument or by setting "
            "the environment variable 'DRAGODIS_DISASSEMBLER'."
        )
    if disassembler_name.lower() == "ida":
        return IDA(file_path, **disassembler_args)
    elif disassembler_name.lower() == "ghidra":
        return Ghidra(file_path, **disassembler_args)
    else:
        raise ValueError(f"Not a valid disassembler: {disassembler_name}")
