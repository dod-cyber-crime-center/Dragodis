"""
Base interface for dragodis
"""
from __future__ import annotations

# Import available disassemblers so they get registered.
import os
import pathlib
from typing import Union, Type, TYPE_CHECKING

from dragodis import utils
from dragodis.ghidra import GhidraLocal, GhidraRemote
from dragodis.ida import IDALocal, IDARemote
from dragodis.interface import FlatAPI


IDA = IDALocal if utils.in_ida() else IDARemote

def Ghidra(*args, **kwargs):
    # Need to dynamically provide Ghidra disassembler since detection can be wrong if
    # this module gets imported prematurely by a plugin before pyhidra sets up the interpreter.
    if utils.in_ghidra():
        return GhidraLocal(*args, **kwargs)
    else:
        return GhidraRemote(*args, **kwargs)

if TYPE_CHECKING:
    Ghidra = GhidraLocal if utils.in_ghidra() else GhidraRemote


# Expose flat api when user wants to do typing.
Disassembler = FlatAPI


def _get_class(name: str = None) -> Type[Disassembler]:
    # If name not provided, see if we can detect we are inside a disassembler. If so, use that.
    if not name:
        if utils.in_ida():
            return IDA
        if utils.in_ghidra():
            return Ghidra

    disassembler_name = name or os.environ.get("DRAGODIS_DISASSEMBLER", None)
    if not disassembler_name:
        raise ValueError(
            "No disassembler provided. "
            "Please provide disassembler name as an argument or by setting "
            "the environment variable 'DRAGODIS_DISASSEMBLER'."
        )
    if disassembler_name.lower() == "ida":
        return IDA
    elif disassembler_name.lower() == "ghidra":
        return Ghidra
    else:
        raise ValueError(f"Not a valid disassembler: {disassembler_name}")


def open_program(
        file_path: Union[str, pathlib.Path],
        disassembler: str = None,
        **config
) -> Disassembler:
    """
    Opens given file in the given disassembler.

    :param file_path: Path to binary file to disassemble.
    :param disassembler: Name of disassembler to use.
        (Defaults to disassembler provided in DRAGODIS_DISASSEMBLER environment variable.)
    :param config: Arguments to pass to disassembler during instantiation.
        Non-applicable arguments will be ignored.

    :raises NotInstalledError: If the specified disassembler has not been installed.
    :raises ValueError: If the specified disassembler is not supported.
    """
    file_path = pathlib.Path(file_path)
    return _get_class(disassembler)(file_path, **config)
