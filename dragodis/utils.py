"""
Utility functions used throughout the project.
"""
import contextlib
from typing import Optional

from elftools.common.exceptions import ELFError
from elftools.elf import elffile
import pefile
import pyhidra


class cached_property(property):
    """
    A cached_property which allows a setter.
    When the given property is set, this will automatically invalidate the cache.
    Good for read many / write rarely type properties in which the property value
    could only change if the setter was called.

    To invalidate the cache outside of setting the property use del.
        e.g. del obj.thing
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "__cached_" + self.fget.__name__

    def __get__(self, instance, type=None):
        """
        First attempts to pull from cached results before calling fget.
        """
        if instance is None:
            return self
        try:
            return instance.__dict__[self.name]
        except KeyError:
            res = instance.__dict__[self.name] = self.fget(instance)
            return res

    def __set__(self, instance, value):
        """
        Sets new value and invalidates cache.
        """
        self.fset(instance, value)
        self.__delete__(instance)

    def __delete__(self, instance):
        """
        Invalidates cache.
        """
        try:
            del instance.__dict__[self.name]
        except KeyError:
            pass


def is_64_bit(input_file) -> Optional[bool]:
    """
    Attempt to determine if the file is 64bit based on the pe header.
    Note that the pe.close() prevents an mmap'd file from
    being left open indefinitely as the PE object doesn't seem to get garbage collected.
    Forcing garbage collection also corrects that issue.

    :param input_file: The full path to the file in question

    :returns: True if 64 bit, False if not 64 bit or error in parsing the header.
    """
    # Get first bytes of file to check the file magic
    with open(input_file, "rb") as f:
        first_bytes = f.read(8)

    # PE file type
    if first_bytes[0:2] == b"\x4D\x5A":
        try:
            with contextlib.closing(pefile.PE(input_file, fast_load=True)) as pe:
                return pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
        except pefile.PEFormatError:
            return False

    # elf file type
    elif first_bytes[1:4] == b"\x45\x4C\x46":
        try:
            with open(input_file, "rb") as f:
                elf = elffile.ELFFile(f)
                return elf.get_machine_arch() in ["AArch64", "x64"]
        except ELFError:
            return False

    # 32 bit MACH-O executable
    elif first_bytes[0:4] == b"\xCE\xFA\xED\xFE":
        return False

    # 64 bit MACH-O executable
    elif first_bytes[0:4] == b"\xCF\xFA\xED\xFE":
        return True

    return False


def in_ida() -> bool:
    """
    Detects if we are inside IDA.
    """
    try:
        import idc
        return True
    except (ModuleNotFoundError, ImportError):
        return False


def in_ghidra() -> bool:
    """
    Detects if we are inside a Ghidra interpreter with a program loaded.
    """
    interpreter = pyhidra.get_current_interpreter()
    return bool(interpreter and interpreter.currentProgram)
