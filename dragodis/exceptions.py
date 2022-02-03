class DragodisError(Exception):
    """Base exception for Dragodis exceptions."""
    pass


class NotInstalledError(DragodisError):
    """
    Raised when trying to use open_program() on a disassembler not installed.
    """


class NotExistError(DragodisError):
    """
    Raised when a disassembler call returns the disassembler specific value
    designating that the desired value does not exist.

    e.g. Trying to get a function with an address that is not part of a function.
    """


class UnsupportedError(DragodisError):
    """
    Raised when a feature is not supported by the current dissassembler.
    """
