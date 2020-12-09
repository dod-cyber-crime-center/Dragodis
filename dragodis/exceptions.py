class DragodisError(Exception):
    """Base exception for Dragodis exceptions."""

    pass


class NotExistError(DragodisError):
    """
    Raised when a disassembler call returns the disassembler specific value
    designating that the desired value does not exist.

    e.g. Trying to get a function with an address that is not part of a function.
    """

    pass
