from __future__ import annotations
from typing import TYPE_CHECKING, Union, Optional

from dragodis.interface.operand_value import (
    OperandValue, Immediate, MemoryReference, Register, RegisterList,
    Phrase,
)


if TYPE_CHECKING:
    import ghidra


class GhidraImmediate(Immediate):
    ...


class GhidraMemoryReference(MemoryReference):
    ...


class GhidraRegister(Register):

    def __init__(self, register: "ghidra.program.model.lang.Register"):
        self._register = register

    def __eq__(self, register: "GhidraRegister"):
        if isinstance(register, GhidraRegister):
            return self._register.equals(register._register)
        return False

    @property
    def bit_width(self) -> int:
        return int(self._register.getBitLength())

    @property
    def mask(self) -> int:
        mask = bytes(self._register.getBaseMask())
        return int.from_bytes(mask, byteorder='big', signed=False)

    @property
    def base(self) -> GhidraRegister:
        return GhidraRegister(self._register.getBaseRegister())

    @property
    def name(self) -> str:
        return str(self._register.getName()).lower()


class GhidraRegisterList(RegisterList):
    ...


class GhidraPhrase(Phrase):
    """
    Defines general "phrase" operand in Ghidra.
    """

    def __init__(
            self,
            base: Optional[GhidraRegister] = None,
            index: Optional[GhidraRegister] = None,
            scale: int = 1,
            offset: Union[GhidraRegister, int] = 0,
    ):
        """
        Initializes phrase with given base, index, scale, and offset
        (from GhidraOperand)
        """
        self._base = base
        self._index = index
        # Wrapping in int() to remove Java nonsense.
        self._scale = int(scale)
        if not isinstance(offset, GhidraRegister):
            offset = int(offset)
        self._offset = offset

    @property
    def base(self) -> Optional[GhidraRegister]:
        return self._base

    @property
    def index(self) -> Optional[GhidraRegister]:
        return self._index

    @property
    def scale(self) -> int:
        return self._scale

    @property
    def offset(self) -> Union[GhidraRegister, int]:
        return self._offset
