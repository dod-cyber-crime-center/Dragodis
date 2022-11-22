
from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Iterable

from dragodis.ghidra.flowchart import GhidraFlowchart
from dragodis.ghidra.function_signature import GhidraFunctionSignature
from dragodis.ghidra.instruction import GhidraInstruction
from dragodis.ghidra.reference import GhidraReference
from dragodis.ghidra.stack import GhidraStackFrame
from dragodis.interface import Function, CommentType

if TYPE_CHECKING:
    import ghidra
    from dragodis.ghidra.flat import GhidraFlatAPI


class GhidraFunction(Function):

    def __init__(self, ghidra: GhidraFlatAPI, function: "ghidra.program.model.listing.Function"):
        super().__init__(ghidra)
        self._ghidra = ghidra
        self._function = function

    def __contains__(self, addr: int) -> bool:
        return self._body.contains(self._ghidra._to_addr(addr))

    @property
    def _body(self) -> "ghidra.program.model.address.AddressSetView":
        return self._function.getBody()

    @property
    def start(self) -> int:
        return self._function.getEntryPoint().getOffset()

    @property
    def end(self) -> int:
        # NOTE: Calling next() to get the address AFTER the last instruction.
        #   This is to replicate the non-inclusionary characteristics of IDA.
        return self._body.getMaxAddress().next().getOffset()

    @property
    def flowchart(self) -> GhidraFlowchart:
        return GhidraFlowchart(self._ghidra, self._body)

    def get_comment(self, comment_type=CommentType.plate) -> Optional[str]:
        if comment_type in (CommentType.anterior, CommentType.plate):
            return self._function.getComment()
        elif comment_type == CommentType.repeatable:
            return self._function.getRepeatableComment()
        else:
            raise ValueError(f"Invalid comment type for function: {repr(comment_type)}")

    @property
    def name(self) -> str:
        return self._function.getName()

    @name.setter
    def name(self, value: Optional[str]):
        from ghidra.program.model.symbol import SourceType
        self._function.setName(value, SourceType.USER_DEFINED)

    def set_comment(self, comment: Optional[str], comment_type=CommentType.plate):
        if comment_type in (CommentType.anterior, CommentType.plate):
            self._function.setComment(comment)
        elif comment_type == CommentType.repeatable:
            self._function.setRepeatableComment(comment)
        else:
            raise ValueError(f"Invalid comment type for function: {repr(comment_type)}")

    @property
    def source_code(self) -> Optional[str]:
        code = self._ghidra._decomp_api.decompile(self._function)
        # Remove carriage returns, leaving only the newlines.
        code = code.replace("\r", "")
        return code

    @property
    def stack_frame(self) -> GhidraStackFrame:
        return GhidraStackFrame(self._ghidra, self._function.getStackFrame())

    @property
    def signature(self) -> GhidraFunctionSignature:
        return GhidraFunctionSignature(self._ghidra, self._function)

    @property
    def is_library(self) -> bool:
        return self._function in self._ghidra._static_functions
