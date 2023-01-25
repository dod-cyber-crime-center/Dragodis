from __future__ import annotations
import logging
from typing import Optional, TYPE_CHECKING

from dragodis.exceptions import *
from dragodis.ida.flowchart import IDAFlowchart
from dragodis.ida.stack import IDAStackFrame
from dragodis.interface import Function, CommentType

if TYPE_CHECKING:
    import ida_funcs
    from dragodis.ida.flat import IDAFlatAPI


logger = logging.getLogger(__name__)


# TODO: Cache this function to return same object for same address.
#   (However, different addresses can be the same function!!!)
class IDAFunction(Function):

    def __init__(self, ida: IDAFlatAPI, func_t: "ida_funcs.func_t"):
        super().__init__(ida)
        self._ida = ida
        self._func_t = func_t
        self._name = None

    def __contains__(self, addr: int) -> bool:
        # NOTE: We can't just test if it's between start and end because the
        # function might have fragmented function chunks.
        try:
            func = self._ida.get_function(addr)
        except Exception:  # TODO: catch appropriate exception as used above.
            return False
        # return func is self  # TODO: Should be able to do this when reuse caching is on
        return func.start == self.start

    @property
    def start(self) -> int:
        return self._func_t.start_ea

    @property
    def end(self) -> int:
        return self._func_t.end_ea

    @property
    def flowchart(self) -> IDAFlowchart:
        return IDAFlowchart(self._ida, self._ida._ida_gdl.FlowChart(self._func_t))

    def get_comment(self, comment_type=CommentType.anterior) -> Optional[str]:
        # If user asks for anterior or eol, assume they mean the same thing.
        if comment_type in (CommentType.anterior, CommentType.plate):
            return self._ida._ida_funcs.get_func_cmt(self._func_t, 0)
        elif comment_type == CommentType.repeatable:
            return self._ida._ida_funcs.get_func_cmt(self._func_t, 1)
        else:
            raise ValueError(f"Invalid comment type for function: {repr(comment_type)}")

    @property
    def name(self) -> str:
        if not self._name:
            self._name = self._ida._ida_funcs.get_func_name(self.start)
        return self._name

    @name.setter
    def name(self, new_name: Optional[str]):
        success = self._ida._ida_name.set_name(
            self.start, new_name or "", self._ida._ida_name.SN_NOCHECK)
        if not success:
            raise ValueError(f"Failed to set function name at {hex(self.start)} with {new_name}")
        self._name = None  # clear cache

    def set_comment(self, comment: str, comment_type=CommentType.anterior):
        # IDA takes an empty string to clear comments
        if not comment:
            comment = ""

        # If user asks for anterior or eol, assume they mean the same thing.
        if comment_type in (CommentType.anterior, CommentType.plate):
            self._ida._ida_funcs.set_func_cmt(self._func_t, comment, 0)
        elif comment_type == CommentType.repeatable:
            self._ida._ida_funcs.set_func_cmt(self._func_t, comment, 1)
        else:
            raise ValueError(f"Invalid comment type for function: {repr(comment_type)}")

    @property
    def source_code(self) -> Optional[str]:
        decompiled_code = self._ida._ida_helpers.decompiled_code(self.start)
        if decompiled_code:
            return str(decompiled_code)

    @property
    def stack_frame(self) -> IDAStackFrame:
        return IDAStackFrame(self._ida, self._ida._ida_frame.get_frame(self._func_t))

    @property
    def is_library(self) -> bool:
        return bool(self._func_t.flags & self._ida._ida_funcs.FUNC_LIB)
