"""
Helper utilities for Ghidra
"""
from typing import TYPE_CHECKING

from dragodis.interface import FlowType

if TYPE_CHECKING:
    import ghidra


def iterate(java_iterator):
    """
    Sometimes jpype doesn't pick up some of Ghidra's Iterator objects in order
    to automatically convert it to a python iterator.
    Therefore, this can be used to manually iterate a given java iterator as a python generator.
    """
    while java_iterator.hasNext():
        yield java_iterator.next()


def convert_flow_type(flow_type: "ghidra.program.model.symbol.FlowType") -> FlowType:
    """
    Converts a Ghidra FlowType to a Dragodis FlowType

    :raises TypeError: Encountered unknown/unsupported flow type.
    """
    if flow_type.isCall():
        return FlowType.call
    elif flow_type.isTerminal():
        return FlowType.terminal
    elif flow_type.isJump():
        if flow_type.isConditional():
            return FlowType.conditional_jump
        elif flow_type.isUnConditional():
            return FlowType.unconditional_jump
    elif flow_type.isFallthrough():
        return FlowType.fall_through

    raise TypeError(f"Unknown flow type: {flow_type}")
