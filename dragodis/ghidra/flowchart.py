
from __future__ import annotations
from typing import TYPE_CHECKING, Iterable, List

from dragodis.exceptions import NotExistError

from dragodis.ghidra.line import GhidraLine
from dragodis.ghidra.utils import iterate, convert_flow_type
from dragodis.interface import Flowchart, BasicBlock, FlowType

if TYPE_CHECKING:
    import ghidra
    from dragodis.ghidra.flat import GhidraFlatAPI


class GhidraBasicBlock(BasicBlock):

    def __init__(self, ghidra: GhidraFlatAPI, block: "ghidra.program.model.block.CodeBlockImpl"):
        super().__init__(ghidra)
        self._ghidra = ghidra
        self._block = block

    # NOTE: For some unknown reason, GhidraBasicBlock doesn't inherit the BasicBlock.__hash__() function.
    def __hash__(self):
        return hash(self.start)

    def __eq__(self, other) -> bool:
        return isinstance(other, GhidraBasicBlock) and self._block.hasSameAddresses(other._block)

    def __len__(self) -> int:
        return self._block.getNumAddresses()

    def __contains__(self, addr: int) -> bool:
        try:
            addr = self._ghidra._to_addr(addr)
        except NotExistError:
            return False
        return self._block.contains(addr)

    @property
    def start(self) -> int:
        return self._block.getFirstStartAddress().getOffset()

    @property
    def end(self) -> int:
        return self._block.getMaxAddress().getOffset() + 1

    @property
    def flow_type(self) -> FlowType:
        return convert_flow_type(self._block.getFlowType())

    @property
    def flowchart(self) -> "GhidraFlowchart":
        return self._ghidra.get_function(self.start).flowchart

    @property
    def blocks_to(self) -> Iterable["GhidraBasicBlock"]:
        for block_ref in iterate(self._block.getSources(self._ghidra._monitor)):
            block = GhidraBasicBlock(self._ghidra, block_ref.getSourceBlock())
            if block in self.flowchart:
                yield block

    @property
    def blocks_from(self) -> Iterable["GhidraBasicBlock"]:
        for block_ref in iterate(self._block.getDestinations(self._ghidra._monitor)):
            block = GhidraBasicBlock(self._ghidra, block_ref.getDestinationBlock())
            if block in self.flowchart:
                yield block


class GhidraFlowchart(Flowchart):

    def __init__(self, ghidra: GhidraFlatAPI, address_set: "ghidra.program.model.address.AddressSetView"):
        self._ghidra = ghidra
        self._address_set = address_set

    def __contains__(self, block: GhidraBasicBlock):
        return self._address_set.contains(block._block.getFirstStartAddress())

    @property
    def blocks(self) -> Iterable[GhidraBasicBlock]:
        iterator = self._ghidra._basic_block_model.getCodeBlocksContaining(
            self._address_set, self._ghidra._monitor
        )
        for block in iterate(iterator):
            yield GhidraBasicBlock(self._ghidra, block)

    def get_block(self, addr: int) -> GhidraBasicBlock:
        """
        Gets BasicBlock containing given address.
        Defaults to iterating each block and checking if address is contained within.

        :raises NotExistError: If block doesn't exist with in the flowchart for the given address.
        """
        block = self._ghidra._basic_block_model.getFirstCodeBlockContaining(
            self._ghidra._to_addr(addr), self._ghidra._monitor
        )
        if block:
            return GhidraBasicBlock(self._ghidra, block)
        else:
            raise NotExistError(f"Unable to find block containing address 0x{addr:08x} within flowchart.")
