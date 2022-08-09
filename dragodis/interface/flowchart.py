
from __future__ import annotations
import abc
import functools
from typing import Iterable, TYPE_CHECKING, Optional, Set

from dragodis.exceptions import NotExistError

if TYPE_CHECKING:
    from dragodis.interface import FlowType, Line, FlatAPI


@functools.total_ordering
class BasicBlock(metaclass=abc.ABCMeta):

    def __init__(self, api: FlatAPI):
        self._api = api

    def __str__(self) -> str:
        return f"block[0x{self.start:08x} --> 0x{self.end:08x}]"

    def __repr__(self) -> str:
        return f"<BasicBlock 0x{self.start:08x} --> 0x{self.end:08x}>"

    def __hash__(self):
        return hash(self.start)

    def __eq__(self, other) -> bool:
        """
        Checks equality of Basic Blocks.
        Defaults to checking that the start addresses are the same.
        """
        return isinstance(other, self.__class__) and self.start == other.start

    def __lt__(self, other):
        return self.start < other.start

    def __contains__(self, addr: int) -> bool:
        """
        Returns whether the given address is within the block.
        Defaults to checking if address is in-between start and end.
        """
        return self.start <= addr < self.end

    def __len__(self) -> int:
        """
        Returns the number of lines within the blocks.
        Defaults to checking length of self.lines
        """
        return len(list(self.lines()))

    @property
    @abc.abstractmethod
    def start(self) -> int:
        """
        The start address for the block.
        """

    @property
    @abc.abstractmethod
    def end(self) -> int:
        """
        The end address for the block.
        The end address is *not* part of the block.
        """

    @property
    @abc.abstractmethod
    def flow_type(self) -> FlowType:
        """
        The type of code flow for how things exit this block.
        """

    @property
    @abc.abstractmethod
    def flowchart(self) -> "Flowchart":
        """
        The Flowchart this block is contained in.
        """

    @property
    @abc.abstractmethod
    def blocks_to(self) -> Iterable["BasicBlock"]:
        """
        Iterates BasicBlocks that flow to this block.
        """

    @property
    @abc.abstractmethod
    def blocks_from(self) -> Iterable["BasicBlock"]:
        """
        Iterates BasicBlocks that flow from this block.
        """

    # TODO: Rename to instructions?
    def lines(self, start=None, reverse=False) -> Iterable[Line]:
        """
        Iterates Lines within the block.

        :param start: Start address (defaults to start or end address)
        :param reverse: Direction to iterate

        :yields: Line objects

        :raises NotExistError: If given start address is not in block
        """
        if start is not None and start not in self:
            raise NotExistError(f"Start address {hex(start)} is not in block.")

        if reverse:
            start = start or (self.end - 1)
            end = self.start - 1
        else:
            start = start or self.start
            end = self.end

        yield from self._api.lines(start=start, end=end, reverse=reverse)

    @property
    def ancestors(self) -> Set["BasicBlock"]:
        """
        Returns a set of ancestor blocks for the given block.

        :returns: Set of ancestor blocks.
        """
        ancestors = set()

        to_process = [self]
        while to_process:
            block = to_process.pop()
            for parent in block.blocks_to:
                if parent not in ancestors and parent != self:
                    ancestors.add(parent)
                    to_process.append(parent)

        return ancestors


class Flowchart(metaclass=abc.ABCMeta):

    def __len__(self) -> int:
        """
        Returns the number of basic blocks within the flowchart.
        Defaults to checking length of self.blocks
        """
        return sum(1 for _ in self.blocks)

    def __contains__(self, block: BasicBlock):
        """
        Tests if given block is in the flowchart.
        Overwrite for optimized implementation.
        """
        for _block in self.blocks:
            if _block == block:
                return True
        return False

    def __eq__(self, other):
        """
        Tests equality of Flowchart.
        Defaults to checking equality of all BasicBlocks.
        """
        if not isinstance(other, self.__class__):
            return False
        return all(b1 == b2 for b1, b2 in zip(self.blocks, other.blocks))

    def __str__(self) -> str:
        # Get first block to indicate address.
        start = self.start
        start = f"0x{start:08x}" if start is not None else "Empty"
        return f"flowchart[{start}]"

    def __repr__(self):
        blocks = "\t\n".join(map(repr, self.blocks))
        return f"<Flowchart \n\t{blocks}\n>"

    # TODO: This function should enforce that the order of the blocks is by address?
    #   I.E. Whatever the order IDA does.
    #   This will avoid the need for having a "start_block".
    @property
    @abc.abstractmethod
    def blocks(self) -> Iterable[BasicBlock]:
        """
        Iterates BasicBlocks within the flowchart.
        Blocks should be yielded in order of address. (ie. the order you see them in list view)
        """

    def _traverse(self, start_ea=None, dfs=False):
        """
        Blind traversal of the graph.

        :param int start_ea: EA within a block from which to start traversing
        :param bool dfs: If true, traversal will be depth-first. If false, traversal will be breadth-first.

        :yield BasicBlock: function block object
        """
        # Set our flag to True if start_ea is none so we yield all blocks, else wait till we find the requested block
        block_found = start_ea is None

        # Pull starting block.
        for block in self.blocks:
            non_visited = [block]
            break
        else:
            return

        visited = set()
        while non_visited:
            cur_block = non_visited.pop(0)
            if hash(cur_block) in visited:
                continue

            visited.add(hash(cur_block))
            succs = sorted(cur_block.blocks_from)
            if dfs:
                # [0:0] allows us to extend to the front
                non_visited[0:0] = succs
            else:
                non_visited.extend(succs)

            if not block_found:
                block_found = start_ea in cur_block

            if block_found:
                yield cur_block

    def _traverse_reverse(self, start=None, dfs=False) -> Iterable[BasicBlock]:
        """
        Perform a reverse traversal of the graph in depth-first/breadth-first manner where given a start node, traverse 1 complete
        path to the root node before following additional paths.

        :param start: Address within a block from which to start traversing
        :param dfs: If true, traversal will be depth-first. If false, traversal will be breadth-first.
        """
        if start:
            non_visited = [self.get_block(start)]
        else:
            non_visited = sorted(self.blocks, key=lambda bb: bb.start)[-1:]

        visited = set()
        while non_visited:
            cur_block = non_visited.pop(0)
            if hash(cur_block) in visited:
                continue

            visited.add(hash(cur_block))

            preds = sorted(cur_block.blocks_to, reverse=True)
            # For now, only consider predicates that are before the current block.
            # This helps to prevent cyclic loops.
            preds = [pred for pred in preds if pred < cur_block]
            if dfs:
                non_visited[0:0] = preds
            else:
                non_visited.extend(preds)

            yield cur_block

    def traverse(self, start=None, reverse=False, dfs=False) -> Iterable[BasicBlock]:
        """
        Iterates over basic blocks within the same order as code flow.

        :param start: optional start address to start iterating from.
        :param reverse: iterate in reverse.
        :param dfs: If true, traversal will be depth-first. If false, traversal will be breadth-first.
        """
        if reverse:
            yield from self._traverse_reverse(start, dfs=dfs)
        else:
            yield from self._traverse(start, dfs=dfs)

    def lines(self, start=None, reverse=False, dfs=False):
        """
        """
        _first_block = True
        for block in self.traverse(start, reverse=reverse, dfs=dfs):
            if start and _first_block:
                yield from block.lines(start, reverse=reverse)
            else:
                yield from block.lines(reverse=reverse)
            _first_block = False

    def get_block(self, addr: int) -> BasicBlock:
        """
        Gets BasicBlock containing given address.
        Defaults to iterating each block and checking if address is contained within.

        :raises NotExistError: If block doesn't exist with in the flowchart for the given address.
        """
        for block in self.blocks:
            if addr in block:
                return block
        raise NotExistError(f"Unable to find block containing address 0x{addr:08x} within flowchart.")

    @property
    def start(self) -> Optional[int]:
        """
        The first address or the first block, which should be the entry point
        or None if flowchart contains no blocks.
        (Override this function, if that is not the case.)
        """
        for block in self.blocks:
            return block.start
