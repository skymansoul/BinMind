# /*
#  * Reconstructs original control-flow structures from obfuscated
#  * flattened CFGs produced by tools like O-LLVM and Tigress.
#  *
#  * Core classes: BlockType, BasicBlock, ControlFlowGraph,
#  * ReconstructedStructure, FlattenedCFGAnalyzer, CFGSimplifier
#  */
# Time complexity: O(n), Space: O(log n).
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

logger = logging.getLogger(__name__)


class BlockType(Enum):
    """Type tag for each node in a control-flow graph."""
    NORMAL = "normal"
    DISPATCHER = "dispatcher"
    CONDITIONAL = "conditional"
    LOOP_HEADER = "loop_header"
    RETURN = "return"


@dataclass
class BasicBlock:
    """Single node in a control-flow graph, address-anchored."""
    address: int
    instructions: list = field(default_factory=list)
    block_type: BlockType = BlockType.NORMAL
    frequency: int = 0
    transitions: list = field(default_factory=list)
    original_targets: list = field(default_factory=list)


@dataclass
class ControlFlowGraph:
    """Full graph structure with blocks indexed by address."""
    blocks: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    dispatcher_address: Optional[int] = None


@dataclass
class ReconstructedStructure:
    """Output container for de-flattened control-flow structures."""
    if_else_blocks: list = field(default_factory=list)
    while_loops: list = field(default_factory=list)
    for_loops: list = field(default_factory=list)


class FlattenedCFGAnalyzer:
    """Core analysis engine for identifying and de-flattening CFGs."""

    def __init__(self):
        self.__dispatcher_patterns = [
            "switch.*case",
            "jmp\\s+\\[.*\\]",
            "mov.*reg,.*;.*jmp",
            "add.*reg,.*;.*jmp"
        ]

    def identify_dispatcherCf(self, cfg: ControlFlowGraph) -> Optional[int]:
        """Walk every block and test dispatcher signatures."""
        for addr, block in cfg.blocks.items():
            for instr in block.instructions:
                if any(pattern in instr.lower()
                       for pattern in self.__dispatcher_patterns):
                    if len(block.transitions) > 3:
                        cfg.dispatcher_address = addr
                        block.block_type = BlockType.DISPATCHER
                        return addr
        return None

    def collect_real_transitionsCf(self, cfg: ControlFlowGraph) -> ControlFlowGraph:
        """Recover original transition edges starting from dispatcher targets."""
        if cfg.dispatcher_address is None:
            return cfg

        dispatcher = cfg.blocks[cfg.dispatcher_address]
        for target in dispatcher.transitions:
            if target in cfg.blocks:
                target_block = cfg.blocks[target]
                self.__trace_real_pathCf(cfg, target_block)

        return cfg

    def __trace_real_pathCf(self, cfg: ControlFlowGraph,
                            start_block: BasicBlock):
        """Follow linear execution path from dispatcher exit to next branch."""
        visited = set()
        current = start_block

        while current.address not in visited:
            visited.add(current.address)
            if current.block_type == BlockType.DISPATCHER:
                break

            if len(current.transitions) == 1:
                next_addr = current.transitions[0]
                if (next_addr in cfg.blocks
                        and next_addr != cfg.dispatcher_address):
                    current.original_targets.append(next_addr)
                    current = cfg.blocks[next_addr]
            elif len(current.transitions) == 2:
                for target in current.transitions:
                    if target != cfg.dispatcher_address:
                        current.original_targets.append(target)
                break


class CFGSimplifier:
    """Post-processing: removes dispatcher nodes and reconstructs structures."""

    def remove_dispatcherCf(self, cfg: ControlFlowGraph) -> ControlFlowGraph:
        """Rewire predecessor edges to bypass the dispatcher entirely."""
        if cfg.dispatcher_address is None:
            return cfg

        new_edges = []
        dispatcher = cfg.blocks[cfg.dispatcher_address]

        for pred_addr in self.__find_predecessorsCf(
                cfg, cfg.dispatcher_address):
            for succ_addr in dispatcher.original_targets:
                if succ_addr in cfg.blocks:
                    new_edges.append((pred_addr, succ_addr))

        cfg.edges = new_edges
        return cfg

    def __find_predecessorsCf(self, cfg: ControlFlowGraph,
                              target_addr: int) -> List[int]:
        """Scan the edge list for all source addresses transitioning to target."""
        preds = []
        for src, dst in cfg.edges:
            if dst == target_addr:
                preds.append(src)
        return preds

    def reconstruct_structuresCf(self, cfg: ControlFlowGraph) -> ReconstructedStructure:
        """Naive structural recovery: 2-way branches -> if-else, self-loops -> while."""
        structure = ReconstructedStructure()

        for addr, block in cfg.blocks.items():
            if len(block.transitions) == 2:
                structure.if_else_blocks.append(
                    (addr, block.transitions[0], block.transitions[1]))

            for target in block.transitions:
                if target == addr:
                    structure.while_loops.append(
                        (addr, block.transitions[0]))

        return structure

    def export_pseudocodeCf(self, cfg: ControlFlowGraph,
                            structure: ReconstructedStructure) -> str:
        """Render recovered structures as C-like pseudocode."""
        lines = ["// De-flattened Control Flow"]

        for if_else in structure.if_else_blocks:
            lines.append("if (condition) {")
            lines.append(f"    // Block: 0x{if_else[1]:X}")
            lines.append("} else {")
            lines.append(f"    // Block: 0x{if_else[2]:X}")
            lines.append("}")

        for while_loop in structure.while_loops:
            lines.append("while (condition) {")
            lines.append(f"    // Block: 0x{while_loop[1]:X}")
            lines.append("}")

        return "\n".join(lines)


__all__ = [
    "BlockType", "BasicBlock", "ControlFlowGraph",
    "ReconstructedStructure", "FlattenedCFGAnalyzer", "CFGSimplifier"
]
