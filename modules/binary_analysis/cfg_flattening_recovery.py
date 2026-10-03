import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

logger = logging.getLogger(__name__)


class BlockType(Enum):
    NORMAL = "normal"
    DISPATCHER = "dispatcher"
    CONDITIONAL = "conditional"
    LOOP_HEADER = "loop_header"
    RETURN = "return"


@dataclass
class BasicBlock:
    address: int
    instructions: list = field(default_factory=list)
    block_type: BlockType = BlockType.NORMAL
    frequency: int = 0
    transitions: list = field(default_factory=list)
    original_targets: list = field(default_factory=list)


@dataclass
class ControlFlowGraph:
    blocks: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    dispatcher_address: Optional[int] = None


@dataclass
class ReconstructedStructure:
    if_else_blocks: list = field(default_factory=list)
    while_loops: list = field(default_factory=list)
    for_loops: list = field(default_factory=list)


class FlattenedCFGAnalyzer:

    def __init__(self):
        self.__dispatcher_patterns = [
            "switch.*case",
            "jmp\\s+\\[.*\\]",
            "mov.*reg,.*;.*jmp",
            "add.*reg,.*;.*jmp"
        ]

    def identify_dispatcherCf(self, cfg: ControlFlowGraph) -> Optional[int]:
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
        if cfg.dispatcher_address is None:
            return cfg

        dispatcher = cfg.blocks[cfg.dispatcher_address]
        for target in dispatcher.transitions:
            if target in cfg.blocks:
                target_block = cfg.blocks[target]
                self.__trace_real_pathCf(cfg, target_block)

        return cfg

    def __trace_real_pathCf(self, cfg: ControlFlowGraph, start_block: BasicBlock):
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

    def remove_dispatcherCf(self, cfg: ControlFlowGraph) -> ControlFlowGraph:
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

    def __find_predecessorsCf(self, cfg: ControlFlowGraph, target_addr: int) -> List[int]:
        preds = []
        for src, dst in cfg.edges:
            if dst == target_addr:
                preds.append(src)
        return preds

    def reconstruct_structuresCf(self, cfg: ControlFlowGraph) -> ReconstructedStructure:
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

    def export_pseudocodeCf(self, cfg: ControlFlowGraph, structure: ReconstructedStructure) -> str:
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
