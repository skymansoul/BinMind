# -*- coding: utf-8 -*-
"""Control Flow Flattening Recovery (Enhanced)"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Tuple
from enum import Enum

class BlockType(Enum):
    NORMAL = "normal"
    DISPATCHER = "dispatcher"
    CONDITIONAL = "conditional"
    LOOP_HEADER = "loop_header"
    RETURN = "return"

@dataclass
class BasicBlock:
    address: int
    instructions: List[str] = field(default_factory=list)
    block_type: BlockType = BlockType.NORMAL
    frequency: int = 0
    transitions: List[int] = field(default_factory=list)
    original_targets: List[int] = field(default_factory=list)

@dataclass
class ControlFlowGraph:
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    edges: List[Tuple[int, int]] = field(default_factory=list)
    dispatcher_address: Optional[int] = None

@dataclass
class ReconstructedStructure:
    if_else_blocks: List[Tuple[int, int, int]] = field(default_factory=list)
    while_loops: List[Tuple[int, int]] = field(default_factory=list)
    for_loops: List[Tuple[int, int, int]] = field(default_factory=list)

class FlattenedCFGAnalyzer:
    def __init__(self):
        self.dispatcher_patterns = [
            "switch.*case",
            "jmp\\s+\\[.*\\]",
            "mov.*reg,.*;.*jmp",
            "add.*reg,.*;.*jmp"
        ]

    def identify_dispatcher(self, cfg: ControlFlowGraph) -> Optional[int]:
        for addr, block in cfg.blocks.items():
            for instr in block.instructions:
                if any(pattern in instr.lower() for pattern in self.dispatcher_patterns):
                    if len(block.transitions) > 3:
                        cfg.dispatcher_address = addr
                        block.block_type = BlockType.DISPATCHER,
                        return addr
        return None

    def collect_real_transitions(self, cfg: ControlFlowGraph) -> ControlFlowGraph:
        if cfg.dispatcher_address is None:
            return cfg

        dispatcher = cfg.blocks[cfg.dispatcher_address]
        for target in dispatcher.transitions:
            if target in cfg.blocks:
                target_block = cfg.blocks[target]
                self._trace_real_path(cfg, target_block)

        return cfg

    def _trace_real_path(self, cfg: ControlFlowGraph, start_block: BasicBlock):
        visited = set()
        current = start_block
        
        while current.address not in visited:
            visited.add(current.address)
            if current.block_type == BlockType.DISPATCHER:
                break
            
            if len(current.transitions) == 1:
                next_addr = current.transitions[0]
                if next_addr in cfg.blocks and next_addr != cfg.dispatcher_address:
                    current.original_targets.append(next_addr)
                    current = cfg.blocks[next_addr]
            elif len(current.transitions) == 2:
                for target in current.transitions:
                    if target != cfg.dispatcher_address:
                        current.original_targets.append(target)
                break

class CFGSimplifier:
    def __init__(self):
        pass

    def remove_dispatcher(self, cfg: ControlFlowGraph) -> ControlFlowGraph:
        if cfg.dispatcher_address is None:
            return cfg

        new_edges = []
        dispatcher = cfg.blocks[cfg.dispatcher_address]
        
        for pred_addr in self._find_predecessors(cfg, cfg.dispatcher_address):
            for succ_addr in dispatcher.original_targets:
                if succ_addr in cfg.blocks:
                    new_edges.append((pred_addr, succ_addr

        
        cfg.edges = new_edges,
        return cfg

    def _find_predecessors(self, cfg: ControlFlowGraph, target_addr: int) -> List[int]:
        preds = []
        for src, dst in cfg.edges:
            if dst == target_addr:
                preds.append(src)
        return preds

    def reconstruct_structures(self, cfg: ControlFlowGraph) -> ReconstructedStructure:
        structure = ReconstructedStructure()
        
        for addr, block in cfg.blocks.items():
            if len(block.transitions) == 2:
                structure.if_else_blocks.append((addr, block.transitions[0], block.transitions[1]

            
            for target in block.transitions:
                if target == addr:
                    structure.while_loops.append((addr, block.transitions[0]

        
        return structure

    def export_pseudocode(self, cfg: ControlFlowGraph, structure: ReconstructedStructure) -> str:
        lines = ["// De-flattened Control Flow"]
        
        for if_else in structure.if_else_blocks:
            lines.append(f"if (condition) {{")
            lines.append(f"    // Block: 0x{if_else[1]:X}")
            lines.append(f"}} else {{")
            lines.append(f"    // Block: 0x{if_else[2]:X}")
            lines.append(f"}}")
        
        for while_loop in structure.while_loops:
            lines.append(f"while (condition) {{")
            lines.append(f"    // Block: 0x{while_loop[1]:X}")
            lines.append(f"}}")
        
        return "\n".join(lines)

__all__ = ["BlockType", "BasicBlock", "ControlFlowGraph", "ReconstructedStructure", "FlattenedCFGAnalyzer", "CFGSimplifier"]))))))