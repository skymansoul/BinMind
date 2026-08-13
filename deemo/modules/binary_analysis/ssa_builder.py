import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)



class BasicBlock:
    __slots__ = ('id', 'instructions', 'predecessors', 'successors', 'dominator_tree_parent', 'dominance_frontier',)

    def __init__(self, id, instructions=field(default_factory=list), predecessors=field(default_factory=list), successors=field(default_factory=list), dominator_tree_parent=None, dominance_frontier=field(default_factory=set)):
        self.id = id
        self.instructions = instructions
        self.predecessors = predecessors
        self.successors = successors
        self.dominator_tree_parent = dominator_tree_parent
        self.dominance_frontier = dominance_frontier

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'preds': self.predecessors,
            'succs': self.successors,
            'dom_parent': self.dominator_tree_parent
        }


class SSAVariable:
    __slots__ = ('name', 'version', 'original_name', 'defining_block',)

    def __init__(self, name, version=0, original_name="", defining_block=0):
        self.name = name
        self.version = version
        self.original_name = original_name
        self.defining_block = defining_block

    @property
    def ssa_name(self) -> str:
        return f"{self.name}_{self.version}"

class SSABuilder:
    """SSA 构造器 (main class)"""

    def __init__(self):
        self._blocks: Dict[int, BasicBlock] = {}
        self._def_sites: Dict[str, List[int]] = defaultdict(list)
        self._var_versions: Dict[str, int] = {}
        self._phi_inserted: int = 0

    def add_block(self, block: BasicBlock):
        self._blocks[block.id] = block

    def compute_dominators(self, entry_id: int = 0):
        all_nodes = set(self._blocks.keys())
        dom = {b: all_nodes.copy() if b != entry_id else {entry_id}
              for b in all_nodes}

        changed = True
        while changed:
            changed = False
            for b in all_nodes - {entry_id}:
                preds = self._blocks[b].predecessors
                if not preds:
                    continue
                new_dom = set.intersection(*[dom[p] for p in preds if p in dom]) \
                         if all(p in dom for p in preds) else all_nodes - {b}
                new_dom.add(b)
                if new_dom != dom[b]:
                    dom[b] = new_dom
                    changed = True

        for b in all_nodes - {entry_id}:
            strict_dom = dom[b] - {b}
            if strict_dom:
                immediate = max(strict_dom,
                               key=lambda d: len(dom.get(d, set())))
                self._blocks[b].dominator_tree_parent = immediate

    def insert_phi_functions(self, vars_to_ssa: Set[str]):
        for var in vars_to_ssa:
            def_blocks = self._def_sites.get(var, [])
            processed = set()
            worklist = list(def_blocks)

            while worklist:
                block_id = worklist.pop()
                if block_id in processed:
                    continue
                processed.add(block_id)
                df = self._blocks[block_id].dominance_frontier
                for df_block in df:
                    if df_block not in self._blocks:
                        continue
                    self._phi_inserted += 1
                    self._def_sites[var].append(df_block)
                    if df_block not in processed:
                        worklist.append(df_block)

    def analyze(self, blocks: Optional[List[Dict[str, Any]]] = None,
                variables: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        if blocks:
            for b in blocks:
                block = BasicBlock(
                    id=b.get('id', 0),
                    instructions=b.get('instructions', []),
                    predecessors=b.get('predecessors', []),
                    successors=b.get('successors', []))
                self.add_block(block)
                for instr_str in block.instructions:
                    parts = instr_str.split()
                    for var in (variables or []):
                        if var in parts and '=' in instr_str:
                            self._def_sites[var].append(block.id)

        if self._blocks:
            entry = min(self._blocks.keys())
            self.compute_dominators(entry)

        if variables:
            self.insert_phi_functions(set(variables))

        return {
            'success': True,
            'total_blocks': len(self._blocks),
            'phi_functions_inserted': self._phi_inserted,
            'ssa_ready': self._phi_inserted > 0,
            'dominance_tree': {
                b: self._blocks[b].dominator_tree_parent
                for b in self._blocks
                if self._blocks[b].dominator_tree_parent is not None
            }
        }


def build_ssa(blocks: List[Dict[str, Any]],
              variables: Optional[List[str]] = None,
              **kwargs) -> Dict[str, Any]:
    builder = SSABuilder()
    return builder.analyze(blocks=blocks, variables=variables)


__all__ = ["SSABuilder", "BasicBlock", "SSAVariable", "build_ssa"]
