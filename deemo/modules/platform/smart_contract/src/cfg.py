# 2026-07-29
# CFG builder — Cooper 2001 快速迭代 dominator 算法
# 对大多数合约（几百到几千条指令）够快，10w+ 指令可改 Lengauer-Tarjan
from collections import deque
from typing import Dict, List, Set, Tuple
from .parser import EVMBytecodeParser, EVMOp


class CFGBuilder:
    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.blocks: Dict[int, List[EVMOp]] = {}
        self.edges: Dict[int, List[int]] = {}  # block_start → [successor_starts]
        self._entry = 0

    def build(self):
        self.blocks = {}
        self.edges = {}
        blocks = self.parser.get_basic_blocks()
        for start, ops in blocks:
            self.blocks[start] = ops
        # 构建边
        block_starts = sorted(self.blocks.keys())
        for i, start in enumerate(block_starts):
            ops = self.blocks[start]
            last = ops[-1] if ops else None
            if last is None:
                continue
            successors = []
            if last.name == 'JUMP':
                target = self._resolve_jump_target(last)
                if target is not None:
                    successors.append(target)
            elif last.name == 'JUMPI':
                target = self._resolve_jump_target(last)
                if target is not None:
                    successors.append(target)
                if i + 1 < len(block_starts):
                    successors.append(block_starts[i + 1])
            elif last.name in ('RETURN', 'REVERT', 'STOP', 'INVALID', 'SELFDESTRUCT'):
                pass  # terminal
            else:
                if i + 1 < len(block_starts):
                    successors.append(block_starts[i + 1])
            self.edges[start] = successors

    def _resolve_jump_target(self, op: EVMOp) -> int:
        # 静态分析：查找前一 PUSH 的 data
        for prev_op in reversed(self.parser.ops[:self.parser.ops.index(op)]):
            if prev_op.is_push:
                try:
                    return int.from_bytes(prev_op.push_data, 'big')
                except ValueError:
                    return None
        return None

    def get_reachable_blocks(self) -> Set[int]:
        visited = set()
        q = deque([0])
        while q:
            cur = q.popleft()
            if cur in visited:
                continue
            visited.add(cur)
            for succ in self.edges.get(cur, []):
                if succ not in visited:
                    q.append(succ)
        return visited

    def compute_dominators(self) -> Dict[int, Set[int]]:
        """Cooper 2001 快速迭代算法。"""
        reachable = sorted(self.get_reachable_blocks())
        if not reachable:
            return {}
        all_nodes = set(reachable)
        dom = {n: all_nodes.copy() if n != 0 else {0} for n in reachable}
        changed = True
        while changed:
            changed = False
            for n in reachable:
                if n == 0:
                    continue
                preds = [p for p, succs in self.edges.items() if n in succs]
                if not preds:
                    continue
                new_dom = all_nodes.copy()
                for p in preds:
                    new_dom &= dom.get(p, all_nodes)
                new_dom.add(n)
                if new_dom != dom[n]:
                    dom[n] = new_dom
                    changed = True
        return dom
