"""函数内控制流图与支配关系 — PCFV 守卫支配性验证的基础.

创建: 2024-09-05
设计决策:
  - 支配性验证是 PCFV 与基线路径窄化的本质区别: 基线反向BFS收集约束时不验证
    守卫是否真正支配访问点, 兄弟分支的守卫会被错误采信, 导致真阳性被过滤.
  - 采用标准迭代支配算法: 对 <500 条指令的函数, 迭代收敛足够快.
  - 分支极性判定: 若访问点仅能通过taken边到达 → taken极性约束生效;
    仅通过fallthrough边到达 → not-taken约束; 两条路径都可达 → 约束不成立.
"""
from typing import Dict, List, Set, Tuple

_JCC_REGS = {
    'je', 'jne', 'jz', 'jnz', 'jg', 'jnle', 'jge', 'jnl', 'jl', 'jnge',
    'jle', 'jng', 'ja', 'jnbe', 'jae', 'jnb', 'jb', 'jnae', 'jbe', 'jna',
    'js', 'jns', 'jp', 'jnp', 'jpe', 'jpo', 'jcxz', 'jecxz', 'jrcxz',
}
_JMP_ONLY = {'jmp', 'jmpq'}


class CFGNode:
    """CFG 节点: 一条指令地址."""
    __slots__ = ('addr', 'succs', 'preds')

    def __init__(self, addr: int):
        self.addr = addr
        self.succs: Set[int] = set()
        self.preds: Set[int] = set()


class IntraCFG:
    """指令级函数内 CFG + 支配者集合计算."""

    def __init__(self, insns: list):
        self.insns = insns
        self.nodes: Dict[int, CFGNode] = {}
        self._entry: int = 0
        self._dom_table: Dict[int, Set[int]] = None
        self._build()

    def _build(self) -> None:
        for insn in self.insns:
            self.nodes.setdefault(insn.addr, CFGNode(insn.addr))
        self._entry = self.insns[0].addr if self.insns else 0
        for i, insn in enumerate(self.insns):
            src = insn.addr
            node = self.nodes[src]
            mn = insn.mnemonic
            if mn == 'call' or mn == 'callq':
                if i + 1 < len(self.insns):
                    node.succs.add(self.insns[i + 1].addr)
            elif mn in _JCC_REGS:
                tgt = self._target_of(insn)
                if i + 1 < len(self.insns):
                    node.succs.add(self.insns[i + 1].addr)
                if tgt is not None:
                    node.succs.add(tgt)
            elif mn in _JMP_ONLY:
                tgt = self._target_of(insn)
                if tgt is not None:
                    node.succs.add(tgt)
            elif mn == 'ret' or mn == 'retq':
                pass
            else:
                if i + 1 < len(self.insns):
                    node.succs.add(self.insns[i + 1].addr)
        for addr, node in self.nodes.items():
            for s in node.succs:
                if s in self.nodes:
                    self.nodes[s].preds.add(addr)

    @staticmethod
    def _target_of(insn) -> int:
        op = insn.operands.strip()
        token = op.split()[0] if op else ''
        if not token:
            return None
        try:
            return int(token, 16)
        except ValueError:
            pass
        try:
            return int(token, 10)
        except ValueError:
            return None

    def dominators(self, node_addr: int) -> Set[int]:
        """返回 node_addr 的支配者集合(含自身).

        支配表一次性计算并缓存: 每访问点重复全图迭代是
        大函数超线性耗时的主源 (scal_4000 单函数 268s).
        """
        if node_addr not in self.nodes:
            return set()
        if self._dom_table is None:
            self._dom_table = self._compute_all_dominators()
        return self._dom_table.get(node_addr, set())

    def _compute_all_dominators(self) -> Dict[int, Set[int]]:
        """迭代计算全部节点的支配者集合."""
        dom: Dict[int, Set[int]] = {a: set(self.nodes) for a in self.nodes}
        dom[self._entry] = {self._entry}
        changed = True
        rounds = 0
        while changed:
            changed = False
            rounds += 1
            for a in sorted(self.nodes):
                if a == self._entry:
                    continue
                preds = self.nodes[a].preds
                new_dom = (set(self.nodes)
                           if not preds else
                           set.intersection(*(dom[p] for p in preds)))
                new_dom.add(a)
                if new_dom != dom[a]:
                    dom[a] = new_dom
                    changed = True
        return dom

    def reachable(self, src_addr: int, dst_addr: int,
                  max_steps: int = 300) -> bool:
        """src 是否可达 dst (前向BFS, 有界)."""
        if src_addr == dst_addr:
            return True
        seen: Set[int] = set()
        queue = [src_addr]
        steps = 0
        while queue and steps < max_steps:
            cur = queue.pop(0)
            if cur in seen:
                continue
            seen.add(cur)
            steps += 1
            node = self.nodes.get(cur)
            if node is None:
                continue
            for s in node.succs:
                if s == dst_addr:
                    return True
                if s not in seen:
                    queue.append(s)
        return False

    def branch_polarity_for_access(self, branch_addr: int,
                                   access_addr: int) -> int:
        """分支对访问点的生效极性.

        返回: 0=无约束(两条边都可达), 1=taken极性, 2=fallthrough极性.
        fallthrough 后继 = 线性顺序下一条指令 (不依赖集合顺序).
        """
        node = self.nodes.get(branch_addr)
        if node is None or access_addr not in self.nodes:
            return 0
        succs = list(node.succs)
        if len(succs) < 2:
            return 0
        fall_succ = self._linear_next(branch_addr)
        if fall_succ not in node.succs:
            fall_succ = None
        taken_succ = (succs[0] if succs[0] != fall_succ else succs[1]) \
            if fall_succ is not None else succs[0]
        if taken_succ is None:
            return 0
        via_taken = self.reachable(taken_succ, access_addr)
        via_fall = (fall_succ is not None
                    and self.reachable(fall_succ, access_addr))
        if via_taken and not via_fall:
            return 1
        if via_fall and not via_taken:
            return 2
        return 0

    def _linear_next(self, addr: int) -> int:
        for i, insn in enumerate(self.insns):
            if insn.addr == addr and i + 1 < len(self.insns):
                return self.insns[i + 1].addr
        return addr
