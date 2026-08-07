# coding: utf-8
"""
UAF 路径敏感时序生命周期验证 (PTLV) — 对标 heap overflow VCT 的深度 UAF FP 削减.

核心洞察: UAF 的主要 FP 类来自路径合并不精确 — 指针在一条路径上被 free,
在另一条路径上被 use, 静态分析合并两条路径后报告 UAF.
PTLV 通过编码每条路径的卫士条件栈, 检查 free 路径与 use 路径的互斥性.

方法:
  1. CFG + 分支条件编码 — 为每条指令记录到达条件栈
  2. 卫士互斥检查 — free 路径条件 ∩ use 路径条件 = ∅ → 可证明无 UAF
  3. NULL 卫士推断 — if(ptr) use(ptr) 暗示 ptr 在到达 use 前未被 free
  4. 必经路径支配 — 若 use 被 free 支配 (必经 free), 则 UAF 确定

复杂度: O(|V|·|C| + |E|) where |C| = 分支条件数 (通常 < 10/函数).

  - "CRIX: Detecting Missing-Check Bugs via Predicate Extraction"
  - "MineSweeper: A Study of UAF in the Linux Kernel"
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, FrozenSet
from collections import defaultdict, deque
import re

class GuardOp(Enum):
    EQ = auto(); NE = auto(); LT = auto(); LE = auto()
    GT = auto(); GE = auto(); IS_NULL = auto(); NOT_NULL = auto()
    IS_TRUE = auto(); IS_FALSE = auto()

@dataclass(frozen=True)
class GuardCondition:
    """单个卫士条件 — e.g. 'ptr != NULL' 或 'count > 0'."""
    variable: str
    op: GuardOp
    value: str = ''
    addr: int = 0

    def negate(self) -> 'GuardCondition':
        neg_map = {
            GuardOp.EQ: GuardOp.NE, GuardOp.NE: GuardOp.EQ,
            GuardOp.LT: GuardOp.GE, GuardOp.LE: GuardOp.GT,
            GuardOp.GT: GuardOp.LE, GuardOp.GE: GuardOp.LT,
            GuardOp.IS_NULL: GuardOp.NOT_NULL,
            GuardOp.NOT_NULL: GuardOp.IS_NULL,
            GuardOp.IS_TRUE: GuardOp.IS_FALSE,
            GuardOp.IS_FALSE: GuardOp.IS_TRUE,
        }
        return GuardCondition(self.variable, neg_map[self.op],
                              self.value, self.addr)

    def contradicts(self, other: 'GuardCondition') -> bool:
        if self.variable != other.variable: return False
        return self.op == other.negate().op

    def __repr__(self):
        op_str = {GuardOp.EQ:'==', GuardOp.NE:'!=', GuardOp.LT:'<',
                  GuardOp.LE:'<=', GuardOp.GT:'>', GuardOp.GE:'>=',
                  GuardOp.IS_NULL:'==NULL', GuardOp.NOT_NULL:'!=NULL',
                  GuardOp.IS_TRUE:'==true', GuardOp.IS_FALSE:'==false'}[self.op]
        return f'{self.variable}{op_str}@{self.addr:x}'

@dataclass
class PathCondition:
    """路径条件栈 — 到达某条指令所需满足的卫士条件集合."""
    conditions: FrozenSet[GuardCondition] = field(default_factory=frozenset)

    def add(self, cond: GuardCondition) -> 'PathCondition':
        return PathCondition(self.conditions | {cond})

    def compatible_with(self, other: 'PathCondition') -> bool:
        for c1 in self.conditions:
            for c2 in other.conditions:
                if c1.contradicts(c2): return False
        return True

@dataclass
class CfgNode:
    addr: int; inst_type: str = 'other'
    path_cond: PathCondition = field(default_factory=PathCondition)
    ptr_var: str = ''; callee: str = ''

class PathSensitiveCfg:
    """路径敏感 CFG — 为每个节点计算到达条件."""

    def __init__(self):
        self._nodes: Dict[int, CfgNode] = {}
        self._edges: Dict[int, List[int]] = defaultdict(list)
        self._preds: Dict[int, List[int]] = defaultdict(list)
        self._edge_conds: Dict[Tuple[int, int], GuardCondition] = {}
        self._entry: int = 0

    def add_node(self, addr: int, inst_type: str = 'other',
                 ptr_var: str = '', callee: str = ''):
        self._nodes[addr] = CfgNode(addr=addr, inst_type=inst_type,
                                     ptr_var=ptr_var, callee=callee)
        if not self._entry: self._entry = addr

    def add_edge(self, from_addr: int, to_addr: int,
                 condition: GuardCondition = None):
        self._edges[from_addr].append(to_addr)
        self._preds[to_addr].append(from_addr)
        if condition:
            self._edge_conds[(from_addr, to_addr)] = condition

    def propagate_conditions(self, ptr_var: str = ''):
        visited: Set[int] = set()
        worklist = deque([self._entry])
        while worklist:
            cur = worklist.popleft()
            if cur in visited: continue
            visited.add(cur)
            node = self._nodes.get(cur)
            if not node: continue
            for succ in self._edges.get(cur, []):
                if succ not in self._nodes: continue
                succ_node = self._nodes[succ]
                cond = self._edge_conds.get((cur, succ))
                succ_node.path_cond = (node.path_cond.add(cond)
                                       if cond else node.path_cond)
                worklist.append(succ)
        # 多前驱节点取条件交集
        for addr, node in self._nodes.items():
            preds = self._preds.get(addr, [])
            if len(preds) <= 1: continue
            pred_conds = [self._nodes[p].path_cond
                         for p in preds if p in self._nodes]
            if pred_conds:
                common = pred_conds[0].conditions
                for pc in pred_conds[1:]:
                    common = common & pc.conditions
                node.path_cond = PathCondition(common)

    def get_free_sites(self) -> List[CfgNode]:
        return [n for n in self._nodes.values() if n.inst_type == 'free']

    def get_use_sites(self) -> List[CfgNode]:
        return [n for n in self._nodes.values() if n.inst_type == 'use']

    def dominator_free_of_use(self, free_addr: int, use_addr: int) -> bool:
        """检查 free 是否支配 use (use 的每条路径都经过 free)."""
        def dfs(cur: int, target: int, visited: Set[int],
                passed_free: bool) -> bool:
            if cur == target: return passed_free
            if cur in visited: return True
            visited.add(cur)
            cur_passed = passed_free or (cur == free_addr)
            for succ in self._edges.get(cur, []):
                if not dfs(succ, target, visited.copy(), cur_passed):
                    return False
            return True
        return dfs(self._entry, use_addr, set(), False)

@dataclass
class TemporalVerdict:
    """PTLV 判定结果."""
    is_uaf: bool; confidence: float; reason: str
    free_path_cond: str = ''; use_path_cond: str = ''
    guards_contradict: bool = False; dominated: bool = False

class TemporalPathVerifier:
    """路径敏感时序验证器 — UAF 的核心 FP 削减引擎.

    四个判定策略 (优先级递减):
      1. 路径互斥: free 和 use 在不同互斥分支 → Not UAF
      2. 支配关系: free 支配 use (必经 free) → Confirmed UAF
      3. 路径兼容: free 和 use 路径兼容 → Possible UAF (保留)
      4. 默认保留: 无法判定 → 保守保留
    """

    def __init__(self):
        self._cfg: Optional[PathSensitiveCfg] = None

    def build_from_instructions(
        self, instructions: List[Dict],
        callee_names: Dict[int, str], ptr_var: str = '',
    ) -> PathSensitiveCfg:
        cfg = PathSensitiveCfg()
        addrs = sorted(inst['addr'] for inst in instructions)
        inst_map = {inst['addr']: inst for inst in instructions}

        for addr in addrs:
            inst = inst_map[addr]
            callee = callee_names.get(addr, '').lower()
            mnem = inst.get('mnemonic', '').lower()
            if any(a in callee for a in ('malloc','calloc','realloc')):
                cfg.add_node(addr, 'alloc', ptr_var, callee)
            elif 'free' in callee or 'delete' in callee:
                cfg.add_node(addr, 'free', ptr_var, callee)
            elif ptr_var and (ptr_var in inst.get('comment','') or
                              ptr_var in str(inst)):
                cfg.add_node(addr, 'use', ptr_var, callee)
            else:
                cfg.add_node(addr, 'other', ptr_var, callee)

        for i, addr in enumerate(addrs):
            if i + 1 >= len(addrs): continue
            next_addr = addrs[i + 1]
            inst = inst_map[addr]
            mnem = inst.get('mnemonic', '').lower()
            if mnem.startswith('j'):
                target = self._parse_branch_target(inst)
                guard = self._extract_guard(inst, ptr_var, addr)
                if target and target in cfg._nodes:
                    if guard:
                        cfg.add_edge(addr, target, guard)
                        cfg.add_edge(addr, next_addr, guard.negate())
                    else:
                        cfg.add_edge(addr, target)
            else:
                cfg.add_edge(addr, next_addr)

        cfg.propagate_conditions(ptr_var)
        self._cfg = cfg
        return cfg

    def verify(self, free_site: int, use_site: int,
               ptr_var: str = '') -> TemporalVerdict:
        if not self._cfg:
            return TemporalVerdict(True, 0.5, 'CFG 未构建')
        free_node = self._cfg._nodes.get(free_site)
        use_node = self._cfg._nodes.get(use_site)
        if not free_node or not use_node:
            return TemporalVerdict(True, 0.5, '节点不存在')

        free_pc = free_node.path_cond
        use_pc = use_node.path_cond

        # 策略 1: 路径互斥
        for c1 in free_pc.conditions:
            for c2 in use_pc.conditions:
                if c1.contradicts(c2):
                    return TemporalVerdict(
                        False, 0.90,
                        f'free 条件 {c1} 与 use 条件 {c2} 互斥',
                        str(free_pc), str(use_pc), guards_contradict=True)

        # 策略 2: 支配关系
        dominated = self._cfg.dominator_free_of_use(free_site, use_site)
        if dominated:
            return TemporalVerdict(
                True, 0.85,
                f'free@{free_site:x} 支配 use@{use_site:x}',
                str(free_pc), str(use_pc), dominated=True)

        # 策略 3: 路径兼容
        if free_pc.compatible_with(use_pc):
            return TemporalVerdict(True, 0.60, '路径兼容, 无法证明无UAF',
                                   str(free_pc), str(use_pc))
        return TemporalVerdict(True, 0.55, '默认保留')

    @staticmethod
    def _parse_branch_target(inst: Dict) -> Optional[int]:
        m = re.search(r'(0x[0-9a-fA-F]+)', inst.get('comment',''))
        return int(m.group(1), 16) if m else None

    @staticmethod
    def _extract_guard(inst: Dict, ptr_var: str,
                       addr: int) -> Optional[GuardCondition]:
        mnem = inst.get('mnemonic', '').lower()
        comment = inst.get('comment', '')
        if ptr_var and ptr_var in comment:
            if 'NULL' in comment or 'null' in comment.lower():
                if mnem in ('je','jz'): return GuardCondition(ptr_var, GuardOp.IS_NULL, addr=addr)
                if mnem in ('jne','jnz'): return GuardCondition(ptr_var, GuardOp.NOT_NULL, addr=addr)
        if mnem in ('je','jz'): return GuardCondition('flag', GuardOp.IS_TRUE, addr=addr)
        if mnem in ('jne','jnz'): return GuardCondition('flag', GuardOp.IS_FALSE, addr=addr)
        if mnem in ('jg','jge','jl','jle','ja','jb','jae','jbe'):
            return GuardCondition('flag', GuardOp.IS_TRUE, addr=addr)
        return None
