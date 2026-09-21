"""
格式串约束引擎 — 将格式说明符约束系统 (Format Spec Constraint System) 从正则分类提升到约束传播+抽象解释.

与 fmt_constraint_solver.py 的纯正则方法对照:
  1. CallingConventionModel: 基于Microsoft x64 ABI计算%n$→实际参数栈槽
  2. DefUseChainTracker: Worklist算法沿DU链做fixpoint污点传播 (AbsInt lattice)
  3. AttackSurfaceComputer: 三层评分分解 (格式串可控×写入原语×地址可控)
  4. L1/L2/L3 分层架构: 参数建模→污点传播→攻击面量化

与格式说明符约束系统 (Format Spec Constraint System) 关系: 正则级classify + 本引擎约束精化 → 最终综合评分.
"""

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple


# L1: 格式参数建模

class FmtPrimitive(IntEnum):
    NONE, LEAK, READ, WRITE, WIDE_WRITE = range(5)  # 安全原语等级

_PRIMITIVE_MAP = {'d':0,'i':0,'u':0,'o':0,'x':1,'X':1,'p':1,'s':2,
    'n':3,'hn':4,'hhn':4}  # spec_char → FmtPrimitive

@dataclass
class FormatArgModel:
    """单个格式参数的约束模型 (lattice element)."""
    spec_index: int; positional: int = 0; primitive: int = 0
    stack_slot: int = -1; is_ctrl: bool = False
    def join(self, other: 'FormatArgModel') -> 'FormatArgModel':
        """⊔: upper bound — 合并两个参数约束."""
        return FormatArgModel(spec_index=self.spec_index,
            positional=max(self.positional, other.positional),
            primitive=max(self.primitive, other.primitive),
            stack_slot=max(self.stack_slot, other.stack_slot),
            is_ctrl=self.is_ctrl or other.is_ctrl)

@dataclass
class FmtCallModel:
    call_func: str; call_line: int
    fmt_string: str = ""; fmt_source: str = ""
    args: List[FormatArgModel] = field(default_factory=list)


# L1: 调用约定模型

class CallingConventionModel:
    """Microsoft x64 ABI: rcx=fmt, rdx=arg1, r8=arg2, r9=arg3.
    第5+参数: [rsp+0x20], [rsp+0x28], ... 栈传递."""

    REG_SLOTS = 4

    @staticmethod
    def slot(pos: int) -> int:  # %n$ → slot index (0=rcx)
        return max(-1, pos - 1) if pos >= 1 else -1

    @staticmethod
    def offset(slot: int) -> int:
        return 0 if slot < CallingConventionModel.REG_SLOTS \
               else (slot - CallingConventionModel.REG_SLOTS) * 8

    @staticmethod
    def controllable(slot: int, max_stack: int = 128) -> bool:
        """槽在栈上且偏移≤max_stack→攻击者可写入该位置的值."""
        return slot >= CallingConventionModel.REG_SLOTS and \
               (slot - CallingConventionModel.REG_SLOTS) * 8 <= max_stack


# L2: 定义-使用链追踪 (Worklist Fixpoint)

@dataclass
class DUNode:
    """DU链节点: 变量的一次定义."""
    var: str; line: int; expr: str = ""
    kind: str = ""  # "external"|"heap"|"constant"|"assign"
    users: List[int] = field(default_factory=list)
    tainted: bool = False

class DefUseChainTracker:
    """Worklist-based def-use taint propagation.

    Lattice: {⊥=Clean, ⊤=Tainted} per variable.
    Fixpoint: iteratively join taint from external sources through DU edges.
    Complexity: O(|V|·|E|) per fixpoint iteration, bounded by |V|.
    """

    EXT_RE = re.compile(r'(argv|getenv|recv|read|scanf|fgets|gets|fread'
        r'|strcpy|strncpy|memcpy|strcat|strncat|sprintf|snprintf)')
    # 指针赋值/数组赋值/复合赋值/普通赋值统一定义
    DEF_RE = re.compile(
        r'(?:\*\s*(\w[\w.]*)\s*=\s*(.+?)\s*;)'         # *ptr = expr
        r'|(?:\b(\w[\w.]*)\s*\[[^\]]*\]\s*=\s*(.+?)\s*;)'  # arr[i] = expr
        r'|(?:\b(\w[\w.]*)\s*([+\-*/|&^]?=)\s*(.+?)\s*;)'  # var = expr / var += expr
    )

    def __init__(self):
        self.nodes: Dict[str, DUNode] = {}
        self._worklist: List[str] = []
        self._tainted: Set[str] = set()

    def build(self, src: str) -> 'DefUseChainTracker':
        """Build DU graph + run fixpoint taint propagation."""
        lines = src.splitlines()
        for i, line in enumerate(lines, 1):
            m = self.DEF_RE.search(line.strip())
            if m:
                var, expr = None, ""
                if m.group(1):  # 指针赋值 *ptr = expr
                    var, expr = m.group(1), m.group(2).strip()
                elif m.group(3):  # 数组赋值 arr[i] = expr
                    var, expr = m.group(3), m.group(4).strip()
                elif m.group(5):  # 普通/复合赋值 var = expr / var += expr
                    var, expr = m.group(5), m.group(7).strip()
                if var:
                    node = DUNode(var=var, line=i, expr=expr)
                    if self.EXT_RE.search(expr):
                        node.kind, node.tainted = 'external', True
                        self._worklist.append(var)
                    elif 'malloc' in expr or 'calloc' in expr:
                        node.kind = 'heap'
                    elif re.match(r'^"[^"]*"$', expr):
                        node.kind = 'constant'
                    else:
                        node.kind = 'assign'
                    self.nodes[var] = node
            for m in re.finditer(r'\b(\w[\w.]*)\b', line):
                v = m.group(1)
                if v in self.nodes and i not in self.nodes[v].users:
                    self.nodes[v].users.append(i)
        self._fixpoint()
        return self

    def _fixpoint(self):
        """Worklist fixpoint: propagate ⊤ (tainted) through DU edges."""
        iters = 0
        while self._worklist and iters < len(self.nodes) + 5:
            var = self._worklist.pop(0)
            if var in self._tainted: continue
            self._tainted.add(var); iters += 1
            if var not in self.nodes: continue
            expr = self.nodes[var].expr
            for ov, on in self.nodes.items():
                if ov not in self._tainted and on.expr and \
                   re.search(rf'\b{re.escape(var)}\b', on.expr):
                    on.tainted = True; self._worklist.append(ov)

    def tainted(self, var: str) -> bool:
        return var in self._tainted

    def node(self, var: str) -> Optional[DUNode]:
        return self.nodes.get(var)


# L3: 攻击面计算

@dataclass
class AttackSurface:
    """格式串调用点的攻击面 (CVSS风格 0-10)."""
    fmt_call: FmtCallModel
    has_write: bool = False; has_read: bool = False
    ctrl_write_targets: int = 0; score: float = 0.0
    # CVSS分量 (0-5 + 0-3 + 0-2 = 0-10)
    fmt_ctrl: float = 0.0; write_score: float = 0.0; addr_ctrl: float = 0.0
    vectors: List[str] = field(default_factory=list)

    def finalize(self) -> float:
        self.score = min(10.0, self.fmt_ctrl + self.write_score + self.addr_ctrl)
        return self.score


class AttackSurfaceComputer:
    """三层评分解耦: 格式串可控性(0-5) × 写入原语(0-3) × 地址可控(0-2).

    Scoring adapted from CVSS v3.1 exploitability metrics, applied to format strings.
    """

    def __init__(self, du: Optional[DefUseChainTracker] = None):
        self._du = du; self._cc = CallingConventionModel()

    def compute(self, model: FmtCallModel) -> AttackSurface:
        s = AttackSurface(fmt_call=model)
        # Layer 1: format string control
        src = model.fmt_source
        if src == "constant":
            s.vectors.append("fmt=CONST")
        elif src == "external" or (self._du and self._du.tainted(model.fmt_string)):
            s.fmt_ctrl = 5.0; s.vectors.append("fmt=EXT(5.0)")
        elif src == "variable":
            s.fmt_ctrl = 2.0; s.vectors.append("fmt=VAR(2.0)")
        else:
            s.fmt_ctrl = 2.5
        # Layer 2: write primitive availability
        prims = [a.primitive for a in model.args]
        s.has_write = any(p >= 3 for p in prims)
        s.has_read = any(p >= 2 for p in prims)
        if s.has_write:
            max_p = max(prims)
            s.write_score = 3.0 if max_p >= 4 else 2.5
            s.vectors.append(f"write={'%hhn' if max_p>=4 else '%n'}")
        elif s.has_read:
            s.write_score = 1.0; s.vectors.append("read=%s")
        # Layer 3: address controllability
        if s.has_write:
            for a in model.args:
                if a.primitive >= 3:
                    slot = a.stack_slot if a.stack_slot >= 0 else self._cc.slot(a.positional)
                    if self._cc.controllable(slot, 128):
                        s.ctrl_write_targets += 1
        if s.ctrl_write_targets >= 2:
            s.addr_ctrl = 2.0; s.vectors.append(f"addr_ctrl={s.ctrl_write_targets}")
        elif s.ctrl_write_targets == 1:
            s.addr_ctrl = 1.0; s.vectors.append("addr_ctrl=1")
        s.finalize()
        return s


# ═══ 集成入口 → 已提取至 analysis.fmt_constraint_pipeline ═══
# 保持向后兼容: 从此处重新导出 (懒加载, 避免与 pipeline 循环导入)
def __getattr__(name):
    if name in ("analyze_format_string_deep", "deep_score_exploitability",
                "enhance_with_constraints"):
        from analysis.fmt_constraint_pipeline import (
            analyze_format_string_deep, deep_score_exploitability,
            enhance_with_constraints,
        )
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ['FmtPrimitive', 'FormatArgModel', 'FmtCallModel',
    'CallingConventionModel', 'DUNode', 'DefUseChainTracker',
    'AttackSurface', 'AttackSurfaceComputer',
    'analyze_format_string_deep', 'deep_score_exploitability',
    'enhance_with_constraints']
