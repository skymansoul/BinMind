"""
路径敏感约束传播 约束依赖图 — 变量间约束依赖+反向链证明.
静态分析看到 malloc(n*4)+buf[idx]=x 时不知 idx是否<n*4, 利用守卫 if(idx<n*4)证明安全.
节点: VarConstraint(name, lo, hi, precision). 边: GUARD→VAR, ASSIGN→VAR, ALLOC→SIZE, WRITE→OFFSET.
保守性: 仅可达约束参与推理, 不可达约束静默跳过.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class VarConstraint:
    """变量约束 — 变量的取值范围."""
    name: str
    lo: int = 0           # 下界 (含)
    hi: int = -1          # 上界 (含), -1=无界
    is_proved: bool = False  # 是否被守卫条件证明
    guard_line: int = 0   # 来源于哪一行的守卫
    dep_vars: Set[str] = field(default_factory=set)  # 依赖的变量


@dataclass
class GuardSite:
    """守卫条件站点 — if(idx < N) 中的守卫信息."""
    line_no: int
    guard_var: str          # 被检查的变量
    operator: str           # < | <= | > | >= | ==
    bound_var: str = ""     # 边界变量 (若为变量)
    bound_const: int = -1   # 边界常量 (若为常量)
    is_constant: bool = False
    then_start: int = 0     # then分支起始行
    then_end: int = 0       # then分支结束行
    else_start: int = 0     # else分支起始行
    else_end: int = 0       # else分支结束行


@dataclass
class ConstraintEdge:
    """约束图中的边."""
    src: str          # 源变量/守卫
    dst: str          # 目标变量
    edge_type: str    # 'guard' | 'assign' | 'arith' | 'alias'
    line_no: int      # 所在行号
    detail: str = ""


class MIVRConstraintGraph:
    """约束依赖图 — 从伪代码构建, 支持查询和传播."""

    _GUARD_RE = re.compile(r'if\s*\(\s*!?\s*(\w+)\s*(<|<=|>|>=|==|!=)\s*(\d+|\w[\w]*)\s*\)')
    _ASSIGN_RE = re.compile(r'(\w+)\s*=\s*(\w[\w]*)\s*([+\-*/]\s*(\w[\w]*|\d+))?\s*;?')
    _MALLOC_RE = re.compile(r'(?:(\w+)\s*=\s*(?:\([^)]*\)\s*)?)?(?:malloc|calloc)\s*\(\s*([^)]+)\s*\)', re.IGNORECASE)
    _WRITE_RE = re.compile(r'(memcpy|memmove|strcpy|strncpy|memset|sprintf|snprintf|strcat)\s*\(', re.IGNORECASE)

    def __init__(self):
        self._constraints: Dict[str, VarConstraint] = {}
        self._guards: List[GuardSite] = []
        self._edges: List[ConstraintEdge] = []
        self._alloc_sites: List[Tuple[int, str, str]] = []  # (line, var, expr)
        self._write_sites: List[Tuple[int, str, str]] = []   # (line, func, target)

    # 构建

    def build(self, pseudocode: str) -> None:
        """从伪代码构建约束依赖图."""
        lines = pseudocode.splitlines()
        self._extract_guards(lines)
        self._extract_assignments(lines)
        self._extract_allocs(lines)
        self._extract_writes(lines)

    def _extract_guards(self, lines: List[str]) -> None:
        """提取 if(idx < N) 守卫 + then/else 边界."""
        i = 0
        while i < len(lines):
            s = lines[i].strip()
            gm = self._GUARD_RE.search(s)
            if gm:
                gv = gm.group(1)
                op = gm.group(2)
                bv_raw = gm.group(3)
                is_c, bc = self._try_int(bv_raw)
                gs = GuardSite(
                    line_no=i, guard_var=gv, operator=op,
                    bound_var="" if is_c else bv_raw,
                    bound_const=bc, is_constant=is_c,
                )
                # 找 then/else 体边界
                gs.then_start, gs.then_end, gs.else_start, gs.else_end, _ = \
                    self._find_branch_bodies(lines, i)
                self._guards.append(gs)
                # 生成约束
                if is_c:
                    if op in ('<', '<='):
                        hi = bc - 1 if op == '<' else bc
                        self._add_constraint(VarConstraint(
                            gv, lo=0, hi=hi, is_proved=True,
                            guard_line=i))
                    elif op in ('>', '>='):
                        lo = bc + 1 if op == '>' else bc
                        self._add_constraint(VarConstraint(
                            gv, lo=lo, hi=-1, is_proved=True,
                            guard_line=i))
                    elif op == '==':
                        self._add_constraint(VarConstraint(
                            gv, lo=bc, hi=bc, is_proved=True,
                            guard_line=i))
                elif bv_raw and bv_raw.isidentifier():
                    self._edges.append(ConstraintEdge(
                        bv_raw, gv, 'guard', i,
                        f'{gv} {op} {bv_raw}'))
            i += 1

    def _extract_assignments(self, lines: List[str]) -> None:
        """提取赋值, 构建变量间约束边."""
        for i, line in enumerate(lines):
            s = line.strip()
            am = self._ASSIGN_RE.search(s)
            if not am:
                continue
            lhs = am.group(1)
            rhs = am.group(2)
            if lhs in ('if', 'else', 'for', 'while', 'return', 'sizeof'):
                continue
            if rhs and rhs.isidentifier() and rhs not in (
                    'NULL', 'nullptr', 'malloc', 'calloc', 'free', 'sizeof'):
                self._edges.append(ConstraintEdge(
                    rhs, lhs, 'assign', i, f'{lhs} = {rhs}'))

    def _extract_allocs(self, lines: List[str]) -> None:
        """提取分配点."""
        for i, line in enumerate(lines):
            s = line.strip()
            mm = self._MALLOC_RE.search(s)
            if mm:
                var = mm.group(1) or "anon"
                expr = mm.group(2)
                self._alloc_sites.append((i, var, expr))

    def _extract_writes(self, lines: List[str]) -> None:
        """提取写入点."""
        for i, line in enumerate(lines):
            s = line.strip()
            wm = self._WRITE_RE.search(s)
            if wm:
                self._write_sites.append((i, wm.group(1), s))

    # 约束操作

    def _add_constraint(self, c: VarConstraint) -> None:
        existing = self._constraints.get(c.name)
        if existing and existing.is_proved:
            return  # 已证明的约束不被覆盖
        self._constraints[c.name] = c

    @staticmethod
    def _try_int(s: str) -> Tuple[bool, int]:
        try:
            return True, int(s)
        except ValueError:
            try:
                return True, int(s, 16)
            except ValueError:
                return False, -1

    @staticmethod
    def _find_branch_bodies(
        lines: List[str], cond_idx: int,
    ) -> Tuple[int, int, int, int, int]:
        """定位 if(cond) { then } else { else } 边界."""
        # 查找 '{'
        brace_idx = -1
        for k in range(cond_idx, min(cond_idx + 3, len(lines))):
            if '{' in lines[k]:
                brace_idx = k
                break
        if brace_idx < 0:
            # 单行if — then-body是下一行
            if cond_idx + 1 < len(lines):
                return cond_idx + 1, cond_idx + 2, -1, -1, cond_idx + 2
            return -1, -1, -1, -1, cond_idx + 1

        # 当 { 与 if 同行时, then-body 从该行开始 (含同行写入)
        if brace_idx == cond_idx:
            then_s = brace_idx
            # 初始深度: 同行内的 brace 差异
            depth = 1 + lines[brace_idx].count('{') - lines[brace_idx].count('}')
        else:
            then_s = brace_idx + 1
            depth = 1
        else_s = -1
        then_e = -1
        else_e = -1
        merge = -1

        for k in range(then_s + 1 if brace_idx == cond_idx else then_s,
                       len(lines)):
            s = lines[k].strip()
            is_else_boundary = s.startswith('} else') or s.startswith('}else')
            if is_else_boundary and then_e < 0:
                then_e = k
                if '{' in s:
                    else_s = k + 1
                else:
                    for m in range(k + 1, min(k + 3, len(lines))):
                        if '{' in lines[m]:
                            else_s = m + 1
                            break
                if else_s > k:
                    depth = 1
                continue
            delta = s.count('{') - s.count('}')
            depth += delta
            if depth <= 0:
                merge = k + 1
                if then_e < 0:
                    then_e = k
                if else_s >= 0 and else_e < 0:
                    else_e = k
                break

        if then_e < 0:
            then_e = merge if merge > 0 else len(lines)
        if else_s >= 0 and else_e < 0:
            else_e = merge if merge > 0 else len(lines)
        return (then_s, then_e, else_s,
                else_e if else_s >= 0 else -1,
                merge if merge > 0 else len(lines))

    # 查询

    def get_constraint(self, var: str) -> Optional[VarConstraint]:
        """获取变量的约束."""
        return self._constraints.get(var)

    def get_direct_constraint(self, var: str) -> Optional[VarConstraint]:
        """获取变量的直接约束 (仅自身被守卫绑定的)."""
        c = self._constraints.get(var)
        if c and c.is_proved:
            return c
        return None

    def resolve_transitive_constraint(
        self, var: str, max_depth: int = 5,
    ) -> Optional[VarConstraint]:
        """通过赋值链传递性解析约束: i = idx, idx < 64 → i ∈ [0, 63]."""
        if max_depth <= 0:
            return None
        direct = self.get_direct_constraint(var)
        if direct:
            return direct
        for edge in self._edges:
            if edge.dst == var and edge.edge_type == 'assign':
                src_c = self.resolve_transitive_constraint(
                    edge.src, max_depth - 1)
                if src_c:
                    return VarConstraint(
                        name=var, lo=src_c.lo, hi=src_c.hi,
                        is_proved=True, guard_line=src_c.guard_line,
                    )
        return None

    def has_guard_before_write(
        self, guard_var: str, write_line: int,
    ) -> Optional[GuardSite]:
        """检查在写入之前是否存在对guard_var的守卫."""
        best = None
        for gs in self._guards:
            if gs.guard_var != guard_var:
                continue
            if gs.line_no > write_line:
                continue
            # 守卫必须在写入之前 (允许同行, guard在write之前)
            if best is None or gs.line_no > best.line_no:
                # 检查写入是否在then分支内
                if gs.then_start <= write_line <= gs.then_end:
                    best = gs
        return best

    @property
    def guards(self) -> List[GuardSite]:
        return self._guards

    @property
    def alloc_sites(self) -> List[Tuple[int, str, str]]:
        return self._alloc_sites

    @property
    def write_sites(self) -> List[Tuple[int, str, str]]:
        return self._write_sites


__all__ = [
    'VarConstraint', 'GuardSite', 'ConstraintEdge',
    'MIVRConstraintGraph',
]
