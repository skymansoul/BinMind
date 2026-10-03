# coding: utf-8
"""
值同余追踪 (Value Congruence Tracking) — 轻量关系域, 专为堆安全证明设计.
核心: 在 def-use 链上传播 ==, ≤, +k 关系, O(|V|·α(|V|)) per query.
解决 "malloc(N) 和 memcpy(..., N) 用同一变量" 这一最大 FP 来源.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


class RelationGraph:
    """变量关系图 — 维护 == (union-find), ≤ (邻接表), +k (偏移映射).

    查询复杂度: find(x) = O(α(|V|)).
    """

    def __init__(self):
        self._parent: Dict[str, str] = {}
        self._meta: Dict[str, Dict] = {}          # {root: {min_val, max_val, constant}}
        self._le_edges: Dict[str, List[Tuple[str, str]]] = {}  # u → [(v, 'LE')]
        self._offset: Dict[str, List[Tuple[str, int]]] = {}   # u → [(v, k)] u==v+k

    def _find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            self._meta[x] = {'min_val': 0, 'max_val': -1, 'constant': None}
        while self._parent.get(x, x) != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def _union(self, a: str, b: str):
        ra, rb = self._find(a), self._find(b)
        if ra == rb:
            return
        self._parent[ra] = rb
        ma, mb = self._meta.get(ra, {}), self._meta.get(rb, {})
        merged = {}
        if ma.get('constant') is not None and mb.get('constant') is not None:
            if ma['constant'] != mb['constant']:
                return
            merged['constant'] = ma['constant']
        else:
            merged['constant'] = ma.get('constant') or mb.get('constant')
        merged['min_val'] = max(ma.get('min_val', 0), mb.get('min_val', 0))
        ma_max, mb_max = ma.get('max_val', -1), mb.get('max_val', -1)
        merged['max_val'] = mb_max if ma_max < 0 else (ma_max if mb_max < 0 else min(ma_max, mb_max))
        self._meta[rb] = merged

    def set_equal(self, x: str, y: str):
        self._union(x, y)

    def set_leq(self, x: str, y: str):
        rx, ry = self._find(x), self._find(y)
        if rx != ry:
            self._le_edges.setdefault(rx, []).append((ry, 'LE'))

    def set_geq(self, x: str, y: str):
        self.set_leq(y, x)

    def set_plus_k(self, x: str, y: str, k: int):
        if k == 0:
            self.set_equal(x, y)
            return
        rx, ry = self._find(x), self._find(y)
        if rx != ry:
            self._offset.setdefault(rx, []).append((ry, k))

    def set_constant(self, x: str, value: int):
        root = self._find(x)
        existing = self._meta[root].get('constant')
        if existing is not None and existing != value:
            return
        self._meta[root]['constant'] = value
        self._meta[root]['min_val'] = max(self._meta[root]['min_val'], value)
        cur_max = self._meta[root]['max_val']
        self._meta[root]['max_val'] = min(cur_max, value) if cur_max >= 0 else value

    def can_prove_leq(self, alloc_var: str, write_var: str) -> Tuple[bool, str]:
        """证明 write ≤ alloc (即写入不超过分配)."""
        ra, rw = self._resolve_id(alloc_var), self._resolve_id(write_var)
        if ra is None or rw is None:
            return False, '无法解析变量到关系图'
        if ra == rw:
            return True, '同源变量'
        ma, mw = self._meta.get(ra, {}), self._meta.get(rw, {})
        ac, wc = ma.get('constant'), mw.get('constant')
        if ac is not None and wc is not None and ac >= wc:
            return True, f'常数: {ac} ≥ {wc}'
        if ac is not None and mw.get('max_val', -1) >= 0 and ac >= mw['max_val']:
            return True, f'常数 alloc={ac} ≥ write_max={mw["max_val"]}'
        # 偏移链: alloc == write + k (k ≥ 0) → alloc ≥ write → 安全
        if ra in self._offset:
            for t, k in self._offset[ra]:
                if self._find(t) == rw and k >= 0:
                    return True, f'alloc == write + {k}'
        # BFS 传递链
        if self._path_exists(rw, ra):
            return True, '传递链: write ≤ ... ≤ alloc'
        return False, '无法证明'

    def _resolve_id(self, var: str) -> Optional[str]:
        """将 var@addr 解析到图节点. 若精确键不存在, 按变量主干匹配."""
        if var in self._parent:
            return self._find(var)
        stem = var[:var.rfind('@')] if '@' in var else var
        if not stem:
            return None
        root: Optional[str] = None
        for key in list(self._parent):
            if key.startswith(stem + '@'):
                r = self._find(key)
                if root is None:
                    root = r
                elif root != r:
                    return None
        return root

    def _path_exists(self, src: str, dst: str, max_depth: int = 8) -> bool:
        if src == dst:
            return True
        visited = {src}
        q = [(src, 0)]
        while q:
            u, d = q.pop(0)
            if d > max_depth:
                continue
            for v, _ in self._le_edges.get(u, []):
                if v == dst:
                    return True
                if v not in visited:
                    visited.add(v)
                    q.append((v, d + 1))
        return False


class ValueFlowTracer:
    """沿 IR 操作 + def-use 链构建 RelationGraph."""

    def __init__(self):
        self.graph = RelationGraph()
        self._last_def: Dict[str, int] = {}  # var_name → 最后定义的地址

    @staticmethod
    def _canonical(addr: int, var: str) -> str:
        return f'{var}@{addr:x}'

    def _resolve(self, addr: int, var: str) -> str:
        """解析变量到其最新定义点的 canonical ID."""
        if var in self._last_def:
            return f'{var}@{self._last_def[var]:x}'
        return f'{var}@{addr:x}'

    def trace_from_ir(self, ir_ops: Dict[int, Dict],
                      def_use: Dict[int, List[int]] = None) -> RelationGraph:
        """从 IR 操作提取 ==, ≤, +k 关系."""
        def_use = def_use or {}
        for addr, op in sorted(ir_ops.items()):
            op_type = op.get('op_type', '')
            dst = op.get('dest', op.get('dst', ''))
            src, src2 = op.get('src', ''), op.get('src2', op.get('operand2', ''))
            if not dst:
                continue
            did = self._canonical(addr, dst)
            sid = self._resolve(addr, src) if src else ''
            # MOV: dst == src (若 src 是变量而非立即数)
            if op_type in ('mov', 'li', 'assign', 'load_imm', 'const', 'cast'):
                if src and not _imm(src):
                    self.graph.set_equal(did, sid)
                if (imm := _imm(op.get('value', op.get('imm', src)))) is not None:
                    self.graph.set_constant(did, imm)
            # ADD: dst == src + k or dst ≥ src
            elif op_type == 'add' and src:
                if src2 and (k := _imm(src2)) is not None:
                    self.graph.set_plus_k(did, sid, abs(k))
                else:
                    self.graph.set_geq(did, sid)
            # SUB: src == dst + k or dst ≤ src
            elif op_type == 'sub' and src:
                if src2 and (k := _imm(src2)) is not None and k > 0:
                    self.graph.set_plus_k(sid, did, k)
                else:
                    self.graph.set_leq(did, sid)
            # MUL/SHL: dst ≥ src
            elif op_type in ('mul', 'shl') and src:
                self.graph.set_geq(did, sid)
            # 记录此变量在此地址被定义
            self._last_def[dst] = addr
            # def-use 传播: 仅在 use 指令为 passthrough (mov/load) 时建立相等
            # 算术操作 (add/sub/mul) 的 dst≠src, 关系已由 op handler 捕获
            if addr in def_use:
                for use_addr in def_use[addr]:
                    if (use_op := ir_ops.get(use_addr, {})):
                        use_type = use_op.get('op_type', '')
                        ud = use_op.get('dest', use_op.get('dst', ''))
                        if ud and use_type in ('mov', 'li', 'assign', 'load_imm', 'const', 'cast'):
                            self.graph.set_equal(did, self._canonical(use_addr, ud))
        return self.graph


def _imm(val: Any) -> Optional[int]:
    if isinstance(val, int):
        return val
    if not isinstance(val, str):
        return None
    v = val.strip()
    try:
        return int(v, 16) if v.startswith(('0x', '0X')) else int(v)
    except ValueError:
        return None


def prove_heap_safety(alloc_site: int, write_site: int,
                      alloc_var: str, write_var: str,
                      ir_ops: Dict[int, Dict],
                      def_use: Dict[int, List[int]] = None,
                      alloc_id: Optional[str] = None,
                      write_id: Optional[str] = None) -> Tuple[bool, str, RelationGraph]:
    """证明堆操作安全性: alloc_size ≥ write_size.

    alloc_id/write_id: 前端预解析的值键 (var@defaddr). 提供则直接查询,
    避免依赖全局 last-def 的误解析.
    """
    t = ValueFlowTracer()
    g = t.trace_from_ir(ir_ops, def_use)
    aid = alloc_id if alloc_id else t._resolve(alloc_site, alloc_var)
    wid = write_id if write_id else t._resolve(write_site, write_var)
    safe, reason = g.can_prove_leq(aid, wid)
    return safe, reason, g


def batch_prove_heap_safety(candidates: List[Dict], ir_ops: Dict[int, Dict],
                            def_use: Dict[int, List[int]] = None) -> Tuple[List[Dict], Dict]:
    """批量安全证明. 返回 (filtered, stats)."""
    t = ValueFlowTracer()
    g = t.trace_from_ir(ir_ops, def_use)
    stats = {'total': len(candidates), 'proved_safe': 0}
    filtered = []
    for c in candidates:
        aid = c.get('alloc_id') or t._resolve(c.get('alloc_site', 0),
                                              c.get('alloc_size_var', 'size'))
        wid = c.get('write_id') or t._resolve(c.get('write_site', 0),
                                              c.get('write_size_var', 'size'))
        safe, reason = g.can_prove_leq(aid, wid)
        if safe:
            c['_vct_safe'], c['_vct_reason'] = True, reason
            stats['proved_safe'] += 1
        else:
            filtered.append(c)
    stats['retained'] = len(filtered)
    return filtered, stats
