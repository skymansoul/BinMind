# coding: utf-8
"""
UAF 深度检测管线 — 与 heap overflow 对称的六层 FP 削减架构.
L0:候选提取 L1:生命周期区间 L2:别名(union-find) L3:路径可达性 L4:时序约束求解.
参考: CRIX (Usenix'22), MineSweeper (NDSS'22)."""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from compat.uaf_constraint import (
    UafConstraintSystem, UafCandidate, UafEventType,
    LifetimeInterval, AliasGraph, encode_uaf_lifetime,
    prove_uaf_infeasible,
)


@dataclass
class UafLayerStats:
    name: str; input_count: int; retained: int; duration_ms: float

@dataclass
class UafPipelineResult:
    total_candidates: int; final_candidates: int
    layer_stats: List[UafLayerStats]; exploitable: int
    reduction_rate: float; total_duration_ms: float


class DeepUafDetector:
    """UAF 六层深度检测器 — 与 DeepHeapOrchestrator 对称."""

    def __init__(self,
                 enable_alias: bool = True,
                 enable_path: bool = True,
                 enable_constraint: bool = True,
                 alias_depth: int = 5):
        self.enable_alias = enable_alias
        self.enable_path = enable_path
        self.enable_constraint = enable_constraint
        self.alias_depth = alias_depth

    def detect(self,
               instructions: List[Dict],
               ir_ops: Dict[int, Dict],
               callee_names: Dict[int, str],
               ) -> UafPipelineResult:
        """执行六层 UAF 检测管线."""
        t0 = time.perf_counter()
        layers: List[UafLayerStats] = []

# L0: 候选提取
        candidates = self._extract_candidates(
            instructions, ir_ops, callee_names)
        total = len(candidates)
        layers.append(UafLayerStats(
            'L0_extract', 0, total, 0))

# L1: 生命周期区间过滤
        before = len(candidates)
        candidates = [c for c in candidates
                      if not self._l1_lifetime_filter(c, instructions)]
        layers.append(UafLayerStats(
            'L1_lifetime', before, len(candidates), 0))

# L2: 别名追踪
        if self.enable_alias:
            before = len(candidates)
            candidates = self._l2_alias_filter(
                candidates, instructions, ir_ops)
            layers.append(UafLayerStats(
                'L2_alias', before, len(candidates), 0))

# L3: 路径可达性
        if self.enable_path:
            before = len(candidates)
            candidates = [c for c in candidates
                          if not self._l3_path_filter(c, instructions)]
            layers.append(UafLayerStats(
                'L3_path', before, len(candidates), 0))

# L4: 约束求解
        if self.enable_constraint:
            before = len(candidates)
            candidates = self._l4_constraint_filter(
                candidates, instructions)
            layers.append(UafLayerStats(
                'L4_constraint', before, len(candidates), 0))

        elapsed = (time.perf_counter() - t0) * 1000
        reduction = (total - len(candidates)) / max(1, total)

        return UafPipelineResult(
            total_candidates=total,
            final_candidates=len(candidates),
            layer_stats=layers,
            exploitable=sum(
                1 for c in candidates if c.get('confidence', 0) > 0.7),
            reduction_rate=reduction,
            total_duration_ms=elapsed,
        )

# L0: 候选提取

    def _extract_candidates(self, instructions: List[Dict],
                            ir_ops: Dict[int, Dict],
                            callee_names: Dict[int, str]) -> List[Dict]:
        """识别 alloc→free→use 三元组, 含别名传播和 realloc 悬空检测."""
        candidates = []
        alloc_records: List[Tuple[int, int, str]] = []
        alias_map: Dict[str, List[str]] = {}  # ptr → [alias1, alias2, ...]

        for inst in instructions:
            addr = inst['addr']
            callee = callee_names.get(addr, '').lower()

            if any(a in callee for a in
                   ('malloc', 'calloc', 'realloc', '_Znwm', '_Znam')):
                op = ir_ops.get(addr, {})
                sz = op.get('alloc_size', op.get('size', 0))
                ptr = op.get('dest', op.get('return_reg', 'rax'))
                alloc_records.append((addr, sz, ptr))
                # realloc: 旧指针变为悬空
                if 'realloc' in callee:
                    old_ptr = op.get('src', op.get('arg0', ''))
                    if old_ptr and old_ptr != ptr:
                        for a_addr, a_sz, a_ptr in alloc_records:
                            if a_ptr == old_ptr and a_addr != addr:
                                for inst2 in instructions:
                                    addr2 = inst2['addr']
                                    if addr2 <= addr: continue
                                    op2 = ir_ops.get(addr2, {})
                                    if (old_ptr in str(op2.get('src', '')) or
                                        old_ptr in str(op2.get('dest', ''))):
                                        if op2.get('op_type') in ('load','store','call'):
                                            candidates.append({
                                                'alloc_site': a_addr, 'free_site': addr,
                                                'use_site': addr2, 'alloc_size': a_sz,
                                                'ptr_name': old_ptr,
                                                'vuln_type': 'use_after_realloc',
                                                'confidence': 0.75})

            # 追踪别名: store dest=alias, src=original
            op = ir_ops.get(addr, {})
            if op.get('op_type') == 'store':
                dest = op.get('dest', '')
                src = op.get('src', '')
                if dest and src:
                    alias_map.setdefault(src, []).append(dest)

            elif 'free' in callee or 'delete' in callee:
                op = ir_ops.get(addr, {})
                freed_ptr = op.get('src', op.get('arg0', 'rdi'))
                # 扩展: 检查 freed_ptr 是否是某个别名
                ptrs_to_check = {freed_ptr}
                for orig, aliases in alias_map.items():
                    if freed_ptr in aliases or freed_ptr == orig:
                        ptrs_to_check.update(aliases)
                        ptrs_to_check.add(orig)

                for a_addr, a_sz, a_ptr in alloc_records:
                    # 直接匹配或别名匹配
                    if a_ptr != freed_ptr and a_ptr not in ptrs_to_check:
                        continue
                    for inst2 in instructions:
                        addr2 = inst2['addr']
                        if addr2 <= addr: continue
                        op2 = ir_ops.get(addr2, {})
                        src_str = str(op2.get('src', ''))
                        dest_str = str(op2.get('dest', ''))
                        # 检查原始指针及其所有别名
                        all_refs = {freed_ptr, a_ptr} | ptrs_to_check
                        if any(p in src_str or p in dest_str for p in all_refs):
                            if op2.get('op_type') in ('load', 'store', 'call'):
                                candidates.append({
                                    'alloc_site': a_addr, 'free_site': addr,
                                    'use_site': addr2, 'alloc_size': a_sz,
                                    'ptr_name': freed_ptr,
                                    'vuln_type': 'use_after_free',
                                    'confidence': 0.6})

        return candidates

# L1: 生命周期区间

    def _l1_lifetime_filter(self, c: Dict,
                            instructions: List[Dict]) -> bool:
        """若 use_ts ∈ [alloc_ts, free_ts) → 安全, 过滤."""
        addrs = sorted(set(inst['addr'] for inst in instructions))
        ts_map = {a: i for i, a in enumerate(addrs)}

        alloc_idx = ts_map.get(c['alloc_site'], 0)
        free_idx = ts_map.get(c['free_site'], 0)
        use_idx = ts_map.get(c['use_site'], 0)

        # use 在 free 之前 → 安全
        if use_idx <= free_idx:
            return True
        # use 在 alloc 之前 → 未初始化, 不同漏洞类别
        if use_idx < alloc_idx:
            return True
        return False

# L2: 别名追踪

    def _l2_alias_filter(self, candidates: List[Dict],
                         instructions: List[Dict],
                         ir_ops: Dict[int, Dict]) -> List[Dict]:
        """Union-find 别名追踪: free(ptr) 后检查悬挂指针别名传播."""
        ag = AliasGraph()

        for inst in instructions:
            addr = inst['addr']
            op = ir_ops.get(addr, {})
            if op.get('op_type') == 'store':
                dest = op.get('dest', '')
                src = op.get('src', '')
                if dest and src:
                    ag.alias(dest, src)

        retained = []
        for c in candidates:
            alloc_site = c['alloc_site']
            ptr = c['ptr_name']
            obj_id = f'obj_{alloc_site:x}'
            ag.alloc_ptr(ptr, obj_id)

            aliases = ag.get_aliases(obj_id)
            use_site = c['use_site']

            # 检查 use 点是否通过别名访问
            uses_alias = any(
                a != ptr for a in aliases
            )
            if uses_alias:
                # 别名可能指向不同对象 — 保留但降权
                c['confidence'] *= 0.85
                c['_alias_note'] = f'别名集={aliases}'
            retained.append(c)

        return retained

# L3: 路径可达性

    def _l3_path_filter(self, c: Dict,
                        instructions: List[Dict]) -> bool:
        """检查 free→use CFG 路径. 若不可达 → 过滤."""
        edges: Dict[int, List[int]] = {}
        addrs = sorted(inst['addr'] for inst in instructions)

        for i, addr in enumerate(addrs):
            edges.setdefault(addr, [])
            if i + 1 < len(addrs):
                edges[addr].append(addrs[i + 1])
            # 跳转边 (从 ir_ops 推断)
            for inst in instructions:
                if inst['addr'] == addr:
                    mnem = inst.get('mnemonic', '').lower()
                    if mnem in ('jmp', 'ret'):
                        break
                    if mnem in ('jz', 'je', 'jnz', 'jne', 'jg', 'jl',
                                'jge', 'jle', 'ja', 'jb', 'jae', 'jbe'):
                        # 从 comment 解析目标
                        cmt = inst.get('comment', '')
                        import re
                        m = re.search(r'(0x[0-9a-fA-F]+)', cmt)
                        if m:
                            edges[addr].append(int(m.group(1), 16))

        # BFS 检查可达性
        visited: Set[int] = set()
        queue = [c['free_site']]
        while queue:
            cur = queue.pop(0)
            if cur == c['use_site']:
                return False  # 可达 → 不过滤
            if cur in visited:
                continue
            visited.add(cur)
            for nxt in edges.get(cur, []):
                if nxt not in visited:
                    queue.append(nxt)

        return True  # 不可达 → 过滤

# L4: 约束求解

    def _l4_constraint_filter(self, candidates: List[Dict],
                              instructions: List[Dict]) -> List[Dict]:
        """UafConstraintSystem: 证明时序约束不可满足."""
        addrs = sorted(set(inst['addr'] for inst in instructions))
        ts_map = {a: i for i, a in enumerate(addrs)}

        retained = []
        for c in candidates:
            safe, reason = prove_uaf_infeasible(
                c['alloc_site'], c['free_site'], c['use_site'],
                ts_map, c['ptr_name'],
            )
            if safe:
                c['_filtered_by'] = 'L4_constraint'
                c['_filter_reason'] = reason
            else:
                retained.append(c)

        return retained


def uaf_quick_scan(instructions: List[Dict],
                   ir_ops: Dict[int, Dict],
                   callee_names: Dict[int, str],
                   ) -> UafPipelineResult:
    """快速 UAF 扫描 — 仅 L0+L1."""
    detector = DeepUafDetector(
        enable_alias=False, enable_path=False, enable_constraint=False)
    return detector.detect(instructions, ir_ops, callee_names)


def uaf_deep_scan(instructions: List[Dict],
                  ir_ops: Dict[int, Dict],
                  callee_names: Dict[int, str],
                  ) -> UafPipelineResult:
    """深度 UAF 扫描 — L0-L4 全层级."""
    detector = DeepUafDetector(
        enable_alias=True, enable_path=True, enable_constraint=True)
    return detector.detect(instructions, ir_ops, callee_names)
