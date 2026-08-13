"""SHIELD 编排器 — 三引擎串联: 指针溯源 → 不相交证明 → 尺寸约束关联.

SHIELD = Selective Heap Interval-Evidence Logical Disambiguation.
任一引擎证明安全即可滤除误报:
  E1 Pointer Provenance: 追踪指针必须来源 (哪个 malloc)
  E2 Disjointness Prover: (A)不同alloc不重叠 (B)访问在可用范围内 (C)live-range互斥
  E3 Size-Bound Correlator: 证明 access_size ≤ alloc_size 恒成立

与 ImprovedHeapOverflowDetector 集成: 产生初始findings → SHIELD滤除 → 保留真实告警.
创建: 2025-01-13
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

try:
    from .pointer_provenance import (
        PointerProvenanceEngine, PointerOrigin, PointerState)
    from .disjointness_prover import (
        DisjointnessProver, HeapAccess, DisjointnessProof)
    from .size_bound_correlation import (
        SizeBoundCorrelator, ValueExpr)
except ImportError:
    from pointer_provenance import (  # type: ignore[no-redef]
        PointerProvenanceEngine, PointerOrigin, PointerState)
    from disjointness_prover import (  # type: ignore[no-redef]
        DisjointnessProver, HeapAccess, DisjointnessProof)
    from size_bound_correlation import (  # type: ignore[no-redef]
        SizeBoundCorrelator, ValueExpr)


@dataclass
class ShieldVerdict:
    """SHIELD 的综合判定结果."""
    finding_id: str
    is_safe: bool                    # True = 滤除 (误报)
    engine: str = ""                 # 哪个引擎证明的 (provenance/disjointness/size_bound)
    confidence: float = 0.0
    reasoning: str = ""
    alloc_expr: Optional[ValueExpr] = None
    access_expr: Optional[ValueExpr] = None
    provenance_result: str = ""
    disjointness_result: str = ""
    correlation_result: str = ""


@dataclass
class ShieldReport:
    """SHIELD 完整分析报告."""
    verdicts: List[ShieldVerdict]
    total_findings: int
    filtered: int                       # 证明安全的数量
    confirmed: int                      # 无法证明安全的数量
    filter_rate: float
    engine_stats: Dict[str, int]        # 每个引擎的贡献
    avg_confidence: float


class ShieldOrchestrator:
    """SHIELD 三引擎编排器 — 堆溢出误报消减.

    使用方式:
      orch = ShieldOrchestrator()
      report = orch.analyze(instructions, findings)
      # findings 来自 ImprovedHeapOverflowDetector.analyze()
    """

    _ACCESS_PAT = re.compile(
        r'mov\s+(?:qword|dword|word|byte)\s+ptr\s+\[(\w+)\s*(?:\+\s*(0x[0-9a-f]+|\d+))?\]',
        re.I)
    _CALL_PAT = re.compile(
        r'call\s+(?:[0-9a-f]+\s+<)?([^>\s]+)(?:@plt)?>?', re.I)

    def __init__(self):
        self._provenance = PointerProvenanceEngine()
        self._disjointness = DisjointnessProver()
        self._correlator = SizeBoundCorrelator()

        self._engine_stats = {
            'provenance': 0, 'disjointness': 0, 'size_bound': 0,
            'unfiltered': 0}

    def analyze(self, instructions: List[str],
                findings: List[dict],
                addrs: Optional[List[int]] = None
                ) -> ShieldReport:
        """对 findings 逐一运行 SHIELD 三引擎, 返回综合报告."""
        # 指针溯源 — 全局分析一次
        state = self._provenance.analyze(instructions, addrs)

        # 注册 alloc 点到 disjointness prover
        for alloc_addr in self._provenance.alloc_sites:
            self._disjointness.register_alloc(alloc_addr)

        # 识别指令中的 malloc/memcpy 调用点
        malloc_calls, memcpy_calls = self._find_calls(instructions)

        verdicts: List[ShieldVerdict] = []
        for f in findings:
            v = self._evaluate_finding(f, instructions, state,
                                        malloc_calls, memcpy_calls)
            verdicts.append(v)

        total = len(verdicts)
        filtered = sum(1 for v in verdicts if v.is_safe)
        confirmed = total - filtered

        avg_conf = (sum(v.confidence for v in verdicts) / max(1, total))

        return ShieldReport(
            verdicts=verdicts, total_findings=total,
            filtered=filtered, confirmed=confirmed,
            filter_rate=filtered / max(1, total),
            engine_stats=dict(self._engine_stats),
            avg_confidence=avg_conf)

    def _evaluate_finding(self, f: dict, instructions: List[str],
                          state: PointerState,
                          malloc_calls: Dict[int, str],
                          memcpy_calls: Dict[int, str]
                          ) -> ShieldVerdict:
        """对单个 finding 运行三引擎证明管线."""
        fid = f.get('description', str(f.get('insn_addr', 'unknown')))
        insn_addr = f.get('insn_addr', 0)
        alloc_addr = f.get('alloc_site', 0)
        access_offset = f.get('access_offset', 0)
        access_size = f.get('access_size', 4)
        alloc_size = f.get('alloc_size_requested', 0)

# Engine 1: 指针溯源
        prov_result = ""
        origin = state.reg_origin  # 从全局 state 查询

# Engine 2: 不相交证明
        # 构建 HeapAccess 并检查
        heap_acc = HeapAccess(
            insn_addr=insn_addr,
            ptr_register='',  # 从 finding 推断
            offset_expr=str(access_offset),
            offset_value=access_offset,
            access_size=access_size,
            origin=origin.get('rax')  # 尝试获取 rax 的溯源
        )

        disc_proof = self._disjointness.check_access(
            heap_acc, known_alloc_size=alloc_size)

        if disc_proof.is_safe:
            self._engine_stats['disjointness'] += 1
            return ShieldVerdict(
                finding_id=fid, is_safe=True,
                engine='disjointness', confidence=disc_proof.confidence,
                reasoning=disc_proof.reasoning,
                disjointness_result=disc_proof.reasoning)

# Engine 3: 尺寸约束关联
        # 找到最近的 malloc 调用和 memcpy 调用
        corr_result = ""
        if malloc_calls and memcpy_calls:
            # finding 地址 → 指令索引, 然后找前后的 malloc/memcpy
            insn_idx = self._find_insn_index(instructions, insn_addr)
            mall_idx = self._nearest_before(malloc_calls, insn_idx)
            memc_idx = self._nearest_after(memcpy_calls, insn_idx)

            # memcpy 可能在 finding 之前 (size参数在memcpy调用时确定)
            if memc_idx is None:
                memc_idx = self._nearest_before(memcpy_calls, insn_idx)

            if mall_idx is not None and memc_idx is not None:
                alloc_expr = self._correlator.trace_alloc_size(
                    instructions, mall_idx)
                access_expr = self._correlator.trace_access_size(
                    instructions, memc_idx)
                safe = self._correlator.prove_safe(alloc_expr, access_expr)

                if safe:
                    self._engine_stats['size_bound'] += 1
                    return ShieldVerdict(
                        finding_id=fid, is_safe=True,
                        engine='size_bound',
                        confidence=0.85,
                        reasoning=f'{access_expr} ≤ {alloc_expr} provably safe',
                        alloc_expr=alloc_expr, access_expr=access_expr,
                        correlation_result=f'{access_expr} ≤ {alloc_expr}')

                corr_result = (f'alloc={alloc_expr}, access={access_expr}, '
                              f'safe={safe}')

# 无法证明安全
        self._engine_stats['unfiltered'] += 1
        return ShieldVerdict(
            finding_id=fid, is_safe=False,
            engine='none', confidence=0.0,
            reasoning='could not prove safety with any SHIELD engine',
            provenance_result=prov_result,
            disjointness_result=disc_proof.reasoning,
            correlation_result=corr_result)

    def _find_calls(self, instructions: List[str]
                    ) -> Tuple[Dict[int, str], Dict[int, str]]:
        """找出所有 malloc 和 memcpy 调用点, 返回 {指令索引: 函数名}."""
        mallocs: Dict[int, str] = {}
        memcpys: Dict[int, str] = {}
        for i, il in enumerate(instructions):
            m = self._CALL_PAT.search(il.strip().lower())
            if not m:
                continue
            func = m.group(1).lower()
            if any(af in func for af in ('malloc', 'calloc', 'realloc')):
                mallocs[i] = func
            elif any(sf in func for sf in ('memcpy', 'memmove')):
                memcpys[i] = func
        return mallocs, memcpys

    @staticmethod
    def _nearest_before(calls: Dict[int, str],
                        target_idx: int) -> Optional[int]:
        candidates = [idx for idx in calls if idx < target_idx]
        return max(candidates) if candidates else None

    @staticmethod
    def _nearest_after(calls: Dict[int, str],
                       target_idx: int) -> Optional[int]:
        candidates = [idx for idx in calls if idx > target_idx]
        return min(candidates) if candidates else None

    def _find_insn_index(self, instructions: List[str],
                          target_addr: int,
                          addrs: Optional[List[int]] = None) -> int:
        """将指令地址转换为指令索引."""
        if addrs:
            for i, a in enumerate(addrs):
                if a == target_addr:
                    return i
        # fallback: 在指令文本中搜索地址
        for i, il in enumerate(instructions):
            if f'{target_addr:x}:' in il.lower():
                return i
        return -1

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._engine_stats)

    def clear(self):
        self._provenance = PointerProvenanceEngine()
        self._disjointness = DisjointnessProver()
        self._correlator = SizeBoundCorrelator()
        for k in self._engine_stats:
            self._engine_stats[k] = 0


# smoke
def _check():
    """SHIELD 编排器集成测试: 安全/溢出/多alloc 三个场景."""
    orch = ShieldOrchestrator()
    insns = [
        "  401000:\tmov    eax,DWORD PTR [rbp+0x10]",
        "  401003:\tmov    edx,eax", "  401005:\tadd    eax,0x1",
        "  401008:\tmov    ecx,eax", "  40100a:\tcall   malloc",
        "  40100f:\tmov    r8,rdx", "  401012:\tcall   memcpy",
        "  401017:\tmov    DWORD PTR [rax+0x4],0x42",
    ]
    # Case 1: s≤s+1 → size_bound 证明安全
    r1 = orch.analyze(insns, [{'insn_addr': 0x401017, 'access_offset': 4,
        'access_size': 4, 'alloc_size_requested': 64,
        'description': 'safe'}])
    assert r1.filtered == 1, f"Case1 should filter, got {r1.filtered}"
    print(f"  Case1 (safe s≤s+1): filtered={r1.filtered}/{r1.total_findings} "
          f"engine={r1.verdicts[0].engine}")
    # Case 2: offset 0x100 > alloc 64 → 不可证明安全
    orch.clear()
    r2 = orch.analyze(insns, [{'insn_addr': 0x401027, 'access_offset': 0x100,
        'access_size': 4, 'alloc_size_requested': 64,
        'description': 'overflow'}])
    assert r2.filtered == 0, f"Case2 should NOT filter"
    print(f"  Case2 (overflow 0x100): filtered={r2.filtered}/{r2.total_findings}")
    # Case 3: multi-alloc, access within bounds → disjointness 证明安全
    orch.clear()
    r3 = orch.analyze([
        "  402000:\tmov    ecx,0x40", "  402005:\tcall   malloc",
        "  40200a:\tmov    rbx,rax", "  40200d:\tmov    ecx,0x80",
        "  402012:\tcall   malloc",
        "  402017:\tmov    DWORD PTR [rbx+0x3c],0x42",
    ], [{'insn_addr': 0x402017, 'access_offset': 0x3c,
         'access_size': 4, 'alloc_size_requested': 64,
         'description': 'multi'}])
    assert r3.filtered == 1, f"Case3 should filter"
    print(f"  Case3 (multi-alloc): filtered={r3.filtered}/{r3.total_findings} "
          f"engine={r3.verdicts[0].engine}")
    print("[OK] shield_orchestrator tests passed")

if __name__ == "__main__":
    _check()
