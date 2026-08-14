"""
集成堆溢出验证器 —— 组合 DDAI-ASR 四层分析做最终判定。
四层: 堆抽象域、路径约束提取、不动点区间抽象解释、分配器语义对齐过滤。
"""

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.heap_abstract_domain import (
    HeapAbstractDomain, HeapObject, Interval, compute_effective_size,
)
from core.path_constraints import (
    ConstraintExtractor, LinearConstraint, refine_interval_with_constraints,
)
from core.abstract_engine import AbstractEngine, AbstractState
from core.allocator_constraints import AllocatorConstraintChecker
from core.heap_verify_helpers import verify_candidate, split_args

@dataclass
class VerifyResult:
    """单条告警的验证结果。"""
    original_type: str = ""         # heap-overflow / double-free / UAF
    pointer: str = ""               # 涉及的指针变量
    line_no: int = -1               # 行号
    code_line: str = ""             # 对应代码行
    verdict: str = "UNCERTAIN"     # KEEP / FILTER / UNCERTAIN
    reason: str = ""               # 判定理由
    confidence: float = 0.5        # 调整后的置信度
    alloc_size: int = 0            # 请求分配大小
    effective_size: int = 0        # 实际可用大小
    max_write: int = -1            # 最大写入偏移
    elapsed_ms: float = 0.0        # 分析耗时(ms)

@dataclass
class VerifySummary:
    """批量验证汇总统计。"""
    total_input: int = 0
    kept: int = 0
    filtered: int = 0
    uncertain: int = 0
    fp_reduction_rate: float = 0.0  # 误报压缩率: FILTER / total
    avg_confidence_kept: float = 0.0
    total_elapsed_ms: float = 0.0
    details: List[VerifyResult] = field(default_factory=list)

class HeapVerify:
    """堆漏洞验证引擎的核心入口: verify_function(伪代码) → VerifySummary。"""

    def __init__(self, arch_bits: int = 64, platform: str = "x86_64"):
        self._arch_bits = arch_bits
        self._engine = AbstractEngine(arch_bits)
        self._checker = AllocatorConstraintChecker(platform)
        self._constraint_extractor = ConstraintExtractor()

    def verify_function(
        self, pseudocode: str, func_name: str = "",
    ) -> VerifySummary:
        """验证单个函数中所有堆操作的溢出风险: 快速扫描→抽象解释→精确判定。"""
        t_start = time.time()
        results: List[VerifyResult] = []

        if not pseudocode.strip():
            return VerifySummary()

        # 快速扫描候选点
        candidates = self._scan_candidates(pseudocode)

        # 抽象解释
        states = self._engine.analyze(pseudocode)

        # 对每个候选做判定
        for cand in candidates:
            result = verify_candidate(cand, states, pseudocode)
            results.append(result)

        elapsed = (time.time() - t_start) * 1000

        # 汇总
        kept = [r for r in results if r.verdict == "KEEP"]
        filtered = [r for r in results if r.verdict == "FILTER"]
        uncertain = [r for r in results if r.verdict == "UNCERTAIN"]

        return VerifySummary(
            total_input=len(results),
            kept=len(kept),
            filtered=len(filtered),
            uncertain=len(uncertain),
            fp_reduction_rate=len(filtered) / max(1, len(results)),
            avg_confidence_kept=(
                sum(r.confidence for r in kept) / max(1, len(kept))
            ),
            total_elapsed_ms=elapsed,
            details=results,
        )

    def verify_batch(
        self, decompiled: Dict[str, str],
    ) -> Dict[str, VerifySummary]:
        """批量验证多个函数。"""
        return {
            fname: self.verify_function(code, fname)
            for fname, code in decompiled.items()
        }

    @staticmethod
    def verify_findings(
        findings: List[Dict[str, Any]],
        pseudocode: str = "",
        binary_path: str = "",
    ) -> Tuple[List[Dict[str, Any]], VerifySummary]:
        """兼容原有 findings 接口 —— 验证并调整置信度。"""
        verifier = HeapVerify()
        summary = verifier.verify_function(pseudocode)

        # 构建 verdict map
        verdict_map: Dict[str, str] = {}
        for r in summary.details:
            key = f"{r.pointer}:{r.line_no}"
            verdict_map[key] = r.verdict

        for f in findings:
            ptr = f.get("pointer", f.get("dest", ""))
            key = f"{ptr}:{f.get('line', -1)}"
            if key in verdict_map:
                v = verdict_map[key]
                if v == "FILTER":
                    f["confidence"] = round(f.get("confidence", 0.5) * 0.30, 3)
                    f["verification"] = "filtered-by-abstract-interpretation"
                elif v == "KEEP":
                    f["confidence"] = max(f.get("confidence", 0.5), 0.85)
                    f["verification"] = "confirmed-by-abstract-interpretation"

        return findings, summary

    # 内部 ─────────────────────────────────────────────

    def _scan_candidates(self, code: str) -> List[Dict[str, Any]]:
        """快速扫描 heap 操作候选点。"""
        candidates = []
        lines = code.splitlines()

        alloc_map: Dict[str, Dict[str, Any]] = {}

        for i, line in enumerate(lines):
            # 分配
            alloc_m = re.search(
                r'(\w[\w\d_]*)\s*=\s*(?:\([^)]*\*?\s*\))?\s*(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
                line,
            )
            if alloc_m:
                ptr = alloc_m.group(1)
                func = alloc_m.group(2)
                size_expr = alloc_m.group(3).strip().split(',')[0].strip()
                try:
                    req = int(size_expr)
                except ValueError:
                    req = 0
                eff = compute_effective_size(req) if req > 0 else 0
                alloc_map[ptr] = {
                    "ptr": ptr, "func": func, "requested": req,
                    "effective": eff, "line": i, "code": line.strip(),
                }

            write_m = re.search(
                r'(memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf|read|fread|recv)\s*\(([^)]+)\)',
                line,
            )
            if write_m:
                func = write_m.group(1)
                args = split_args(write_m.group(2))
                if len(args) >= 1:
                    dst = args[0].strip()
                    base = dst.split('[')[0].strip() if '[' in dst else dst
                    # 估算写入大小
                    ws = None
                    if func in ('memcpy', 'memmove', 'memset', 'strncpy',
                                'snprintf', 'read', 'fread', 'recv'):
                        if len(args) >= 3:
                            try:
                                ws = int(args[2].strip())
                            except ValueError:
                                pass
                    if base in alloc_map:
                        candidates.append({
                            **alloc_map[base],
                            "write_func": func,
                            "write_size": ws,
                            "write_line": i,
                            "write_code": line.strip(),
                        })

        return candidates

__all__ = ['VerifyResult', 'VerifySummary', 'HeapVerify']
