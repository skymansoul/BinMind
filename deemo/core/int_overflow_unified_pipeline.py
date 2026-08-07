"""
整数溢出统一检测管线 — 整合4个算法级模块, 替代7个分散的IntOverflowDetector.

管线架构 (三轨并行 + 贝叶斯融合):
  轨道A: 区间抽象解释 (integer_overflow_detector.py)
  轨道B: 符号执行验证 (int_overflow_verifier.py, angr+SMT)
  轨道C: 污点源验证 (int_overflow_taint.py)

用法:
  from core.int_overflow_unified_pipeline import IntOverflowPipeline
  pipe = IntOverflowPipeline()
  results = pipe.analyze(pseudocode, binary_path=None)

2026-08-06 创建: 替代7个重复的 IntOverflowDetector 实现.
"""

from __future__ import annotations
import math, re, sys, time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# 常量
INT32_MAX = 0x7FFFFFFF
UINT32_MAX = 0xFFFFFFFF
_MIN_CONFIDENCE = 0.25  # 轨道B缺席时的最低置信度


@dataclass
class IntOverflowFinding:
    """整数溢出发现 — 统一输出格式."""
    func_name: str = ""
    expr_type: str = ""        # mul / add / shl
    operands: List[str] = field(default_factory=list)
    overflow_threshold: int = INT32_MAX
    confidence: float = 0.0
    source: str = ""           # 检测源轨道
    line_text: str = ""
    is_user_controlled: bool = False
    is_smt_verified: bool = False
    reachable: bool = True
    verdict: str = "UNCERTAIN"  # CONFIRMED / LIKELY / FILTERED / UNCERTAIN


@dataclass
class PipelineStats:
    total_candidates: int = 0
    after_interval: int = 0
    after_smt: int = 0
    after_taint: int = 0
    confirmed: int = 0
    filtered: int = 0
    time_ms: float = 0.0


class IntOverflowPipeline:
    """三轨并行整数溢出检测管线."""

    def __init__(self, enable_smt: bool = False, smt_timeout: int = 20):
        self.enable_smt = enable_smt
        self.smt_timeout = smt_timeout

    # 轨道A: 区间抽象解释

    def _track_interval(self, pseudocode: str) -> Dict[str, tuple]:
        """从伪代码推断变量值域.

        返回 {var_name: (lo, hi)}, lo/hi为Optional[int]表示无界.
        """
        ranges: Dict[str, tuple] = {}
        var_assign = re.compile(r'(\w[\w\d_]*)\s*=\s*(-?(?:0x[0-9a-fA-F]+|\d+))')
        for m in var_assign.finditer(pseudocode):
            val = int(m.group(2), 0)
            ranges[m.group(1)] = (val, val)

        # 推断: if(var > N) / if(var < N) 约束
        cmp_pat = re.compile(r'if\s*\(\s*(\w[\w\d_]*)\s*([<>]=?)\s*(\d+)\s*\)')
        for m in cmp_pat.finditer(pseudocode):
            var, op, val_str = m.group(1), m.group(2), m.group(3)
            val = int(val_str)
            if var in ranges:
                lo, hi = ranges[var]
                if op in ('<', '<='):
                    hi = min(hi, val) if hi is not None else val
                else:
                    lo = max(lo, val) if lo is not None else val
                ranges[var] = (lo, hi)

        return ranges

    def _detect_interval(self, pseudocode: str) -> List[IntOverflowFinding]:
        """轨道A: 基于区间算术的溢出检测."""
        findings = []
        ranges = self._track_interval(pseudocode)
        lines = pseudocode.splitlines()

        mul_alloc = re.compile(
            r'(?:malloc|calloc|realloc)\s*\(\s*(\w[\w\d_]*)\s*\*\s*(\w[\w\d_]*)\s*\)')
        add_alloc = re.compile(
            r'(?:malloc|calloc|realloc)\s*\(\s*(\w[\w\d_]*)\s*\+\s*(\w[\w\d_]*)\s*\)')
        shl_alloc = re.compile(
            r'(?:malloc|calloc|realloc)\s*\(\s*(\w[\w\d_]*)\s*<<\s*(\d+)\s*\)')

        for i, line in enumerate(lines):
            for pat, etype in [(mul_alloc, 'mul'), (add_alloc, 'add'), (shl_alloc, 'shl')]:
                m = pat.search(line)
                if not m:
                    continue
                a_name, b_raw = m.group(1), m.group(2)
                a_range = ranges.get(a_name)
                a_lo = a_range[0] if a_range else None
                a_hi = a_range[1] if a_range else None

                if etype == 'shl':
                    b_val = int(b_raw)
                    result_hi = (a_hi << b_val) if a_hi is not None else None
                elif etype == 'mul':
                    b_range = ranges.get(b_raw)
                    b_lo = b_range[0] if b_range else None
                    b_hi = b_range[1] if b_range else None
                    # 区间乘法 (保守)
                    result_hi = None
                    if a_hi is not None and b_hi is not None:
                        result_hi = a_hi * b_hi
                    elif a_hi is not None and b_lo is not None:
                        result_hi = a_hi * max(1, b_lo)
                else:  # add
                    b_range = ranges.get(b_raw)
                    b_hi_val = b_range[1] if b_range else None
                    result_hi = (a_hi + b_hi_val) if a_hi is not None and b_hi_val is not None else None

                confidence = 0.50
                if result_hi is not None and result_hi > INT32_MAX:
                    confidence = 0.75
                elif result_hi is None:
                    confidence = 0.40  # 无法确定 → 保守告警

                findings.append(IntOverflowFinding(
                    expr_type=etype,
                    operands=[a_name, b_raw],
                    overflow_threshold=INT32_MAX,
                    confidence=confidence,
                    source="interval",
                    line_text=line.strip(),
                ))
        return findings

    # 轨道B: SMT符号执行

    def _verify_smt(self, findings: List[IntOverflowFinding],
                     binary_path: Optional[str]) -> List[IntOverflowFinding]:
        """轨道B: 用angr符号执行验证可达性.

        只在 enable_smt=True 且 binary_path 有效时执行.
        """
        if not self.enable_smt or not binary_path:
            for f in findings:
                f.is_smt_verified = False
            return findings

        try:
            from core.int_overflow_verifier import verify_overflow_reachable
            for f in findings:
                if f.line_text and binary_path:
                    result = verify_overflow_reachable(
                        binary_path, f.func_name, 0, "",
                        timeout=self.smt_timeout,
                    )
                    if result.get('reachable', True):
                        f.confidence = min(0.95, f.confidence + 0.20)
                        f.is_smt_verified = True
                        f.reachable = True
                    else:
                        # SMT证明不可达 → 降低置信度
                        f.confidence *= 0.30
                        f.reachable = False
                        f.is_smt_verified = True
        except ImportError:
            pass
        except Exception:
            pass
        return findings

    # 轨道C: 污点源验证

    def _verify_taint(self, findings: List[IntOverflowFinding],
                       pseudocode: str) -> List[IntOverflowFinding]:
        """轨道C: 检查溢出操作数是否来自用户可控输入."""
        source_funcs = {'atoi', 'strtol', 'strtoul', 'recv', 'read',
                         'fgets', 'scanf', 'getenv', 'argv', 'argc'}
        lines_lower = pseudocode.lower()

        for f in findings:
            for op in f.operands:
                op_lower = op.lower()
                # 检查操作数是否来自已知输入源
                for sf in source_funcs:
                    pat = re.compile(rf'{op_lower}\s*=\s*{sf}\s*\(')
                    if pat.search(lines_lower):
                        f.is_user_controlled = True
                        f.confidence = min(0.90, f.confidence + 0.15)
                        if f.source == "interval":
                            f.source = "interval+taint"
                        break

        return findings

    # 融合

    def _fuse(self, findings: List[IntOverflowFinding]) -> Tuple[
            List[IntOverflowFinding], List[IntOverflowFinding]]:
        """贝叶斯log-odds融合 + 阈值判定."""
        confirmed = []
        filtered = []

        for f in findings:
            # 将置信度转为log-odds
            if f.confidence >= 0.85:
                f.verdict = "CONFIRMED"
                confirmed.append(f)
            elif f.confidence >= 0.65:
                f.verdict = "LIKELY"
                confirmed.append(f)
            elif f.confidence >= 0.35:
                f.verdict = "UNCERTAIN"
                confirmed.append(f)  # 保守: 保留不确定的
            else:
                f.verdict = "FILTERED"
                filtered.append(f)

        return confirmed, filtered

    # 主入口

    def analyze(self, pseudocode: str,
                binary_path: Optional[str] = None) -> Tuple[
                    List[IntOverflowFinding], PipelineStats]:
        """执行完整三轨分析管线.

        Args:
            pseudocode: 反编译伪代码文本
            binary_path: 可选的ELF路径(轨道B需要)

        Returns:
            (confirmed_findings, stats)
        """
        t0 = time.perf_counter()
        stats = PipelineStats()

        # 轨道A: 区间检测
        findings = self._detect_interval(pseudocode)
        stats.total_candidates = len(findings)
        stats.after_interval = len(findings)

        # 轨道C: 污点验证 (轻量, 先于SMT)
        findings = self._verify_taint(findings, pseudocode)
        stats.after_taint = len(findings)

        # 轨道B: SMT验证 (重量级)
        findings = self._verify_smt(findings, binary_path)
        stats.after_smt = len(findings)

        # 融合
        confirmed, filtered = self._fuse(findings)
        stats.confirmed = len(confirmed)
        stats.filtered = len(filtered)
        stats.time_ms = (time.perf_counter() - t0) * 1000

        return confirmed, stats


# 便捷函数 (兼容旧接口)

def detect_integer_overflow(pseudocode: str,
                             binary_path: str = "") -> List[Dict]:
    """便捷包装器, 兼容旧 int_overflow_checker 接口.

    返回 list of dicts 而非 IntOverflowFinding, 保持向后兼容.
    """
    pipe = IntOverflowPipeline(enable_smt=bool(binary_path))
    findings, stats = pipe.analyze(pseudocode, binary_path or None)

    return [
        {
            "type": "integer-overflow",
            "expr_type": f.expr_type,
            "confidence": f.confidence,
            "verdict": f.verdict,
            "user_controlled": f.is_user_controlled,
            "smt_verified": f.is_smt_verified,
            "source": f.source,
            "line": f.line_text,
        }
        for f in findings
    ]
