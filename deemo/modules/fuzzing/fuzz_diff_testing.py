"""差分模糊测试框架 -- 比较多个目标实现的输出一致性。

参考:
  Differential Fuzzing (general)  -- 跨实现的一致性 oracle
  NEZHA (IEEE S&P 2020)          -- 语义差异检测 + δ多样性指标
  FuzzDiff (USENIX 2024)         -- 二进制补丁前后覆盖率差分分析

在两个版本的二进制上并发执行相同的种子, 对比:
  1. 覆盖率差异 -- 哪个版本的哪个函数被更多/更少地覆盖
  2. 行为差异 -- 输出/退出码/信号的不一致
  3. 性能差异 -- 执行时间的显著偏差 (可能暗示回归)

输入输出差异是最强的 oracle: 两个版本对同一输入产生不同结果,
要么是 bug 修复, 要么是 regression。
"""

import hashlib
import json
import logging
import math
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple
from collections import OrderedDict

logger = logging.getLogger(__name__)


class DiffCategory(str, Enum):
    # 差异分类。
    COVERAGE_GAINED = "coverage_gained"       # V2覆盖更多
    COVERAGE_LOST = "coverage_lost"           # V2覆盖更少(回归)
    OUTPUT_MISMATCH = "output_mismatch"       # 输出不同
    EXIT_CODE_MISMATCH = "exit_code_mismatch"  # 退出码不同
    SIGNAL_MISMATCH = "signal_mismatch"       # 信号不同
    PERF_REGRESSION = "perf_regression"       # 执行时间显著增加
    CRASH_INTRODUCED = "crash_introduced"     # V2引入新的崩溃
    CRASH_FIXED = "crash_fixed"               # V1崩溃但V2不崩溃


@dataclass
class DiffResult:
    """单个种子的差分结果。"""
    seed_hash: str
    seed_data: bytes
    category: DiffCategory
    v1_exit_code: int = 0
    v2_exit_code: int = 0
    v1_signal: int = 0
    v2_signal: int = 0
    v1_stdout: bytes = b""
    v2_stdout: bytes = b""
    v1_stderr: bytes = b""
    v2_stderr: bytes = b""
    v1_edges: Set[int] = field(default_factory=set)
    v2_edges: Set[int] = field(default_factory=set)
    v1_exec_time_ms: float = 0.0
    v2_exec_time_ms: float = 0.0
    v1_cov_metric: float = 0.0
    v2_cov_metric: float = 0.0
    # 附加信息
    severity: str = "info"   # info / warning / critical
    description: str = ""
    signature: str = ""      # 差异指纹, 用于去重


class DiffFuzzer:
    """差分模糊测试引擎。

    对两个版本的二进制执行相同的种子集合, 记录所有差异,
    按类别分组输出报告。
    """

    def __init__(self, v1_executor: Callable[[bytes], Tuple[int, int, bytes, bytes, Set[int], float]],
                 v2_executor: Callable[[bytes], Tuple[int, int, bytes, bytes, Set[int], float]],
                 perf_regression_factor: float = 3.0):
        """
        v1_executor, v2_executor:
          签名: (seed: bytes) -> (
            exit_code: int,
            signal_num: int,
            stdout: bytes,
            stderr: bytes,
            covered_edges: Set[int],
            exec_time_ms: float,
          )

        perf_regression_factor: V2执行时间是V1的N倍以上时报告为回归。
        """
        self.v1_exec = v1_executor
        self.v2_exec = v2_executor
        self.perf_factor = perf_regression_factor
        self._results: List[DiffResult] = []
        self._diff_counts: Dict[DiffCategory, int] = defaultdict(int)

    def run(self, seeds: List[bytes],
            max_seeds: int = 5000) -> List[DiffResult]:
        """在所有种子上执行差分分析。

        返回差异列表, 按 severity 降序排列。
        """
        self._results.clear()
        self._diff_counts.clear()

        for i, seed in enumerate(seeds[:max_seeds]):
            try:
                v1_result = self.v1_exec(seed)
                v2_result = self.v2_exec(seed)
            except Exception as ex:
                logger.debug("种子%d执行异常: %s", i, ex)
                continue

            diff = self._compare(seed, v1_result, v2_result)
            if diff is not None:
                self._results.append(diff)
                self._diff_counts[diff.category] += 1

        self._results.sort(
            key=lambda d: (
                {"critical": 0, "warning": 1, "info": 2}[d.severity],
                d.category.value
            )
        )
        return self._results

    def _compare(self, seed: bytes,
                 v1: Tuple, v2: Tuple) -> Optional[DiffResult]:
        """比较两个版本对同一输入的执行结果。"""
        v1_ec, v1_sig, v1_out, v1_err, v1_edges, v1_time = v1
        v2_ec, v2_sig, v2_out, v2_err, v2_edges, v2_time = v2

        seed_hash = hashlib.sha256(seed).hexdigest()[:16]

        # 优先级 1: 崩溃引入 (最严重)
        if v1_sig == 0 and v2_sig != 0:
            return DiffResult(
                seed_hash=seed_hash, seed_data=seed,
                category=DiffCategory.CRASH_INTRODUCED,
                v1_exit_code=v1_ec, v2_exit_code=v2_ec,
                v1_signal=v1_sig, v2_signal=v2_sig,
                v1_stdout=v1_out, v2_stdout=v2_out,
                v1_stderr=v1_err, v2_stderr=v2_err,
                v1_edges=v1_edges, v2_edges=v2_edges,
                v1_exec_time_ms=v1_time, v2_exec_time_ms=v2_time,
                severity="critical",
                description=f"V2崩溃: signal={v2_sig}, V1正常退出",
                signature=hashlib.sha256(
                    f"crash_intro:{v2_sig}:{seed_hash}".encode()
                ).hexdigest()[:16],
            )

        # 优先级 2: 崩溃消失 (值得关注但不一定是bug)
        if v1_sig != 0 and v2_sig == 0:
            return DiffResult(
                seed_hash=seed_hash, seed_data=seed,
                category=DiffCategory.CRASH_FIXED,
                v1_exit_code=v1_ec, v2_exit_code=v2_ec,
                v1_signal=v1_sig, v2_signal=v2_sig,
                v1_stdout=v1_out, v2_stdout=v2_out,
                v1_stderr=v1_err, v2_stderr=v2_err,
                v1_edges=v1_edges, v2_edges=v2_edges,
                v1_exec_time_ms=v1_time, v2_exec_time_ms=v2_time,
                severity="warning",
                description=f"V1崩溃已修复: signal={v1_sig}",
                signature=hashlib.sha256(
                    f"crash_fixed:{v1_sig}:{seed_hash}".encode()
                ).hexdigest()[:16],
            )

        # 优先级 3: 不同信号
        if v1_sig != 0 and v2_sig != 0 and v1_sig != v2_sig:
            return DiffResult(
                seed_hash=seed_hash, seed_data=seed,
                category=DiffCategory.SIGNAL_MISMATCH,
                v1_exit_code=v1_ec, v2_exit_code=v2_ec,
                v1_signal=v1_sig, v2_signal=v2_sig,
                v1_stdout=v1_out, v2_stdout=v2_out,
                v1_stderr=v1_err, v2_stderr=v2_err,
                v1_edges=v1_edges, v2_edges=v2_edges,
                v1_exec_time_ms=v1_time, v2_exec_time_ms=v2_time,
                severity="warning",
                description=f"信号不一致: V1={v1_sig} V2={v2_sig}",
                signature=hashlib.sha256(
                    f"sig_mismatch:{v1_sig}:{v2_sig}:{seed_hash}".encode()
                ).hexdigest()[:16],
            )

        # 优先级 4: 输出不一致
        if v1_out != v2_out or v1_err != v2_err:
            return DiffResult(
                seed_hash=seed_hash, seed_data=seed,
                category=DiffCategory.OUTPUT_MISMATCH,
                v1_exit_code=v1_ec, v2_exit_code=v2_ec,
                v1_signal=v1_sig, v2_signal=v2_sig,
                v1_stdout=v1_out, v2_stdout=v2_out,
                v1_stderr=v1_err, v2_stderr=v2_err,
                v1_edges=v1_edges, v2_edges=v2_edges,
                v1_exec_time_ms=v1_time, v2_exec_time_ms=v2_time,
                severity="warning",
                description="标准输出/错误输出不一致",
                signature=hashlib.sha256(
                    (hashlib.sha256(v1_out).hexdigest()[:8] +
                     hashlib.sha256(v2_out).hexdigest()[:8]).encode()
                ).hexdigest()[:16],
            )

        # 优先级 5: 退出码不一致
        if v1_ec != v2_ec:
            return DiffResult(
                seed_hash=seed_hash, seed_data=seed,
                category=DiffCategory.EXIT_CODE_MISMATCH,
                v1_exit_code=v1_ec, v2_exit_code=v2_ec,
                v1_signal=v1_sig, v2_signal=v2_sig,
                v1_stdout=v1_out, v2_stdout=v2_out,
                v1_stderr=v1_err, v2_stderr=v2_err,
                v1_edges=v1_edges, v2_edges=v2_edges,
                v1_exec_time_ms=v1_time, v2_exec_time_ms=v2_time,
                severity="info",
                description=f"退出码不同: V1={v1_ec} V2={v2_ec}",
                signature=hashlib.sha256(
                    f"ec:{v1_ec}:{v2_ec}:{seed_hash}".encode()
                ).hexdigest()[:16],
            )

        # 优先级 6: 性能回归
        if v1_time > 0 and v2_time > v1_time * self.perf_factor:
            return DiffResult(
                seed_hash=seed_hash, seed_data=seed,
                category=DiffCategory.PERF_REGRESSION,
                v1_exit_code=v1_ec, v2_exit_code=v2_ec,
                v1_signal=v1_sig, v2_signal=v2_sig,
                v1_stdout=v1_out, v2_stdout=v2_out,
                v1_stderr=v1_err, v2_stderr=v2_err,
                v1_edges=v1_edges, v2_edges=v2_edges,
                v1_exec_time_ms=v1_time, v2_exec_time_ms=v2_time,
                severity="info",
                description=f"性能回归: V1={v1_time:.1f}ms V2={v2_time:.1f}ms",
                signature=hashlib.sha256(
                    f"perf:{v1_time:.0f}:{v2_time:.0f}:{seed_hash}".encode()
                ).hexdigest()[:16],
            )

        # 优先级 7: 覆盖率差异
        gained = v2_edges - v1_edges
        lost = v1_edges - v2_edges

        if gained and not lost:
            return DiffResult(
                seed_hash=seed_hash, seed_data=seed,
                category=DiffCategory.COVERAGE_GAINED,
                v1_exit_code=v1_ec, v2_exit_code=v2_ec,
                v1_signal=v1_sig, v2_signal=v2_sig,
                v1_stdout=v1_out, v2_stdout=v2_out,
                v1_stderr=v1_err, v2_stderr=v2_err,
                v1_edges=v1_edges, v2_edges=v2_edges,
                v1_exec_time_ms=v1_time, v2_exec_time_ms=v2_time,
                severity="info",
                description=f"V2新增覆盖: {len(gained)}条边",
                signature=hashlib.sha256(
                    f"cov_gain:{len(gained)}:{seed_hash}".encode()
                ).hexdigest()[:16],
            )

        if lost:
            return DiffResult(
                seed_hash=seed_hash, seed_data=seed,
                category=DiffCategory.COVERAGE_LOST,
                v1_exit_code=v1_ec, v2_exit_code=v2_ec,
                v1_signal=v1_sig, v2_signal=v2_sig,
                v1_stdout=v1_out, v2_stdout=v2_out,
                v1_stderr=v1_err, v2_stderr=v2_err,
                v1_edges=v1_edges, v2_edges=v2_edges,
                v1_exec_time_ms=v1_time, v2_exec_time_ms=v2_time,
                severity="warning",
                description=f"V2丢失覆盖: {len(lost)}条边",
                signature=hashlib.sha256(
                    f"cov_lost:{len(lost)}:{seed_hash}".encode()
                ).hexdigest()[:16],
            )

        # 无差异
        return None

    def summary(self) -> Dict:
        total_diffs = len(self._results)
        return {
            "total_seeds_tested": 0,  # FIXME: 应从外部传入种子总数
            "differences_found": total_diffs,
            "by_category": dict(self._diff_counts),
            "critical": [
                {
                    "signature": d.signature,
                    "description": d.description,
                    "seed_hash": d.seed_hash,
                }
                for d in self._results if d.severity == "critical"
            ][:20],
            "warnings": [
                {
                    "signature": d.signature,
                    "description": d.description,
                    "seed_hash": d.seed_hash,
                }
                for d in self._results if d.severity == "warning"
            ][:50],
        }

    def export_json(self, path: str) -> None:
        """导出全部差异为 JSON。"""
        data = {
            "summary": self.summary(),
            "diffs": [
                {
                    "category": d.category.value,
                    "severity": d.severity,
                    "description": d.description,
                    "signature": d.signature,
                    "seed_hash": d.seed_hash,
                    "v1_exit_code": d.v1_exit_code,
                    "v2_exit_code": d.v2_exit_code,
                    "v1_signal": d.v1_signal,
                    "v2_signal": d.v2_signal,
                    "v1_exec_ms": d.v1_exec_time_ms,
                    "v2_exec_ms": d.v2_exec_time_ms,
                    "v1_edge_count": len(d.v1_edges),
                    "v2_edge_count": len(d.v2_edges),
                }
                for d in self._results
            ],
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def diff_test_binaries(
    v1_exec: Callable,
    v2_exec: Callable,
    seeds: List[bytes],
    output_json: Optional[str] = None,
) -> Dict:
    """模块级便捷入口: 对两个版本的二进制执行差分测试。"""
    fuzzer = DiffFuzzer(v1_exec, v2_exec)
    fuzzer.run(seeds)
    summary = fuzzer.summary()
    if output_json:
        fuzzer.export_json(output_json)
    return summary
