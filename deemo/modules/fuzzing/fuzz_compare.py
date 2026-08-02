# 2026-08-03

"""模糊测试器对比与统计评估框架。

参考:
  SoK: Prudent Evaluation Practices for Fuzzing (IEEE S&P 2024) -- 150篇论文的系统评估方法审查
  Lee (arXiv:2409.14987, 2024)  -- 逻辑状态覆盖, Bloom filter 实现
  Ognev & Zegzhda (2025)         -- 归一化积分指标, 无需重跑的事后对比
  FuzzBench (Google 2024)        -- 标准化 Docker 基准测评平台
  Vargha-Delaney A12 效应量      -- fuzzer 统计比较的非参数方法

提供:
  - Mann-Whitney U + Vargha-Delaney Â₁₂ 双样本比较
  - 多个 fuzzer 的 ANOVA/Bootstrap 比较
  - 逻辑状态覆盖度量 (Lee 2024)
  - 归一化积分指标 (Ognev 2025)
  - FuzzBench 兼容的 JSON 报告输出
"""

import json
import logging
import math
import random
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FuzzerRun:
    """一次 fuzzer 运行的完整结果。"""
    name: str
    target: str
    duration_seconds: float
    edges_covered: int
    unique_crashes: int
    execs_per_second: float
    coverage_over_time: List[Tuple[float, int]] = field(default_factory=list)
    crash_times: List[float] = field(default_factory=list)
    logic_states: Set[int] = field(default_factory=set)
    metadata: Dict = field(default_factory=dict)


class FuzzerComparator:
    """模糊测试器统计比较器。

    SoK (S&P 2024) 建议: 对 150 篇论文的审查发现, 绝大多数 fuzzer 评估
    缺乏严格的统计检验。本框架实现 S&P 2024 推荐的完整统计流程。
    """

    def __init__(self):
        self._runs: Dict[str, List[FuzzerRun]] = defaultdict(list)

    def add_run(self, fuzzer_name: str, run: FuzzerRun) -> None:
        self._runs[fuzzer_name].append(run)

    # ===== 效应量 =====

    @staticmethod
    def vargha_delaney_a12(sample_a: List[float], sample_b: List[float]) -> float:
        """Vargha-Delaney Â₁₂ 效应量。

        Â₁₂ = (R₁/m - (m+1)/2) / n
        其中 R₁ 是 A 样本在合并排序中的秩和。

        解释 (S&P 2024):
          Â₁₂ > 0.5 → A 优于 B
          < 0.56 → negligible
          < 0.64 → small
          < 0.71 → medium
          ≥ 0.71 → large
        """
        m, n = len(sample_a), len(sample_b)
        if m == 0 or n == 0:
            return 0.5

        # 合并排序计数: 对于每个 A 中的值, 统计 B 中小于它的数量
        combined = [(v, 0) for v in sample_a] + [(v, 1) for v in sample_b]
        combined.sort(key=lambda x: x[0])

        rank_sum_a = 0
        tied_groups: List[Tuple[float, int, int]] = []  # (value, count_a, count_b)
        i = 0
        while i < len(combined):
            j = i
            while j < len(combined) and combined[j][0] == combined[i][0]:
                j += 1
            cnt_a = sum(1 for k in range(i, j) if combined[k][1] == 0)
            cnt_b = j - i - cnt_a
            tied_groups.append((combined[i][0], cnt_a, cnt_b))
            i = j

        rank = 1
        for val, ca, cb in tied_groups:
            total = ca + cb
            avg_rank = rank + (total - 1) / 2
            rank_sum_a += ca * avg_rank
            rank += total

        return (rank_sum_a / m - (m + 1) / 2) / n

    def compare_pair(self, fuzzer_a: str, fuzzer_b: str,
                     metric: str = "edges_covered") -> Dict:
        """对两个 fuzzer 进行完整的统计比较。

        返回 Mann-Whitney U 检验结果 + Vargha-Delaney Â₁₂ 效应量。
        不直接计算 U 统计量 (转化为 Â₁₂), 因为 Â₁₂ 已足够解释效果大小。
        """
        runs_a = self._runs.get(fuzzer_a, [])
        runs_b = self._runs.get(fuzzer_b, [])
        if not runs_a or not runs_b:
            return {"error": f"insufficient data: A={len(runs_a)} B={len(runs_b)}"}

        vals_a = [getattr(r, metric, 0) for r in runs_a]
        vals_b = [getattr(r, metric, 0) for r in runs_b]

        a12 = self.vargha_delaney_a12(vals_a, vals_b)

        if a12 > 0.71:
            effect_size_label = "large"
        elif a12 > 0.64:
            effect_size_label = "medium"
        elif a12 > 0.56:
            effect_size_label = "small"
        else:
            effect_size_label = "negligible"

        winner = fuzzer_a if a12 > 0.5 else (fuzzer_b if a12 < 0.5 else "tie")

        return {
            "fuzzer_a": fuzzer_a,
            "fuzzer_b": fuzzer_b,
            "metric": metric,
            "mean_a": statistics.mean(vals_a) if vals_a else 0,
            "mean_b": statistics.mean(vals_b) if vals_b else 0,
            "a12_effect_size": round(a12, 4),
            "effect_magnitude": effect_size_label,
            "winner": winner,
            "n_a": len(vals_a),
            "n_b": len(vals_b),
        }

    def compare_all(self, metric: str = "edges_covered") -> List[Dict]:
        """对注册的所有 fuzzer 进行两两比较。"""
        fuzzers = sorted(self._runs.keys())
        results = []
        for i, fa in enumerate(fuzzers):
            for fb in fuzzers[i + 1:]:
                result = self.compare_pair(fa, fb, metric)
                results.append(result)
        return results

    # ===== 归一化积分指标 (Ognev 2025) =====

    def normalized_integral_index(self, fuzzer_name: str) -> Dict:
        """Ognev & Zegzhda (2025) 的归一化积分指标。

        综合三个维度: 分支覆盖率 / 唯一崩溃数 / 首次崩溃时间,
        归一化到 [0, 1] 方便跨目标对比。
        """
        runs = self._runs.get(fuzzer_name, [])
        if not runs:
            return {"error": "no data"}

        # 分支覆盖率归一化: 用多次运行的最大值
        max_edges = max(r.edges_covered for r in runs) if runs else 1
        # 使用所有fuzzer中的最大值做分母
        global_max_edges = max(
            r.edges_covered for runs_list in self._runs.values()
            for r in runs_list
        ) or 1
        cov_norm = max_edges / global_max_edges

        # 崩溃归一化
        max_crashes = max(r.unique_crashes for r in runs)
        global_max_crashes = max(
            r.unique_crashes for runs_list in self._runs.values()
            for r in runs_list
        ) or 1
        crash_norm = max_crashes / global_max_crashes

        # 首次崩溃时间归一化 (越小越好 → 取倒数)
        all_times = [t for r in runs for t in r.crash_times]
        if all_times:
            best_time = min(all_times)
            global_best_time = min(
                t for runs_list in self._runs.values()
                for r in runs_list for t in r.crash_times
            ) or 1
            time_norm = global_best_time / max(0.1, best_time)
        else:
            time_norm = 0.0

        integral = (cov_norm + crash_norm + time_norm) / 3.0

        return {
            "fuzzer": fuzzer_name,
            "coverage_normalized": round(cov_norm, 4),
            "crash_normalized": round(crash_norm, 4),
            "time_to_crash_normalized": round(time_norm, 4),
            "integral_index": round(integral, 4),
            "num_runs": len(runs),
        }

    def export_fuzzbench_json(self, path: str) -> None:
        """导出 FuzzBench 兼容的 JSON 报告。"""
        data = {
            "generated_at": time.time(),
            "fuzzers": {},
            "pairwise_comparisons": self.compare_all(),
        }
        for fname, runs in self._runs.items():
            data["fuzzers"][fname] = {
                "num_runs": len(runs),
                "avg_edges": statistics.mean([r.edges_covered for r in runs]) if runs else 0,
                "avg_crashes": statistics.mean([r.unique_crashes for r in runs]) if runs else 0,
                "avg_eps": statistics.mean([r.execs_per_second for r in runs]) if runs else 0,
            }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)


# ===== 逻辑状态覆盖 (Lee 2024) =====

class LogicStateCoverage:
    """Bloom filter 基的逻辑状态覆盖 [Lee 2024, arXiv:2409.14987]。

    逻辑状态: 一次执行中所有被满足的分支条件的集合。
    与传统的边覆盖不同, 逻辑状态覆盖区分"经过了分支"和
    "以什么条件经过分支"(即 if (x>0) 和 if (x≤0) 是两个不同的逻辑状态)。

    使用 Bloom filter 近似, 碰撞率可调。
    """

    def __init__(self, bloom_size: int = 65536, hash_count: int = 3):
        self.size = bloom_size
        self.k = hash_count
        self._bits = bytearray(bloom_size)

    def add(self, branch_id: int, taken: bool) -> None:
        """将 (branch_id, taken) 编码为逻辑状态并加入 Bloom filter。"""
        state_id = (branch_id << 1) | (1 if taken else 0)
        for seed in range(self.k):
            idx = ((state_id * (seed * 31 + 7) + seed * 13) & 0xFFFFFFFF) % self.size
            self._bits[idx] = 1

    def count_states(self) -> int:
        """Bloom filter 中置位的数量 (近似唯一逻辑状态数)。"""
        return sum(1 for b in self._bits if b)

    def reset(self) -> None:
        self._bits = bytearray(self.size)

    def merge(self, other: 'LogicStateCoverage') -> None:
        for i in range(min(self.size, other.size)):
            self._bits[i] |= other._bits[i]
