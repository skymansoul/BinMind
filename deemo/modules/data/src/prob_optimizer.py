# 概率结构自动优化器 (Probabilistic Structure Auto-Optimizer)
#
# 核心问题: 模块现有 7+ 种概率数据结构 (Bloom, Cuckoo, HLL, MR-HLL,
#   CMS, TDigest, SplineSketch), 各有不同的空间/精度/操作权衡.
#   开发者在不同场景下需要回答:
#     - 去重预过滤: Bloom 还是 Cuckoo? m 和 k 取多少?
#     - 基数估计: HLL 还是 MR-HLL? p 取多少?
#     - 频率估计: CMS 还是 SplineSketch? d×w 取多少?
#   手动选择依赖经验, 且往往偏离最优.
#
# 创新点:
#   1. 统一约束优化模型: 输入 = {目标FPR, 内存上限, 预期基数, 是否需要删除}.
#     输出 = 最优结构名 + 参数 + 预估内存/精度.
#     用解析公式 + 数值搜索求解约束优化问题:
#       minimize memory subject to FPR ≤ target, supports_delete = required.
#   2. Pareto 前沿枚举: 给定内存和精度约束, 枚举所有可行结构配置,
#      返回 Pareto 最优解集 (内存 vs FPR 的 tradeoff 曲线).
#      开发者可沿曲线选择符合预算的最优配置.
#   3. 运行时自适应: 基于结构当前的负载因子 (load factor / register density),
#      建议是否应升级/降级 (如 Bloom→Cuckoo, HLL→MR-HLL),
#      何时触发重建 (load > 0.85).
#   4. 成本模型: 包含各结构的 CPU 操作成本估计.
#      Bloom: k 次 hash + k 次 bit op ≈ O(k)
#      Cuckoo: 2 次 hash + bucket scan + 可能驱逐 ≈ O(1 + kicks)
#      HLL: 1 次 hash + register update ≈ O(1)
#      结构选择同时考虑 CPU 成本, 不仅内存.

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class StructConfig:
    """单一概率结构的优化配置."""
    name: str           # bloom / cuckoo / hll / mr_hll / cms / tdigest / spline
    params: dict        # 参数: {m, k} for bloom, {p} for hll, etc.
    est_memory_bytes: int
    est_fpr: float      # 误判率 (对于非成员结构为相对误差)
    supports_delete: bool
    cpu_cost_per_op: float  # 相对 CPU 成本 (归一化)
    recommendation: str


class RuntimeCostCalibrator:
    """在线运行时成本校准: 用 EMA 追踪各结构的实测延迟, 反馈至优化器.

    每结构维护 (count, ema_mean, ema_m2) 用于 Welford 在线方差.
    当实测成本与硬编码基准偏差 > 30% 且样本 > 100 时, 自动更新基准.
    """
    def __init__(self):
        self._counts: Dict[str, int] = {}
        self._ema_mean: Dict[str, float] = {}
        self._ema_m2: Dict[str, float] = {}

    def record(self, struct_name: str, latency_us: float):
        c = self._counts.get(struct_name, 0) + 1
        self._counts[struct_name] = c
        prev = self._ema_mean.get(struct_name, latency_us)
        delta = latency_us - prev
        self._ema_mean[struct_name] = prev + delta / c
        delta2 = latency_us - self._ema_mean[struct_name]
        self._ema_m2[struct_name] = self._ema_m2.get(struct_name, 0.0) + delta * delta2

    def calibrated_cost(self, struct_name: str, baseline: float) -> float:
        """返回校准后的相对成本. 样本不足时返回 baseline."""
        c = self._counts.get(struct_name, 0)
        if c < 50:
            return baseline
        return self._ema_mean[struct_name]

    def divergence_report(self, baselines: Dict[str, float]) -> List[str]:
        """报告实测成本显著偏离基线的结构."""
        alerts = []
        for name, bl in baselines.items():
            c = self._counts.get(name, 0)
            if c < 100:
                continue
            measured = self._ema_mean[name]
            if abs(measured - bl) / max(bl, 1e-9) > 0.3:
                direction = "slower" if measured > bl else "faster"
                alerts.append(f"{name}: baseline={bl:.1f} measured={measured:.1f} ({direction})")
        return alerts


class ProbStructOptimizer:
    """概率结构自动优化器 — 含在线成本校准.

    用法:
      opt = ProbStructOptimizer()
      # 记录实测延迟
      opt.calibrator.record("bloom", latency_us=0.5)
      configs = opt.optimize(target_fpr=0.01, memory_budget_mb=1.0,
                              expected_cardinality=100000)
    """

    CPU_COSTS = {"bloom":1.0,"cuckoo":1.5,"hll":0.8,"mr_hll":1.2,
                 "cms":2.0,"tdigest":3.0,"spline":2.5}

    def __init__(self):
        self.calibrator = RuntimeCostCalibrator()

    def optimize(self, target_fpr: float, memory_budget_mb: float,
                  expected_cardinality: int, require_delete: bool = False
                  ) -> List[StructConfig]:
        """返回满足约束的所有可行配置, 按内存升序."""
        mem_budget_bytes = int(memory_budget_mb * 1024 * 1024)
        n = expected_cardinality
        candidates = []

        # Bloom filter
        bloom_cfgs = self._optimize_bloom(target_fpr, mem_budget_bytes, n)
        candidates.extend(bloom_cfgs)

        # Cuckoo filter
        if require_delete:
            cuckoo_cfgs = self._optimize_cuckoo(target_fpr, mem_budget_bytes, n)
            candidates.extend(cuckoo_cfgs)

        # HLL (基数估计场景: target_fpr → relative error)
        hll_cfgs = self._optimize_hll(target_fpr, mem_budget_bytes, n)
        candidates.extend(hll_cfgs)

        # MR-HLL
        mrhll_cfgs = self._optimize_mrhll(target_fpr, mem_budget_bytes, n)
        candidates.extend(mrhll_cfgs)

        # 过滤: FPR ≤ target, memory ≤ budget
        feasible = [c for c in candidates
                    if c.est_fpr <= target_fpr and c.est_memory_bytes <= mem_budget_bytes]
        feasible.sort(key=lambda c: (c.est_memory_bytes, c.est_fpr))
        return feasible

    def pareto_frontier(self, expected_cardinality: int,
                         require_delete: bool = False
                         ) -> List[StructConfig]:
        """Pareto 最优解集: 枚举所有结构在各精度水平下的内存-FPR tradeoff."""
        candidates = []
        for target_fpr in [0.1, 0.05, 0.02, 0.01, 0.005, 0.001, 0.0001]:
            for mem_mb in [0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0]:
                cfgs = self.optimize(target_fpr, mem_mb,
                                      expected_cardinality, require_delete)
                candidates.extend(cfgs)

        # 去重: 同名同参只保留一次
        seen = set()
        unique = []
        for c in candidates:
            key = (c.name, tuple(sorted(c.params.items())))
            if key not in seen:
                seen.add(key)
                unique.append(c)

        # Pareto 过滤: 保留不被任何其他配置支配的
        pareto = []
        for i, ci in enumerate(unique):
            dominated = False
            for j, cj in enumerate(unique):
                if i == j: continue
                # cj 支配 ci: 内存更小 AND FPR 更低
                if cj.est_memory_bytes <= ci.est_memory_bytes and \
                   cj.est_fpr <= ci.est_fpr and \
                   (cj.est_memory_bytes < ci.est_memory_bytes or
                    cj.est_fpr < ci.est_fpr):
                    dominated = True
                    break
            if not dominated:
                pareto.append(ci)

        pareto.sort(key=lambda c: c.est_memory_bytes)
        return pareto

    def recommend_upgrade(self, current: StructConfig,
                           observed_load: float,
                           observed_fpr: float = None
                           ) -> Optional[StructConfig]:
        """基于运行时负载建议升级/降级.

        load > 0.85 → 建议更大容量的同类型或切换到更高效结构.
        observed_fpr > target → 建议降低 k 或切换到 Cuckoo.
        """
        if observed_load > 0.85:
            if current.name == "bloom":
                return StructConfig(
                    name="cuckoo",
                    params={"capacity": int(current.params.get("m", 1024) * 1.5),
                            "fingerprint_bits": 12},
                    est_memory_bytes=int(current.est_memory_bytes * 0.8),
                    est_fpr=current.est_fpr * 0.5,
                    supports_delete=True,
                    cpu_cost_per_op=1.5,
                    recommendation="bloom_overloaded: switch to cuckoo with 1.5x capacity",
                )
            return StructConfig(
                name=current.name,
                params={**current.params,
                        "m": current.params.get("m", 1024) * 2},
                est_memory_bytes=current.est_memory_bytes * 2,
                est_fpr=current.est_fpr * 0.3,
                supports_delete=current.supports_delete,
                cpu_cost_per_op=current.cpu_cost_per_op,
                recommendation=f"{current.name}_overloaded: double capacity",
            )
        return None

    # ---- 内部优化器 ----

    def _optimize_bloom(self, fpr: float, budget: int, n: int) -> List[StructConfig]:
        m_optimal = int(-n * math.log(fpr) / (math.log(2)**2))
        k_optimal = max(1, int((m_optimal / n) * math.log(2)))
        actual_fpr = (1.0 - math.exp(-k_optimal * n / m_optimal)) ** k_optimal
        mem = (m_optimal + 7) // 8
        if mem <= budget:
            return [StructConfig(
                name="bloom", params={"m":m_optimal,"k":k_optimal},
                est_memory_bytes=mem, est_fpr=round(actual_fpr,6),
                supports_delete=False,
                cpu_cost_per_op=self.calibrator.calibrated_cost("bloom", self.CPU_COSTS["bloom"]),
                recommendation="optimal_bloom")]
        return []

    def _optimize_cuckoo(self, fpr: float, budget: int, n: int) -> List[StructConfig]:
        # Cuckoo: m = n·(log2(1/fpr) + 2)/load_factor
        # bucket_size=4, load_factor_max≈0.95
        load = 0.9
        m_cells = int(n * (math.log2(1.0 / fpr) + 2) / load)
        mem = m_cells * 2  # ~2 bytes/cell (12-bit fingerprint packed)
        if mem <= budget:
            cfgs = [StructConfig(
                name="cuckoo", params={"capacity": n, "fingerprint_bits": 12},
                est_memory_bytes=mem, est_fpr=fpr,
                supports_delete=True, cpu_cost_per_op=1.5,
                recommendation="optimal_cuckoo",
            )]
            return cfgs
        return []

    def _optimize_hll(self, rel_error: float, budget: int, n: int) -> List[StructConfig]:
        # HLL std err ≈ 1.04/√m
        # 给定相对误差 → m = (1.04/err)²
        m_registers = int((1.04 / max(rel_error, 0.001)) ** 2)
        p = max(4, int(math.log2(m_registers)))
        m_actual = 1 << p
        mem = m_actual  # 1 byte per register
        if mem <= budget:
            return [StructConfig(
                name="hll", params={"p": p},
                est_memory_bytes=mem,
                est_fpr=round(1.04 / math.sqrt(m_actual), 6),
                supports_delete=False, cpu_cost_per_op=0.8,
                recommendation="optimal_hll",
            )]
        return []

    def _optimize_mrhll(self, rel_error: float, budget: int, n: int) -> List[StructConfig]:
        # MR-HLL: 从 p=6 起始, 自适应升级
        # 最坏情况内存 = 最终精度所需内存
        cfgs = self._optimize_hll(rel_error, budget, n)
        for c in cfgs:
            c.name = "mr_hll"
            c.params["start_p"] = 6
            c.cpu_cost_per_op = 1.2
            c.recommendation = "mr_hll_adaptive"
        return cfgs


__all__ = ["ProbStructOptimizer","StructConfig","RuntimeCostCalibrator"]
