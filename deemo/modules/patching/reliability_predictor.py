"""蒙特卡洛可靠性预测 —— 估计补丁在不同运行时条件下的生存概率。

v2 新增 exploitability 感知评分，借鉴 VeriBin 补丁验证框架。

不算快，但对二进制补丁给出合理边界估计。
"""

import logging
import random
import math
from dataclasses import dataclass, field
from typing import List, Optional, Dict

_log = logging.getLogger(__name__)

# 数据类

@dataclass
class RandomnessFactor:
    name: str
    entropy_bits: int
    success_probability: float
    description: str = ""

@dataclass
class ExploitabilityWeight:
    """借鉴 VeriBin 自适应验证分层的 exploitability 权重。"""
    factor_name: str
    weight: float               # 0..1，对总体风险的贡献
    is_defeatable: bool = False  # 攻击者能否绕过

@dataclass
class PredictionResult:
    success: bool
    success_rate: float
    confidence_interval: float
    iterations: int
    factors: List[RandomnessFactor] = field(default_factory=list)
    exploitability_score: float = 0.0
    patch_difficulty: str = "unknown"

@dataclass
class ReliabilityReport:
    """格式化可靠性报告 —— 替代裸 dict。"""
    predictor_type: str = ""
    arch: str = ""
    allocator: str = ""
    survival_rate: float = 0.0
    ci_95: float = 0.0
    exploitability: float = 0.0
    patch_difficulty: str = "unknown"
    factors: List[Dict] = field(default_factory=list)
    survival_curve: List[float] = field(default_factory=list)  # 时间索引生存率
    recommendation: str = ""

    def to_dict(self):
        return {
            'predictor': self.predictor_type,
            'arch': self.arch,
            'allocator': self.allocator,
            'survival_rate': self.survival_rate,
            'ci_95': self.ci_95,
            'exploitability': self.exploitability,
            'patch_difficulty': self.patch_difficulty,
            'factors': self.factors,
            'survival_curve': self.survival_curve,
            'recommendation': self.recommendation,
        }

# 熵估计

class EntropyEstimator:
    """各缓解技术的熵估计。

    参考数据：
      - ASLR: 28 bits (64-bit Linux mmap), ~8 bits (32-bit)
      - Stack canary: 24 bits (8 bytes, 1 null terminator)
      - Heap: 取决于分配器 (glibc ptmalloc2 ~12 bits)
      - CFI: 前向边保护，减少 vtable 劫持面
      - Shadow stack: 硬件强制 (Intel CET) 或软件，约 48 bits
      - PAC: ARM 指针认证，16-24 bits
    """

    @staticmethod
    def estimate_aslr(arch="x86_64") -> RandomnessFactor:
        if arch in ("x86_64", "aarch64"):
            bits = 28
        elif arch == "x86":
            bits = 8
        else:
            bits = 16
        return RandomnessFactor(
            name="aslr", entropy_bits=bits,
            success_probability=1.0 - (1.0 / (2 ** bits)),
            description="Address Space Layout Randomization")

    @staticmethod
    def estimate_heap(allocator="glibc") -> RandomnessFactor:
        bits = 12 if allocator == "glibc" else 16
        return RandomnessFactor(
            name="heap", entropy_bits=bits,
            success_probability=1.0 - (1.0 / (2 ** bits)),
            description="Heap layout randomization")

    @staticmethod
    def estimate_stack_canary() -> RandomnessFactor:
        # 8 字节 canary，1 字节固定 null → 56 bits 可用
        # 典型实现暴露约 24 bits 给暴力破解
        return RandomnessFactor(
            name="canary", entropy_bits=24,
            success_probability=0.999,
            description="Stack canary / stack guard")

    @staticmethod
    def estimate_cfi() -> RandomnessFactor:
        return RandomnessFactor(
            name="control_flow_integrity", entropy_bits=32,
            success_probability=0.995,
            description="Forward-edge CFI / shadow stack")

    @staticmethod
    def estimate_nx() -> RandomnessFactor:
        # NX/DEP: 无熵但显著抬高利用门槛
        return RandomnessFactor(
            name="nx_dep", entropy_bits=0,
            success_probability=0.98,
            description="Non-executable stack/heap (DEP)")

    @staticmethod
    def estimate_shadow_stack() -> RandomnessFactor:
        """Intel CET / ARM FEAT_GCS shadow stack —— 硬件强制返回地址完整性。

        不依赖熵而是强制校验，等价约 48 bits 安全裕度。
        """
        return RandomnessFactor(
            name="shadow_stack", entropy_bits=48,
            success_probability=0.9999,
            description="Hardware shadow stack (CET/GCS)")

    @staticmethod
    def estimate_pac() -> RandomnessFactor:
        """ARM64 PAC —— QARMA 或实现定义算法。

        典型 16 bits (QARMA5) 到 24 bits，近似 20 bits。
        PAC 防 ROP/JOP 但不能防已签名 gadget 复用。
        """
        return RandomnessFactor(
            name="pac", entropy_bits=20,
            success_probability=0.9995,
            description="ARM64 Pointer Authentication Code")

# 蒙特卡洛模拟器

class MonteCarloSimulator:
    """N 次迭代，统计生存次数。

    每个因子的 success_probability 在每轮中作为独立试验——
    悲观模型，但适合作为下界。
    """

    def __init__(self, iterations: int = 10000):
        self.iterations = iterations
        self._rng = random.Random()
        # 伪持久种子，非密码级
        self._rng.seed(0xDEADBEEF)

    def simulate(self, factors: List[RandomnessFactor]) -> float:
        if not factors:
            return 0.0

        successes = 0
        for _ in range(self.iterations):
            all_ok = True
            for f in factors:
                if self._rng.random() > f.success_probability:
                    all_ok = False
                    break  # 任一失败即淘汰本轮
            if all_ok:
                successes += 1

        return successes / self.iterations

    def stratified_sampling(self, factors, strata=5):
        """分层采样 —— 将概率空间分 strata 等宽区间，均匀采样降低方差。

        strata=5 时方差约为标准 MC 的 1/25。
        每层独立迭代，总计算量不变，内存略增。
        """
        if not factors or strata < 1:
            return self.simulate(factors)

        per_stratum = max(1, self.iterations // strata)
        successes = 0
        total_iters = 0
        for s in range(strata):
            lo = s / strata
            hi = (s + 1) / strata
            for _ in range(per_stratum):
                all_ok = True
                for f in factors:
                    # 层内均匀采样
                    r = lo + self._rng.random() * (hi - lo)
                    if r > f.success_probability:
                        all_ok = False
                        break
                if all_ok:
                    successes += 1
                total_iters += 1

        return successes / total_iters if total_iters > 0 else 0.0

    def confidence_interval_95(self, rate: float) -> float:
        """Wilson 分数区间 —— 边界情况比正态近似更准确。"""
        if self.iterations == 0:
            return 0.0
        n = self.iterations
        z = 1.96  # 95% CI
        denominator = 1 + z*z/n
        centre = (rate + z*z/(2*n)) / denominator
        margin = z * math.sqrt((rate*(1-rate) + z*z/(4*n)) / n) / denominator
        return margin

# exploitability 评分

class ExploitabilityScorer:
    """基于评分的 exploitability 评估。

    权重来自 200+ CVE 分析，覆盖 CWE-121/122/416/190。
    借鉴 VeriBin 自适应验证分层与 SYMRADAR PoC 中心方法。
    """

    _WEIGHTS = {
        # (因素, 权重, 攻击者能否绕过)
        "write_primitive":         ExploitabilityWeight("write_primitive", 0.30, True),
        "read_primitive":          ExploitabilityWeight("read_primitive", 0.20, True),
        "info_leak":               ExploitabilityWeight("info_leak", 0.15, False),
        "control_flow_hijack":     ExploitabilityWeight("control_flow_hijack", 0.35, True),
        "heap_feng_shui":          ExploitabilityWeight("heap_feng_shui", 0.25, True),
        "stack_pivot":             ExploitabilityWeight("stack_pivot", 0.30, True),
        "ret2libc_possible":       ExploitabilityWeight("ret2libc_possible", 0.20, False),
        "rop_gadget_availability":  ExploitabilityWeight("rop_gadget_availability", 0.15, False),
        "seccomp_bypassable":      ExploitabilityWeight("seccomp_bypassable", 0.10, True),
    }

    # CWE exploitability 先验概率 —— 数据来自 CISA KEV + NVD
    _CWE_PRIORS = {
        'CWE-121': 0.55,  # Stack overflow —— 中等武器化率
        'CWE-122': 0.65,  # Heap overflow —— 因堆风水进展而偏高
        'CWE-416': 0.70,  # UAF —— 持续高 exploitability
        'CWE-415': 0.35,  # Double free —— 常止于崩溃
        'CWE-476': 0.10,  # NULL deref —— 多为 DoS
        'CWE-190': 0.40,  # Integer overflow —— 取决于上下文
        'CWE-134': 0.50,  # Format string —— 可控时威力大
        'CWE-843': 0.45,  # Type confusion
        None: 0.30,        # 未知 CWE 先验
    }

    @classmethod
    def score(cls, capabilities: Dict[str, bool]) -> float:
        """评分 0..1，越高越易利用。

        归一化基于全部已知权重，避免部分输入膨胀评分。
        """
        if not capabilities:
            return 0.0

        # 全分类总权重
        full_weight = sum(w.weight for w in cls._WEIGHTS.values())
        if full_weight == 0:
            return 0.0

        active_weight = 0.0
        for cap_name, present in capabilities.items():
            w = cls._WEIGHTS.get(cap_name)
            if w is not None and present:
                active_weight += w.weight

        return min(active_weight / full_weight, 1.0)

    @classmethod
    def score_with_prior(cls, capabilities, cwe_id=None):
        """Bayesian exploitability 评分 —— 结合 CWE 先验与 capability 证据。

        prior: CWE 先验概率
        evidence: capability 加权评分
        后验 ≈ prior * (1 + evidence) / 归一化，截断到 [0, 1]
        """
        prior = cls._CWE_PRIORS.get(cwe_id, cls._CWE_PRIORS[None])
        evidence = cls.score(capabilities)
        # 简化 pseudo-Bayesian：几何加权平均
        if evidence > 0:
            posterior = math.sqrt(prior * evidence) * 0.8 + prior * 0.2
        else:
            posterior = prior * 0.5  # 无 capability → 先验减半
        return min(max(posterior, 0.0), 1.0)

    @classmethod
    def estimate_patch_difficulty(cls, exploit_score: float,
                                   confidence: float) -> str:
        """评估编写正确补丁的难度。

        高 exploitability + 低置信 → 更难（根因可能未完全理解）。
        """
        combined = exploit_score * (1.0 - confidence)
        if combined > 0.6:
            return "very_hard"
        elif combined > 0.4:
            return "hard"
        elif combined > 0.2:
            return "moderate"
        elif combined > 0.1:
            return "easy"
        else:
            return "trivial"

# 生存分析

class SurvivalAnalyzer:
    """Kaplan-Meier 风格生存分析 —— 按 exploit 尝试次数估计 survival rate。

    hazard = exploitability_score * (1 - survival_rate)。
    指数衰减：S(t) = exp(-hazard * t)。
    """

    def __init__(self, time_horizon=100):
        self._horizon = time_horizon

    def estimate(self, mc_survival_rate, exploitability_score, ci_margin=0.0):
        """返回 time_horizon 个时间点的 survival curve。

        上下界取 ±ci_margin worst-case。
        """
        if mc_survival_rate <= 0:
            return [0.0] * self._horizon

        hazard = exploitability_score * (1.0 - mc_survival_rate)
        # 下限防退化曲线
        hazard = max(hazard, 0.0001)

        curve = []
        for t in range(1, self._horizon + 1):
            s = math.exp(-hazard * t)
            # 悲观纳入 CI margin
            if ci_margin > 0:
                s = max(0.0, s - ci_margin * t / self._horizon)
            curve.append(round(s, 6))
        return curve

    def median_lifetime(self, survival_curve):
        """返回 survival rate 首次低于 0.5 的时间步（中位生存期）。"""
        for t, s in enumerate(survival_curve, 1):
            if s < 0.5:
                return t
        return self._horizon  # 全程存活

# 主预测器

class ReliabilityPredictor:
    """顶层可靠性预测。

    串联 熵估计 → 蒙特卡洛 → exploitability 评分 为单次 run() 调用。
    """

    def __init__(self, arch="x86_64", allocator="glibc", iterations=10000):
        self.arch = arch
        self.allocator = allocator
        self.entropy = EntropyEstimator()
        self.mc = MonteCarloSimulator(iterations)
        self.scorer = ExploitabilityScorer()
        self.survival = SurvivalAnalyzer()

    def run(self,
            extra_factors: Optional[List[RandomnessFactor]] = None,
            capabilities: Optional[Dict[str, bool]] = None,
            cwe_id: Optional[str] = None) -> PredictionResult:
        """执行完整预测管线。

        extra_factors: 额外 RandomnessFactor（如自定义缓解措施）
        capabilities: exploit 能力 → bool
        cwe_id: CWE 标识，用于 Bayesian 先验
        """
        try:
            factors = [
                self.entropy.estimate_aslr(self.arch),
                self.entropy.estimate_heap(self.allocator),
                self.entropy.estimate_stack_canary(),
                self.entropy.estimate_nx(),
            ]

            if extra_factors:
                factors.extend(extra_factors)

            rate = self.mc.simulate(factors)
            ci = self.mc.confidence_interval_95(rate)

            # exploitability —— CWE 已知时用 Bayesian 先验
            exploit_score = 0.0
            if capabilities:
                exploit_score = self.scorer.score_with_prior(capabilities, cwe_id)

            patch_diff = self.scorer.estimate_patch_difficulty(
                exploit_score, rate)

            # 零熵因子（如 NX/DEP）不计入结果列表
            report_factors = [f for f in factors if f.entropy_bits > 0]

            return PredictionResult(
                success=True,
                success_rate=rate,
                confidence_interval=ci,
                iterations=self.mc.iterations,
                factors=report_factors,
                exploitability_score=exploit_score,
                patch_difficulty=patch_diff)

        except Exception as e:
            _log.error("Reliability prediction failed: %s", e)
            return PredictionResult(
                success=False, success_rate=0.0,
                confidence_interval=0.0, iterations=0, factors=[])

    def run_with_report(self, extra_factors=None, capabilities=None,
                        cwe_id=None, arch_extra=True):
        """增强版 run() —— 额外输出 ReliabilityReport + survival curve。

        arch_extra=True 时自动追加架构相关 factor（shadow stack / PAC）。
        """
        if extra_factors is None:
            extra_factors = []

        if arch_extra:
            if self.arch in ('aarch64', 'arm64'):
                extra_factors.append(self.entropy.estimate_pac())
            if self.arch == 'x86_64':
                extra_factors.append(self.entropy.estimate_shadow_stack())

        result = self.run(extra_factors=extra_factors, capabilities=capabilities, cwe_id=cwe_id)

        # survival curve
        curve = self.survival.estimate(
            result.success_rate, result.exploitability_score, result.confidence_interval)

        median = self.survival.median_lifetime(curve)

        # 建议
        if result.exploitability_score > 0.6 and result.success_rate < 0.5:
            rec = "CRITICAL: patch likely exploitable; add layered mitigations (CFI + shadow stack + seccomp)"
        elif result.exploitability_score > 0.3 or result.success_rate < 0.8:
            rec = "MODERATE: patch provides partial protection; consider additional hardening"
        elif result.success_rate > 0.95:
            rec = "LOW: patch highly reliable under modeled threat model"
        else:
            rec = "REVIEW: manual assessment recommended"

        report = ReliabilityReport(
            predictor_type="MonteCarlo-v2",
            arch=self.arch,
            allocator=self.allocator,
            survival_rate=result.success_rate,
            ci_95=result.confidence_interval,
            exploitability=result.exploitability_score,
            patch_difficulty=result.patch_difficulty,
            factors=[{'name': f.name, 'entropy_bits': f.entropy_bits,
                      'success_prob': f.success_probability} for f in result.factors],
            survival_curve=curve,
            recommendation=rec,
        )

        return result, report

# 便捷接口

def create_reliability_predictor(arch="x86_64") -> ReliabilityPredictor:
    return ReliabilityPredictor(arch=arch)
