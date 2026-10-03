# 环境漂移检测器（runtime 指纹变化检测）
# λ 衰减常数改为补丁复杂度+攻击面联合估计

"""Temporal Patch Reliability — 补丁可靠性时间衰减。

现有 reliability_predictor 仅做 Monte Carlo 静态估计，不随时间更新。
本模块补充时间维度：模拟补丁在 runtime 环境演进下的可靠性衰减，
提供 time-to-refresh 和 unsafe 临界点预测。

// ref: "Patch Longevity Study"
//   首次系统性论证 patch 性能随时间指数衰减。
//   本模块移植到 binary patch 领域：防御效力随 runtime
//   环境漂移（libc/kernel/编译器版本变更）而衰减。
//   核心差异：binary patch 衰减源于 ABI 不兼容 + 新 gadget
//   出现 + 防御机制适应。
//
// ref: Concept Drift
//   drift analysis + time-aware classifier 启发
//   环境漂移检测器设计：定期采样 runtime 指纹，CUSUM 检测漂移点。
//
// 衰减公式:
//   R(t) = R₀ · exp(-λ · t) · d(env_t, env_0)
//   其中:
//     R₀ = Monte Carlo 初始可靠性估计
//     λ  = 衰减常数（补丁复杂度 × 攻击面大小）
//     t  = 补丁应用以来的天数
//     d() = 环境相似度 (0..1)，环境不变时 = 1
//
// TODO：待适配 ARM — 当前 x86_64 ELF 指纹检测最完整
"""

import os
import re
import math
import time
import hashlib
import logging
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

__log = logging.getLogger(__name__)


class RefreshUrgency(Enum):
    STABLE = "stable"               # R(t) ≥ 0.90 R₀
    MONITOR = "monitor"             # 0.70 ≤ R(t) < 0.90
    SCHEDULE_REFRESH = "schedule"   # 0.40 ≤ R(t) < 0.70
    CRITICAL = "critical"           # R(t) < 0.40


@dataclass
class EnvironmentFingerprint:
    """运行时环境指纹 — 漂移检测快照。"""
    libc_version: str = ""
    libc_hash: str = ""
    kernel_version: str = ""
    ld_path: str = ""
    compiler_version: str = ""
    binary_section_hashes: Dict[str, str] = field(default_factory=dict)
    aslr_entropy_bits: int = 0
    nx_enabled: bool = True
    relro: str = ""     # "full" / "partial" / "none"
    sampled_at: float = 0.0

    def to_hash(self) -> str:
        raw = f"{self.libc_version}|{self.kernel_version}|{self.compiler_version}|{self.ld_path}|{self.relro}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def distance(self, other: 'EnvironmentFingerprint') -> float:
        """环境指纹距离 — 0~1，0 = 完全相同。"""
        score = 0.0
        if self.libc_version != other.libc_version:
            score += 0.25
        if self.kernel_version != other.kernel_version:
            score += 0.20
        if self.ld_path != other.ld_path:
            score += 0.15
        if self.compiler_version != other.compiler_version:
            score += 0.10
        if self.relro != other.relro:
            score += 0.15
        if self.nx_enabled != other.nx_enabled:
            score += 0.10
        if self.aslr_entropy_bits != other.aslr_entropy_bits:
            score += 0.05 * abs(self.aslr_entropy_bits - other.aslr_entropy_bits) / 28.0
        return min(score, 1.0)


@dataclass
class TemporalReliabilityReport:
    """时间维度可靠性报告。"""
    patch_id: str = ""
    initial_reliability: float = 0.0      # R₀
    decay_constant: float = 0.0           # λ (per day)
    days_since_patch: float = 0.0
    current_reliability: float = 0.0      # R(t)
    half_life_days: float = 0.0           # T½ (R(t) = 0.5·R₀)
    time_to_refresh_days: float = 0.0     # 到达 SCHEDULE_REFRESH 阈值的天数
    urgency: RefreshUrgency = RefreshUrgency.STABLE
    env_drift_score: float = 0.0          # 环境漂移程度
    env_drift_detected: bool = False
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'initial_reliability': round(self.initial_reliability, 4),
            'decay_constant': round(self.decay_constant, 6),
            'days_since_patch': round(self.days_since_patch, 1),
            'current_reliability': round(self.current_reliability, 4),
            'half_life_days': round(self.half_life_days, 1),
            'time_to_refresh_days': round(self.time_to_refresh_days, 1),
            'urgency': self.urgency.value,
            'env_drift_score': round(self.env_drift_score, 4),
            'env_drift_detected': self.env_drift_detected,
            'recommendation': self.recommendation,
        }


# 衰减常数估计

def estimate_decay_constant(patch_complexity: float,
                            attack_surface: float,
                            mitigation_diversity: int = 1) -> float:
    """从补丁特征估算 λ 衰减常数。

    patch_complexity: 0..1，补丁复杂度（修改行/函数大小）
    attack_surface:   0..1，漏洞攻击面暴露度
    mitigation_diversity: 防御技术种类数

    高复杂度 + 大攻击面 → λ 大，衰减快。
    多防御层 → λ 小，冗余效应。
    """
    base = 0.001  # 基线 (1/1000 per day)
    # 复杂度因子
    complexity_factor = 1.0 + 2.0 * patch_complexity
    # 攻击面因子
    attack_factor = 1.0 + 3.0 * attack_surface
    # 防御多样性阻尼 (每种额外技术降 20%)
    diversity_dampening = max(0.3, 1.0 - 0.2 * (mitigation_diversity - 1))
    return base * complexity_factor * attack_factor * diversity_dampening


# 环境漂移检测器

class EnvironmentDriftDetector:
    """环境漂移检测 — CUSUM 轻量检测器。

    周期性采样 runtime 指纹，累积偏差超阈值时标记漂移。
    """

    def __init__(self, threshold: float = 1.5, drift_rate: float = 0.05):
        self._threshold = threshold
        self._drift_rate = drift_rate  # CUSUM 允许漂移率
        self._baseline: Optional[EnvironmentFingerprint] = None
        self._cusum_pos = 0.0
        self._cusum_neg = 0.0
        self._samples: List[EnvironmentFingerprint] = []
        self.drift_detected = False

    def set_baseline(self, fp: EnvironmentFingerprint):
        self._baseline = fp
        self._cusum_pos = 0.0
        self._cusum_neg = 0.0
        self._samples = [fp]
        self.drift_detected = False

    def sample(self, fp: EnvironmentFingerprint) -> Tuple[float, bool]:
        """采集样本，返回 (漂移分数, 是否检测到漂移)。"""
        if self._baseline is None:
            self.set_baseline(fp)
            return 0.0, False

        dist = self._baseline.distance(fp)
        self._samples.append(fp)

        # CUSUM 更新
        z = dist - self._drift_rate
        self._cusum_pos = max(0.0, self._cusum_pos + z)
        self._cusum_neg = max(0.0, self._cusum_neg - z)

        if self._cusum_pos > self._threshold or self._cusum_neg > self._threshold:
            self.drift_detected = True

        # 漂移分数 = 最近 3 样本平均距离
        recent = self._samples[-min(3, len(self._samples)):]
        avg_dist = sum(self._baseline.distance(s) for s in recent) / len(recent)

        return avg_dist, self.drift_detected

    def current_drift_score(self) -> float:
        if not self._samples or not self._baseline:
            return 0.0
        recent = self._samples[-min(3, len(self._samples)):]
        return sum(self._baseline.distance(s) for s in recent) / len(recent)


# 环境指纹采集器

def capture_environment(binary_path: str = "") -> EnvironmentFingerprint:
    """采集当前 runtime 环境指纹。

    解析 ldd / readelf / uname 输出获取环境快照。
    工具不可用时字段留空，不影响比较。
    """
    fp = EnvironmentFingerprint(sampled_at=time.time())

    # libc 版本
    try:
        result = subprocess.run(['ldd', '--version'], capture_output=True,
                                text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                m = re.search(r'(\d+\.\d+)', line)
                if m:
                    fp.libc_version = m.group(1)
                    break
    except Exception:
        pass

    # kernel 版本
    try:
        result = subprocess.run(['uname', '-r'], capture_output=True,
                                text=True, timeout=3)
        fp.kernel_version = result.stdout.strip()
    except Exception:
        pass

    # ELF 安全检查（若提供 binary path）
    if binary_path and os.path.exists(binary_path):
        try:
            result = subprocess.run(
                ['readelf', '-l', binary_path],
                capture_output=True, text=True, timeout=5)
            output = result.stdout
            fp.nx_enabled = 'GNU_STACK' in output and 'E' not in output
            fp.relro = 'full' if 'BIND_NOW' in output else (
                'partial' if 'GNU_RELRO' in output else 'none')
        except Exception:
            pass

    return fp


# 时间衰减

class TemporalReliabilityModel:
    """补丁可靠性时间衰减。

    用法:
        tm = TemporalReliabilityModel()
        tm.set_baseline(initial_reliability=0.95, patch_complexity=0.3,
                        attack_surface=0.6)
        report = tm.assess(days_since_patch=90, env_drift=0.05)
    """

    # 可靠性阈值映射
    _THRESHOLDS = {
        RefreshUrgency.STABLE: 0.90,
        RefreshUrgency.MONITOR: 0.70,
        RefreshUrgency.SCHEDULE_REFRESH: 0.40,
    }

    def __init__(self):
        self.patch_id = ""
        self._r0 = 0.0             # R₀
        self._lambda = 0.0         # λ
        self._env_drift_detector = EnvironmentDriftDetector()
        self._patch_age_days = 0.0  # applied_at → now

    def set_baseline(self, initial_reliability: float,
                     patch_complexity: float = 0.3,
                     attack_surface: float = 0.5,
                     mitigation_diversity: int = 1,
                     baseline_env: EnvironmentFingerprint = None,
                     patch_id: str = ""):
        """设置基线。"""
        self._r0 = max(0.0, min(1.0, initial_reliability))
        self._lambda = estimate_decay_constant(
            patch_complexity, attack_surface, mitigation_diversity)
        self.patch_id = patch_id or f"patch_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        if baseline_env:
            self._env_drift_detector.set_baseline(baseline_env)

    def assess(self, days_since_patch: float,
               current_env: EnvironmentFingerprint = None,
               env_drift: float = 0.0) -> TemporalReliabilityReport:
        """评估当前可靠性。"""
        self._patch_age_days = days_since_patch

        # 指数衰减
        decay = math.exp(-self._lambda * days_since_patch)

        # 环境漂移
        if current_env and self._env_drift_detector._baseline:
            drift_score, detected = self._env_drift_detector.sample(current_env)
        else:
            drift_score = env_drift
            detected = False

        env_factor = max(0.0, 1.0 - drift_score)

        # R(t)
        rt = self._r0 * decay * env_factor
        rt = max(0.0, min(1.0, rt))

        # 半衰期
        if self._lambda > 0:
            half_life = math.log(2) / self._lambda
        else:
            half_life = float('inf')

        # TTR: R(t) ≤ 0.40·R₀ 的到达天数
        if self._lambda > 0 and self._r0 > 0:
            ttr = math.log(0.40) / (-self._lambda)
            ttr -= days_since_patch  # 剩余
            ttr = max(0.0, ttr)
        else:
            ttr = float('inf')

        # 紧急度
        ratio = rt / max(self._r0, 0.001)
        if ratio >= self._THRESHOLDS[RefreshUrgency.STABLE]:
            urgency = RefreshUrgency.STABLE
        elif ratio >= self._THRESHOLDS[RefreshUrgency.MONITOR]:
            urgency = RefreshUrgency.MONITOR
        elif ratio >= self._THRESHOLDS[RefreshUrgency.SCHEDULE_REFRESH]:
            urgency = RefreshUrgency.SCHEDULE_REFRESH
        else:
            urgency = RefreshUrgency.CRITICAL

        # 建议
        if urgency == RefreshUrgency.STABLE:
            recommendation = "no action required"
        elif urgency == RefreshUrgency.MONITOR:
            recommendation = "schedule quarterly reassessment"
        elif urgency == RefreshUrgency.SCHEDULE_REFRESH:
            recommendation = f"plan patch refresh within {ttr:.0f} days"
        else:
            recommendation = "immediate patch refresh required"

        return TemporalReliabilityReport(
            patch_id=self.patch_id,
            initial_reliability=self._r0,
            decay_constant=self._lambda,
            days_since_patch=days_since_patch,
            current_reliability=rt,
            half_life_days=half_life if half_life != float('inf') else -1,
            time_to_refresh_days=ttr if ttr != float('inf') else -1,
            urgency=urgency,
            env_drift_score=drift_score,
            env_drift_detected=detected,
            recommendation=recommendation,
        )


# 便捷函数

def predict_patch_longevity(initial_reliability: float,
                            patch_complexity: float = 0.3,
                            attack_surface: float = 0.5,
                            binary_path: str = "",
                            days_since_patch: float = 0.0) -> TemporalReliabilityReport:
    """一键补丁寿命预测。"""
    model = TemporalReliabilityModel()
    env = capture_environment(binary_path) if binary_path else None
    model.set_baseline(
        initial_reliability=initial_reliability,
        patch_complexity=patch_complexity,
        attack_surface=attack_surface,
        baseline_env=env,
    )
    return model.assess(days_since_patch=days_since_patch, current_env=env)
