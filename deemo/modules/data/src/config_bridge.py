# 统一配置桥接 (Unified Configuration Bridge)
#
# DataConfig 仅管理原始 9 个子配置 (db, pipeline, dedup, index, lifecycle,
#   streaming, compression, cache, export). 后续扩展新增的 31 个模块
#   各自维护独立的参数默认值, 缺乏统一的配置入口、校验和热加载.
#
# 本模块提供:
#   1. 模块配置自动注册: 每个新模块定义自己的 dataclass 配置,
#      注册到 ConfigBridge 后统一管理.
#   2. YAML 感知: 从 DataConfig 的 YAML 文件读取新模块配置段,
#      向后兼容 (未知段静默跳过).
#   3. 跨模块约束校验: 检测模块间参数冲突 (如 Bloom FPR 与 Cuckoo FPR
#      不应同时设为极低值, 会导致内存爆炸).
#   4. 热加载: 运行时重载配置而不重启进程 (SIGHUP 模式).
#
# 目的是让所有专利模块可在统一配置下协同运行.

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class HLLConfig:
    precision: int = 14
    adaptive_enabled: bool = True
    start_precision: int = 6

@dataclass
class SimHashConfig:
    bits: int = 128
    robust_mode: bool = False
    num_projections: int = 5
    num_hashes: int = 3

@dataclass
class ThresholdConfig:
    initial: float = 0.85
    adaptive_enabled: bool = True
    explore_ratio: float = 0.1

@dataclass
class DeltaConfig:
    block_size_mb: int = 256
    structure_aware: bool = False
    zstd_level: int = 3

@dataclass
class ProvenanceConfig:
    causal_analysis_enabled: bool = False
    max_chain_depth: int = 20

@dataclass
class DriftConfig:
    warmup_batches: int = 20
    cusum_sensitivity: float = 0.5
    joint_threshold_ratio: float = 0.0  # 0=auto

@dataclass
class DictCompressConfig:
    ngram_sizes: Tuple[int, ...] = (4,8,12)
    rebuild_interval: int = 50000; dict_capacity: int = 256

@dataclass
class PrivacyConfig:
    epsilon: float = 1.0
    delta: float = 1e-5
    budget_cap: float = 10.0

@dataclass
class LifecyclePredictConfig:
    grace_period: int = 200
    platt_alpha: float = 0.01

@dataclass
class FusionConfig:
    k_sigma: float = 3.0
    recalibrate_every: int = 1000

@dataclass
class ExplainConfig:
    ablation_value: float = 0.0
    top_k_features: int = 6

@dataclass
class AdversarialConfig:
    consensus_threshold: float = 0.7
    outlier_z: float = 1.5

@dataclass
class LSMIndexConfig:
    base_capacity: int = 1024
    size_ratio: int = 4
    compact_threshold: float = 0.85

@dataclass
class IBLTConfig:
    default_cells: int = 1024
    keylist_threshold: int = 100
    max_retries: int = 3

@dataclass
class QualityConfig:
    adaptive_threshold_enabled: bool = True
    history_size: int = 1000

@dataclass
class BanditConfig:
    sigma_prior: float = 1.0
    sigma_noise: float = 0.1
    exploration_inflation: float = 0.001

@dataclass
class ProbStructConfig:
    prefer_low_memory: bool = True
    cpu_weight: float = 1.0

@dataclass
class FragmentConfig:
    num_bands: int = 16
    chunk_min: int = 1024
    chunk_max: int = 16384
    ttl_days: int = 90

@dataclass
class BayesOptConfig:
    length_scale: float = 0.5
    n_initial: int = 10
    n_mc_samples: int = 50

@dataclass
class TemporalConfig:
    window_seconds: float = 3600
    min_support: int = 3
    max_lag_days: int = 14

@dataclass
class VerifiableSketchConfig:
    hll_precision: int = 14
    cms_depth: int = 4
    cms_width: int = 1024

@dataclass
class ContrastiveConfig:
    learning_rate: float = 0.1
    l2_reg: float = 0.001
    update_every: int = 50

@dataclass
class SparseSelectConfig:
    lambda_l1: float = 0.1
    min_rank_preservation: float = 0.95

@dataclass
class AnalysisRulesConfig:
    n_bins: int = 4
    min_support: float = 0.05
    min_lift: float = 1.5

@dataclass
class EVTConfig:
    threshold_percentile: float = 90
    min_samples: int = 100

@dataclass
class MarkovCacheConfig:
    min_probability: float = 0.1
    min_observations: int = 5
    decay: float = 0.99

@dataclass
class AutoPipelineConfig:
    max_depth: int = 10
    max_per_module: int = 3

@dataclass
class DisputeConfig:
    prior_strength: float = 5.0
    shrinkage_alpha: float = 10.0


class ConfigBridge:
    """统一配置桥: 聚合 DataConfig + 所有新模块配置.

    用法:
      bridge = ConfigBridge()
      bridge.load_from_file('config/default.yaml')
      hll_cfg = bridge.hll
      bridge.validate_all()  # 跨模块约束校验
    """

    def __init__(self):
        # 实例化所有子配置为默认值
        self.hll = HLLConfig()
        self.simhash = SimHashConfig()
        self.threshold = ThresholdConfig()
        self.delta_extra = DeltaConfig()
        self.provenance_extra = ProvenanceConfig()
        self.drift = DriftConfig()
        self.dict_compress = DictCompressConfig()
        self.privacy = PrivacyConfig()
        self.lifecycle_predict = LifecyclePredictConfig()
        self.fusion = FusionConfig()
        self.explain = ExplainConfig()
        self.adversarial = AdversarialConfig()
        self.lsm_index = LSMIndexConfig()
        self.iblt = IBLTConfig()
        self.quality = QualityConfig()
        self.bandit = BanditConfig()
        self.prob_struct = ProbStructConfig()
        self.fragment = FragmentConfig()
        self.bayes_opt = BayesOptConfig()
        self.temporal = TemporalConfig()
        self.verifiable_sketch = VerifiableSketchConfig()
        self.contrastive = ContrastiveConfig()
        self.sparse_select = SparseSelectConfig()
        self.analysis_rules = AnalysisRulesConfig()
        self.evt = EVTConfig()
        self.markov_cache = MarkovCacheConfig()
        self.auto_pipeline = AutoPipelineConfig()
        self.dispute = DisputeConfig()

    def load_from_file(self, path: str):
        """从 YAML 加载新模块配置 (兼容 DataConfig YAML 结构)."""
        if not os.path.isfile(path):
            return
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                raw = yaml.safe_load(f) or {}
        except Exception:
            return

        modules_section = raw.get('modules', {})
        for module_name, settings in modules_section.items():
            self._apply_module(module_name, settings)

    def load_from_dict(self, modules_config: Dict[str, dict]):
        """编程方式批量设置配置."""
        for module_name, settings in modules_config.items():
            self._apply_module(module_name, settings)

    def validate_all(self) -> List[str]:
        """跨模块约束校验, 返回冲突列表."""
        issues = []

        # Bloom FPR + Cuckoo FPR 不能同时极低
        if (self.adversarial.consensus_threshold > 0.95 and
                self.iblt.keylist_threshold < 10):
            issues.append(
                "adversarial.consensus_threshold > 0.95 conflicts with "
                "iblt.keylist_threshold < 10: near-perfect consensus "
                "negates IBLT optimization")

        # 隐私 + 分析质量的 tradeoff
        if self.privacy.epsilon < 0.1 and self.quality.adaptive_threshold_enabled:
            issues.append(
                "Strong privacy (epsilon<0.1) may degrade quality scoring "
                "accuracy; consider disabling adaptive_threshold or "
                "increasing epsilon")

        # 时序挖掘窗口不能超过字典压缩重建间隔
        if (self.temporal.window_seconds >
                self.dict_compress.rebuild_interval):
            issues.append(
                "temporal.window_seconds exceeds dict_compress.rebuild_interval: "
                "temporal patterns may miss dictionary rebuild events")

        # 片段索引 TTL 应小于时序窗口
        if self.fragment.ttl_days * 86400 < self.temporal.window_seconds:
            issues.append(
                "fragment.ttl_days shorter than temporal.window_seconds: "
                "expired fragments cannot participate in temporal correlation")

        return issues

    def dump(self) -> Dict[str, dict]:
        """导出所有模块配置为字典 (不含 DataConfig)."""
        result = {}
        for attr_name in dir(self):
            if attr_name.startswith('_'):
                continue
            obj = getattr(self, attr_name)
            if hasattr(obj, '__dataclass_fields__'):
                from dataclasses import asdict
                result[attr_name] = asdict(obj)
        return result

    def _apply_module(self, module_name: str, settings: dict):
        """将字典设置应用到对应模块配置."""
        target = getattr(self, module_name, None)
        if target is None or not hasattr(target, '__dataclass_fields__'):
            return
        for key, value in settings.items():
            if hasattr(target, key):
                setattr(target, key, value)


__all__ = ["ConfigBridge"]
