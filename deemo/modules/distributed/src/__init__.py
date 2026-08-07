# src/ — 懒加载门面，避免启动时加载所有模块
# 当引用 src.models.* 时才真正 import models 子模块
#
# 热路径符号（Task/Node/CircuitBreaker）直接导入，避免 __getattr__ 开销

import importlib

__all__ = [
    "TaskStatus", "TaskType", "Task", "Node",
    "retry", "backoff_delay", "setup_logging", "timeout", "memoize",
    "serialize", "deserialize",
    "PriorityTaskQueue", "RedisPriorityQueue", "DeadLetterQueue",
    "CronScheduler", "CronExpr", "parse_cron", "every",
    "BatchCollector", "BatchPipeline",
    "CircuitState", "CircuitBreaker", "MultiBreaker", "SlidingWindowBreaker",
    "TokenBucket", "DistributedTokenBucket", "ConcurrencyLimiter",
    "rate_limit", "RateLimitExceeded",
    "IdempotencyGuard", "idempotency_key",
    "HealthStatus", "HealthServer", "HealthCheck",
    "RedisPool",
    "Counter", "Gauge", "Histogram", "Summary", "Registry",
# 2026-08 广度拓展
    "LoadBalancer", "ConsistentHashRing", "SelectorNode",
    "ElasticPool", "ThresholdScalePolicy", "PredictiveScalePolicy",
    "AdaptiveCircuitBreaker", "FractionalCircuitBreaker",
    "BackpressureController", "BackpressureSignal", "BackpressureBlocked",
    "Pipeline", "PipelineRunner", "PipelineExecutor", "Stage", "FanInCollector",
    "PartitionManager", "HashPartitioner", "RangePartitioner", "RoundRobinPartitioner",
    "GracefulShutdown", "ShutdownPhase",
    "TaskStateMachine", "TransitionTable", "StateMachineBuilder", "InvalidTransition",
    "WatermarkMonitor", "MultiQueueWatermark", "FlowController",
    "NodeRegistry", "NodeRecord", "RedisDiscovery", "GossipDiscovery", "StaticDiscovery",
# 2026-08 故障恢复与自适应容错
    "FaultPropagationGraph", "FaultSignal", "RootCauseCandidate",
    "fault_signals_from_breakers",
    "RescheduleOracle", "reschedule_after_fault",
    "SpeculativeExecutor", "CriticalPathTracker", "SpeculationRecord",
    "AdaptiveCheckpointController", "CheckpointRecord", "FailureRecord",
    "JointBudgetController",
]

_MODULE_MAP = {
    "TaskStatus": "models", "TaskType": "models", "Task": "models", "Node": "models",
    "retry": "utils", "backoff_delay": "utils", "setup_logging": "utils",
    "timeout": "utils", "memoize": "utils",
    "serialize": "serialization", "deserialize": "serialization",
    "PriorityTaskQueue": "priority", "RedisPriorityQueue": "priority",
    "DeadLetterQueue": "priority",
    "CronScheduler": "scheduler", "CronExpr": "scheduler",
    "parse_cron": "scheduler", "every": "scheduler",
    "BatchCollector": "batch", "BatchPipeline": "batch",
    "CircuitState": "circuit_breaker", "CircuitBreaker": "circuit_breaker",
    "MultiBreaker": "circuit_breaker", "SlidingWindowBreaker": "circuit_breaker",
    "TokenBucket": "rate_limiter", "DistributedTokenBucket": "rate_limiter",
    "ConcurrencyLimiter": "rate_limiter",
    "rate_limit": "rate_limiter", "RateLimitExceeded": "rate_limiter",
    "IdempotencyGuard": "idempotency", "idempotency_key": "idempotency",
    "HealthStatus": "health", "HealthServer": "health", "HealthCheck": "health",
    "RedisPool": "pool",
    "Counter": "metrics", "Gauge": "metrics", "Histogram": "metrics",
    "Summary": "metrics", "Registry": "metrics",
    # 2026-08 拓展
    "LoadBalancer": "load_balancer", "ConsistentHashRing": "load_balancer",
    "SelectorNode": "load_balancer",
    "ElasticPool": "elastic_pool", "ThresholdScalePolicy": "elastic_pool",
    "PredictiveScalePolicy": "elastic_pool",
    "AdaptiveCircuitBreaker": "adaptive_breaker",
    "FractionalCircuitBreaker": "adaptive_breaker",
    "BackpressureController": "backpressure", "BackpressureSignal": "backpressure",
    "BackpressureBlocked": "backpressure",
    "Pipeline": "pipeline", "PipelineRunner": "pipeline",
    "PipelineExecutor": "pipeline", "Stage": "pipeline",
    "FanInCollector": "pipeline",
    "PartitionManager": "partition", "HashPartitioner": "partition",
    "RangePartitioner": "partition", "RoundRobinPartitioner": "partition",
    "GracefulShutdown": "graceful_shutdown", "ShutdownPhase": "graceful_shutdown",
    "TaskStateMachine": "state_machine", "TransitionTable": "state_machine",
    "StateMachineBuilder": "state_machine", "InvalidTransition": "state_machine",
    "WatermarkMonitor": "watermark", "MultiQueueWatermark": "watermark",
    "FlowController": "watermark",
    "NodeRegistry": "node_registry", "NodeRecord": "node_registry",
    "RedisDiscovery": "node_registry", "GossipDiscovery": "node_registry",
    "StaticDiscovery": "node_registry",
    # 2026-08 故障恢复与自适应容错
    "FaultPropagationGraph": "fault_propagation", "FaultSignal": "fault_propagation",
    "RootCauseCandidate": "fault_propagation",
    "fault_signals_from_breakers": "fault_propagation",
    "RescheduleOracle": "reschedule_oracle",
    "reschedule_after_fault": "reschedule_oracle",
    "SpeculativeExecutor": "speculative_exec",
    "CriticalPathTracker": "speculative_exec",
    "SpeculationRecord": "speculative_exec",
    "AdaptiveCheckpointController": "adaptive_checkpoint",
    "CheckpointRecord": "adaptive_checkpoint", "FailureRecord": "adaptive_checkpoint",
    "JointBudgetController": "adaptive_checkpoint",
}

_MODULE_CACHE: dict = {}

# 热路径：worker.py 启动时必定需要这些符号，预加载避免首次访问的 import 延迟
try:
    from . import models as _models
    _MODULE_CACHE["models"] = _models
    from . import circuit_breaker as _cb
    _MODULE_CACHE["circuit_breaker"] = _cb
except ImportError:
    pass


def __getattr__(name: str):
    if name in _MODULE_MAP:
        mod_name = _MODULE_MAP[name]
        if mod_name not in _MODULE_CACHE:
            _MODULE_CACHE[mod_name] = importlib.import_module(
                f".{mod_name}", package=__package__
            )
        return getattr(_MODULE_CACHE[mod_name], name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# GRL-Sched 拓展
# 追加注册 — 保持既有映射不变，仅扩展懒加载表与符号导出
# GRL-Sched: 图强化学习任务调度 + 动态图划分
# GRL-Sched 基于 HEFT + GNN + RL 的组合调度框架
__all__ += [
    "TaskDependencyGraph", "TaskNode", "DependencyEdge",
    "GraphPartitioner", "Partition",
    "GNNEncoder", "GRLScheduler", "SimulatedAnnealingScheduler",
    "MakespanSimulator", "LinearQPolicy",
    "DependencyAwareScheduler", "heft_rank", "heft_order", "grl_schedule",
]
_MODULE_MAP.update({
    "TaskDependencyGraph": "grl_graph", "TaskNode": "grl_graph",
    "DependencyEdge": "grl_graph",
    "GraphPartitioner": "grl_partition", "Partition": "grl_partition",
    "GNNEncoder": "grl_scheduler", "GRLScheduler": "grl_scheduler",
    "SimulatedAnnealingScheduler": "grl_scheduler",
    "MakespanSimulator": "grl_scheduler", "LinearQPolicy": "grl_scheduler",
    "DependencyAwareScheduler": "grl_scheduler",
    "heft_rank": "grl_scheduler", "heft_order": "grl_scheduler",
    "grl_schedule": "grl_scheduler",
})

# 故障自愈与自适应容错拓展
# 因果故障传播 + 增量重调度 + 关键路径投机 + 自适应检查点
# 论文: IDI — 干预主义因果推断的故障定位
#       EFTR-HGNet / SPARe
# 这些模块已在上方 __all__ 与 _MODULE_MAP 中注册，此处不重复追加

# 专利级拓展: 鲁棒GNN + 反事实谕示 + 时序超图 + 共形预测
# robust_gnn:             随机平滑认证的 GNN 编码器 — 抗图结构扰动
# counterfactual_oracle:  Pearl do-calculus 调度恢复规划
# temporal_hypergraph:    时序超图卷积 — 捕获非成对依赖与资源竞争演化
# conformal_straggler:    共形预测驱动的滞后检测 — 校准不确定度 + 风险受控投机
__all__ += [
    "RobustGNNCertifier", "RobustSchedulerMixin",
    "SchedulingStructuralCausalModel", "CounterfactualSchedulingOracle",
    "CounterfactualReport",
    "TemporalHypergraph", "TemporalHypergraphConv",
    "hypergraph_augmented_features",
    "ConformalStragglerPredictor", "OnlineQuantileEstimator",
    "ConformalPrediction", "ConformalSpeculationGate",
]
_MODULE_MAP.update({
    "RobustGNNCertifier": "robust_gnn", "RobustSchedulerMixin": "robust_gnn",
    "SchedulingStructuralCausalModel": "counterfactual_oracle",
    "CounterfactualSchedulingOracle": "counterfactual_oracle",
    "CounterfactualReport": "counterfactual_oracle",
    "TemporalHypergraph": "temporal_hypergraph",
    "TemporalHypergraphConv": "temporal_hypergraph",
    "hypergraph_augmented_features": "temporal_hypergraph",
    "ConformalStragglerPredictor": "conformal_straggler",
    "OnlineQuantileEstimator": "conformal_straggler",
    "ConformalPrediction": "conformal_straggler",
    "ConformalSpeculationGate": "conformal_straggler",
})

# 专利级拓展: Lyapunov碳调度 + 死锁验证 + 在线预测 + 调度自监控
# lyapunov_carbon:    李雅普诺夫漂移加惩罚 — 碳感知任务准入/批处理，闭式决策
# deadlock_verifier:  资源分配图约简 — 调度方案死锁自由验证
# online_predictor:   自适应遗忘因子 RLS — 非平稳执行时间的在线预测
# scheduler_monitor:  非参数 CUSUM — 调度器健康自监控
__all__ += [
    "LyapunovCarbonGate", "CarbonIntensityProvider",
    "AdmissionDecision", "CarbonMetrics",
    "carbon_aware_submit",
    "DeadlockVerifier", "ResourceSpec", "DeadlockReport",
    "AdaptiveRLS", "TaskTimePredictor",
    "SchedulerHealthMonitor", "NonparametricCUSUM",
    "DegradationLevel", "SchedulerSnapshot",
    "snapshot_from_metrics",
]
_MODULE_MAP.update({
    "LyapunovCarbonGate": "lyapunov_carbon",
    "CarbonIntensityProvider": "lyapunov_carbon",
    "AdmissionDecision": "lyapunov_carbon",
    "CarbonMetrics": "lyapunov_carbon",
    "carbon_aware_submit": "lyapunov_carbon",
    "DeadlockVerifier": "deadlock_verifier",
    "ResourceSpec": "deadlock_verifier",
    "DeadlockReport": "deadlock_verifier",
    "AdaptiveRLS": "online_predictor",
    "TaskTimePredictor": "online_predictor",
    "SchedulerHealthMonitor": "scheduler_monitor",
    "NonparametricCUSUM": "scheduler_monitor",
    "DegradationLevel": "scheduler_monitor",
    "SchedulerSnapshot": "scheduler_monitor",
    "snapshot_from_metrics": "scheduler_monitor",
})

# 专利级拓展: 最优传输分配 + 纳什公平调度 + 管线重物质化 + 差分隐私
# ot_assigner:         Sinkhorn 最优传输 — 任务→机器的联合代价最小化分配
# nash_fair_scheduler: 多租户博弈纳什均衡 — 策略证明的公平资源分配
# pipeline_remat:      管线重物质化 — 内存约束下的最优中间结果检查点
# dp_metrics:          差分隐私度量 — ε-DP 保护的多租户调度统计
__all__ += [
    "sinkhorn_assign", "OTAssigner",
    "NashFairScheduler", "TenantBid", "NashAllocation",
    "PipelineRematOptimizer", "RematDecision", "RematPlan",
    "DPCounter", "DPGauge", "DPHistogram",
    "DPPrivacyBudget", "DPMetricsCollector",
]
_MODULE_MAP.update({
    "sinkhorn_assign": "ot_assigner", "OTAssigner": "ot_assigner",
    "NashFairScheduler": "nash_fair_scheduler",
    "TenantBid": "nash_fair_scheduler",
    "NashAllocation": "nash_fair_scheduler",
    "PipelineRematOptimizer": "pipeline_remat",
    "RematDecision": "pipeline_remat", "RematPlan": "pipeline_remat",
    "DPCounter": "dp_metrics", "DPGauge": "dp_metrics",
    "DPHistogram": "dp_metrics", "DPPrivacyBudget": "dp_metrics",
    "DPMetricsCollector": "dp_metrics",
})

# 专利级拓展: 因果发现 + PID伸缩 + 自适应负载均衡 + 拜占庭窃取
# causal_discovery:        Granger因果+转移熵 — 从执行轨迹自动推断任务依赖
# pid_autoscaler:          PID控制论弹性伸缩 — 带抗饱和/前馈的闭环自动扩缩
# adaptive_load_balancer:  自适应Power-of-d — d在线调优+尾延迟上界
# byzantine_stealing:      拜占庭容错工作窃取 — 见证人委员会轻量BFT
__all__ += [
    "transfer_entropy", "CausalDependencyDiscoverer",
    "PIDAutoscaler", "ziegler_nichols_tune",
    "AdaptivePowerOfD",
    "ByzantineResilientStealing", "StealTransaction", "NodeReputation",
]
_MODULE_MAP.update({
    "transfer_entropy": "causal_discovery",
    "CausalDependencyDiscoverer": "causal_discovery",
    "PIDAutoscaler": "pid_autoscaler",
    "ziegler_nichols_tune": "pid_autoscaler",
    "AdaptivePowerOfD": "adaptive_load_balancer",
    "ByzantineResilientStealing": "byzantine_stealing",
    "StealTransaction": "byzantine_stealing",
    "NodeReputation": "byzantine_stealing",
})

# 专利级拓展: 草图度量 + 活性验证 + 对抗老虎机 + 联邦蒸馏
# sketch_metrics:       Count-Min + HyperLogLog — 亚线性空间可合并调度统计
# liveness_checker:     运行时LTL活性验证 — 饥饿自由/进展/非活锁检测
# adversarial_bandits:  EXP3-IX对抗老虎机 — 非随机环境下的遗憾最优调度
# federated_distill:    联邦策略蒸馏 — 跨集群调度知识迁移，不共享原始数据
__all__ += [
    "CountMinSketch", "HyperLogLog", "SketchMetrics",
    "LivenessMonitor", "LivenessProperty", "LivenessVerdict",
    "starvation_freedom_property", "progress_property",
    "no_livelock_property",
    "EXP3IX", "AdversarialBanditScheduler",
    "PolicyTeacher", "FederatedDistillationAggregator",
    "PolicyStudent", "federated_round",
]
_MODULE_MAP.update({
    "CountMinSketch": "sketch_metrics", "HyperLogLog": "sketch_metrics",
    "DecayingElasticSketch": "sketch_metrics", "SketchMetrics": "sketch_metrics",
    "LivenessMonitor": "liveness_checker",
    "LivenessProperty": "liveness_checker",
    "LivenessVerdict": "liveness_checker",
    "starvation_freedom_property": "liveness_checker",
    "progress_property": "liveness_checker",
    "no_livelock_property": "liveness_checker",
    "EXP3IX": "adversarial_bandits",
    "AdversarialBanditScheduler": "adversarial_bandits",
    "PolicyTeacher": "federated_distill",
    "FederatedDistillationAggregator": "federated_distill",
    "PolicyStudent": "federated_distill",
    "federated_round": "federated_distill",
})

# 专利级拓展: EVT尾部 + Hawkes到达 + OCO权重 + 谱划分
# evt_tail:            GPD Peaks-Over-Threshold — 调度尾延迟极端分位数预测
# hawkes_arrival:      Hawkes自激过程 — 任务到达爆发预测 + 预扩容
# oco_scheduler:       OCO在线凸优化 — 调度代价权重的动态遗憾最小化
# spectral_partition:  谱聚类+Fiedler向量 — Cheeger不等式保证的DAG划分
__all__ += [
    "fit_gpd_mle", "EVTTailPredictor",
    "HawkesArrivalModel",
    "OCOWeightOptimizer", "OCOSchedulingAdapter",
    "SpectralPartitioner",
]
_MODULE_MAP.update({
    "fit_gpd_mle": "evt_tail", "EVTTailPredictor": "evt_tail",
    "HawkesArrivalModel": "hawkes_arrival",
    "OCOWeightOptimizer": "oco_scheduler",
    "OCOSchedulingAdapter": "oco_scheduler",
    "SpectralPartitioner": "spectral_partition",
})

# ===== 专利级拓展: Wasserstein DRO + 分位数追踪 + MoE门控 + FTRL检查点 =====
# wasserstein_dro:    Wasserstein球分布鲁棒 — 有限样本下的DAG调度对冲
# quantile_tracker:   在线分位数追踪 — 单调约束+衰减的多级延迟分位数
# mixture_experts:    混合专家门控 — 多调度策略的在线自适应融合
# regret_checkpoint:  FTRL连续检查点 — 遗憾最优的自适应间隔整定
__all__ += [
    "wasserstein1", "wasserstein_radius", "WassersteinRobustScheduler",
    "OnlineQuantileTracker",
    "MoEGatingNetwork", "MixtureOfExpertsScheduler",
    "FTRLCheckpointController",
]
_MODULE_MAP.update({
    "wasserstein1": "wasserstein_dro",
    "wasserstein_radius": "wasserstein_dro",
    "WassersteinRobustScheduler": "wasserstein_dro",
    "TDigest": "quantile_tracker", "OnlineQuantileTracker": "quantile_tracker",
    "MoEGatingNetwork": "mixture_experts",
    "MixtureOfExpertsScheduler": "mixture_experts",
    "FTRLCheckpointController": "regret_checkpoint",
})

# 专利级拓展: PAC-Bayes认证 + 切换代价优化 + 容量约束调度
# pac_bayes_cert:      PAC-贝叶斯泛化界 — 学习型调度策略的非空认证
# switching_cost_opt:   切换代价在线优化 — L1稀疏切换的调度参数整定
# capacity_scheduler:   容量约束调度 — 优先级隔离+延迟批处理+极小极大遗憾
__all__ += [
    "catoni_bound", "PACBayesCertifier",
    "SwitchingCostOptimizer",
    "CapacityConfig", "QueuedTask", "CapacityConstrainedScheduler",
]
_MODULE_MAP.update({
    "catoni_bound": "pac_bayes_cert", "PACBayesCertifier": "pac_bayes_cert",
    "SwitchingCostOptimizer": "switching_cost_opt",
    "CapacityConfig": "capacity_scheduler", "QueuedTask": "capacity_scheduler",
    "CapacityConstrainedScheduler": "capacity_scheduler",
})

# 专利级拓展: 学习型优先级 + 贝叶斯熔断 + 流行病Gossip溯源
# learned_priority:   CDF学习型索引 — O(1)近似优先队列
# bayesian_breaker:   BOCD贝叶斯变点检测 — 失败流统计的自适应熔断
# epidemic_gossip:    谣言中心性 — Gossip状态传播的零号病人定位
__all__ += [
    "PiecewiseLinearCDF", "LearnedPriorityQueue",
    "BOCDDetector", "BayesianCircuitBreaker",
    "GossipTrace", "EpidemicSourceDetector",
]
_MODULE_MAP.update({
    "PiecewiseLinearCDF": "learned_priority",
    "LearnedPriorityQueue": "learned_priority",
    "BOCDDetector": "bayesian_breaker",
    "BayesianCircuitBreaker": "bayesian_breaker",
    "GossipTrace": "epidemic_gossip",
    "EpidemicSourceDetector": "epidemic_gossip",
})

# 专利级拓展: 压缩共识 + 到达模拟器
# compressed_consensus: QSGD随机量化 — DIANA风格的分布式调度器状态压缩共识
# arrival_simulator:    别名法离散事件模拟 — what-if调度策略对比分析
__all__ += [
    "qsgd_compress", "qsgd_decompress", "compression_ratio",
    "CompressedConsensus",
    "AliasSampler", "DiscreteEventSimulator",
]
_MODULE_MAP.update({
    "qsgd_compress": "compressed_consensus",
    "qsgd_decompress": "compressed_consensus",
    "compression_ratio": "compressed_consensus",
    "CompressedConsensus": "compressed_consensus",
    "AliasSampler": "arrival_simulator",
    "DiscreteEventSimulator": "arrival_simulator",
})

# 专利级拓展: Anytime部分结果 + 集成元调度
# anytime_scheduler: 等边际贪心 — 可中断任务的渐进精度+截止期限保证
# ensemble_meta:     加权多数投票 — 多策略融合+多样性正则的元调度
__all__ += [
    "AnytimeTask", "AnytimeScheduler",
    "WeightedMajorityEnsemble",
]
_MODULE_MAP.update({
    "AnytimeTask": "anytime_scheduler", "Contract": "anytime_scheduler",
    "ContractScheduler": "anytime_scheduler", "AnytimeScheduler": "anytime_scheduler",
    "WeightedMajorityEnsemble": "ensemble_meta",
})

# 专利级拓展: 自动修复引擎 + 调用链追踪
# remediation_engine: 闭环修复动作生成 — 检测→诊断→修复→验证
# call_chain_tracer:  轻量调用链追踪 — 调度器组件的自动依赖图推断
__all__ += [
    "ActionType", "RemediationAction", "RemediationEngine",
    "Span", "CallChainTracer",
]
_MODULE_MAP.update({
    "ActionType": "remediation_engine",
    "RemediationAction": "remediation_engine",
    "RemediationEngine": "remediation_engine",
    "Span": "call_chain_tracer", "CallChainTracer": "call_chain_tracer",
})

# 专利级拓展: 零拷贝状态传输 + 概率状态机
__all__ += [
    "ZeroCopyStateBuffer", "ZeroCopyTaskState", "ZeroCopyTransfer",
    "ProbabilisticGuard", "ProbabilisticStateMachine",
]
_MODULE_MAP.update({
    "ZeroCopyStateBuffer": "zero_copy_state",
    "ZeroCopyTaskState": "zero_copy_state",
    "ZeroCopyTransfer": "zero_copy_state",
    "ProbabilisticGuard": "probabilistic_sm",
    "ProbabilisticStateMachine": "probabilistic_sm",
})

# 专利级拓展: 数据局部性放置 + 能力感知匹配
__all__ += [
    "DataLocalityTracker", "DataLocalityScheduler",
    "CapabilityVector", "TaskRequirement", "CapabilityAwareScheduler",
]
_MODULE_MAP.update({
    "DataLocalityTracker": "data_locality_placement",
    "DataLocalityScheduler": "data_locality_placement",
    "CapabilityVector": "capability_matching",
    "TaskRequirement": "capability_matching",
    "CapabilityAwareScheduler": "capability_matching",
})

# 专利级拓展: 推测复制管理 + 取消传播
__all__ += [
    "SpeculativeDuplicationManager",
    "CancelPropagationManager",
]
_MODULE_MAP.update({
    "SpeculativeDuplicationManager": "speculative_duplication",
    "CancelPropagationManager": "cancel_propagation",

    "TDigest": "quantile_tracker",
    "FTPLOnlineCache": "data_locality_placement",
    "GaussianDPCounter": "dp_metrics",
    "MomentsAccountant": "dp_metrics",
    "Contract": "anytime_scheduler",
    "ContractScheduler": "anytime_scheduler",
    "DecayingElasticSketch": "sketch_metrics",
    "KingmanDelayBound": "capacity_scheduler",
    "ImportanceSamplingSimulator": "arrival_simulator",
    "CounterfactualOutcomeModel": "remediation_engine",
})
