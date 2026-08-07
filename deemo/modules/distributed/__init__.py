# distributed/ 分布式任务调度对外接口
# 基于 __getattr__ 懒加载：不引用不导入，降低冷启动开销
# 同时暴露 src/ 和 Worker 的扁平命名空间
#
# 热路径符号（Worker/Task/Node）预加载，避免 __getattr__ 首次访问延迟
# 其余按需加载，模块级别 __getattr__ 仅在属性未命中时触发（PEP 562）

import importlib

__all__ = [
    # worker
    "Worker", "WorkerConfig", "AnalysisJob", "JobResult",
    # models
    "Task", "Node", "TaskStatus", "TaskType",
    # utils
    "retry", "backoff_delay", "setup_logging",
    # serialization
    "serialize", "deserialize",
    # priority
    "PriorityTaskQueue", "RedisPriorityQueue", "DeadLetterQueue",
    # scheduler
    "CronScheduler", "CronExpr", "parse_cron", "every",
    # batch
    "BatchCollector", "BatchPipeline",
    # circuit_breaker
    "CircuitState", "CircuitBreaker", "MultiBreaker", "SlidingWindowBreaker",
    # rate_limiter
    "TokenBucket", "DistributedTokenBucket", "ConcurrencyLimiter",
    "rate_limit", "RateLimitExceeded",
    # idempotency
    "IdempotencyGuard", "idempotency_key",
    # health
    "HealthServer", "HealthStatus",
    # pool
    "RedisPool",
    # metrics
    "Counter", "Gauge", "Histogram", "Summary", "Registry",
    # 2026-08 广度拓展
    # load_balancer
    "LoadBalancer", "ConsistentHashRing", "SelectorNode",
    # elastic_pool
    "ElasticPool", "ThresholdScalePolicy", "PredictiveScalePolicy",
    # adaptive_breaker
    "AdaptiveCircuitBreaker", "FractionalCircuitBreaker",
    # backpressure
    "BackpressureController", "BackpressureSignal", "BackpressureBlocked",
    # pipeline
    "Pipeline", "PipelineRunner", "PipelineExecutor", "Stage", "FanInCollector",
    # partition
    "PartitionManager", "HashPartitioner", "RangePartitioner", "RoundRobinPartitioner",
    # graceful_shutdown
    "GracefulShutdown", "ShutdownPhase",
    # state_machine
    "TaskStateMachine", "TransitionTable", "StateMachineBuilder", "InvalidTransition",
    # watermark
    "WatermarkMonitor", "MultiQueueWatermark", "FlowController",
    # node_registry
    "NodeRegistry", "NodeRecord", "RedisDiscovery", "GossipDiscovery", "StaticDiscovery",
    # 2026-08 故障恢复与自适应容错
    "FaultPropagationGraph", "FaultSignal", "RootCauseCandidate",
    "fault_signals_from_breakers",
    "RescheduleOracle", "reschedule_after_fault",
    "SpeculativeExecutor", "CriticalPathTracker", "SpeculationRecord",
    "AdaptiveCheckpointController", "CheckpointRecord", "FailureRecord",
    "JointBudgetController",
]

_MODULE_MAP: dict[str, str] = {
    "Worker": ".worker", "WorkerConfig": ".worker",
    "AnalysisJob": ".worker", "JobResult": ".worker",
    # src.
    "Task": ".src.models", "Node": ".src.models",
    "TaskStatus": ".src.models", "TaskType": ".src.models",
    "retry": ".src.utils", "backoff_delay": ".src.utils",
    "setup_logging": ".src.utils",
    "serialize": ".src.serialization", "deserialize": ".src.serialization",
    "PriorityTaskQueue": ".src.priority", "RedisPriorityQueue": ".src.priority",
    "DeadLetterQueue": ".src.priority",
    "CronScheduler": ".src.scheduler", "CronExpr": ".src.scheduler",
    "parse_cron": ".src.scheduler", "every": ".src.scheduler",
    "BatchCollector": ".src.batch", "BatchPipeline": ".src.batch",
    "CircuitState": ".src.circuit_breaker", "CircuitBreaker": ".src.circuit_breaker",
    "MultiBreaker": ".src.circuit_breaker", "SlidingWindowBreaker": ".src.circuit_breaker",
    "TokenBucket": ".src.rate_limiter", "DistributedTokenBucket": ".src.rate_limiter",
    "ConcurrencyLimiter": ".src.rate_limiter",
    "rate_limit": ".src.rate_limiter", "RateLimitExceeded": ".src.rate_limiter",
    "IdempotencyGuard": ".src.idempotency", "idempotency_key": ".src.idempotency",
    "HealthServer": ".src.health", "HealthStatus": ".src.health",
    "RedisPool": ".src.pool",
    "Counter": ".src.metrics", "Gauge": ".src.metrics",
    "Histogram": ".src.metrics", "Summary": ".src.metrics",
    "Registry": ".src.metrics",
    # 2026-08 拓展
    "LoadBalancer": ".src.load_balancer", "ConsistentHashRing": ".src.load_balancer",
    "SelectorNode": ".src.load_balancer",
    "ElasticPool": ".src.elastic_pool", "ThresholdScalePolicy": ".src.elastic_pool",
    "PredictiveScalePolicy": ".src.elastic_pool",
    "AdaptiveCircuitBreaker": ".src.adaptive_breaker",
    "FractionalCircuitBreaker": ".src.adaptive_breaker",
    "BackpressureController": ".src.backpressure",
    "BackpressureSignal": ".src.backpressure", "BackpressureBlocked": ".src.backpressure",
    "Pipeline": ".src.pipeline", "PipelineRunner": ".src.pipeline",
    "PipelineExecutor": ".src.pipeline", "Stage": ".src.pipeline",
    "FanInCollector": ".src.pipeline",
    "PartitionManager": ".src.partition", "HashPartitioner": ".src.partition",
    "RangePartitioner": ".src.partition", "RoundRobinPartitioner": ".src.partition",
    "GracefulShutdown": ".src.graceful_shutdown", "ShutdownPhase": ".src.graceful_shutdown",
    "TaskStateMachine": ".src.state_machine", "TransitionTable": ".src.state_machine",
    "StateMachineBuilder": ".src.state_machine", "InvalidTransition": ".src.state_machine",
    "WatermarkMonitor": ".src.watermark", "MultiQueueWatermark": ".src.watermark",
    "FlowController": ".src.watermark",
    "NodeRegistry": ".src.node_registry", "NodeRecord": ".src.node_registry",
    "RedisDiscovery": ".src.node_registry", "GossipDiscovery": ".src.node_registry",
    "StaticDiscovery": ".src.node_registry",
    # 2026-08 故障恢复与自适应容错
    "FaultPropagationGraph": ".src.fault_propagation",
    "FaultSignal": ".src.fault_propagation",
    "RootCauseCandidate": ".src.fault_propagation",
    "fault_signals_from_breakers": ".src.fault_propagation",
    "RescheduleOracle": ".src.reschedule_oracle",
    "reschedule_after_fault": ".src.reschedule_oracle",
    "SpeculativeExecutor": ".src.speculative_exec",
    "CriticalPathTracker": ".src.speculative_exec",
    "SpeculationRecord": ".src.speculative_exec",
    "AdaptiveCheckpointController": ".src.adaptive_checkpoint",
    "CheckpointRecord": ".src.adaptive_checkpoint",
    "FailureRecord": ".src.adaptive_checkpoint",
    "JointBudgetController": ".src.adaptive_checkpoint",
}

_CACHE: dict[str, object] = {}

# 热路径预加载 — worker 和 models 在绝大多数导入路径中首先被访问
try:
    from . import worker as _worker_mod
    _CACHE[".worker"] = _worker_mod
    from .src import models as _models_mod
    _CACHE[".src.models"] = _models_mod
except ImportError:
    pass


def __getattr__(name: str):
    if name in _MODULE_MAP:
        mod_path = _MODULE_MAP[name]
        if mod_path not in _CACHE:
            _CACHE[mod_path] = importlib.import_module(
                mod_path, package=__package__
            )
        return getattr(_CACHE[mod_path], name)
    raise AttributeError("module {} has no attribute {}".format(__name__, name))


# GRL-Sched 拓展
# 追加注册 — 保持既有映射不变，仅扩展懒加载表与符号导出
# GRL-Sched: 图强化学习任务调度 + 动态图划分
# 论文: GraphEdge — [待验证]
__all__ += [
    "TaskDependencyGraph", "TaskNode", "DependencyEdge",
    "GraphPartitioner", "Partition",
    "GNNEncoder", "GRLScheduler", "SimulatedAnnealingScheduler",
    "MakespanSimulator", "LinearQPolicy",
    "DependencyAwareScheduler", "heft_rank", "heft_order", "grl_schedule",
]
_MODULE_MAP.update({
    "TaskDependencyGraph": ".src.grl_graph", "TaskNode": ".src.grl_graph",
    "DependencyEdge": ".src.grl_graph",
    "GraphPartitioner": ".src.grl_partition", "Partition": ".src.grl_partition",
    "GNNEncoder": ".src.grl_scheduler", "GRLScheduler": ".src.grl_scheduler",
    "SimulatedAnnealingScheduler": ".src.grl_scheduler",
    "MakespanSimulator": ".src.grl_scheduler", "LinearQPolicy": ".src.grl_scheduler",
    "DependencyAwareScheduler": ".src.grl_scheduler",
    "heft_rank": ".src.grl_scheduler", "heft_order": ".src.grl_scheduler",
    "grl_schedule": ".src.grl_scheduler",
})

# 故障自愈拓展 — 因果传播 + 增量调度 + 投机 + 自适应检查点
# 各符号注册在上方 _MODULE_MAP 与 __all__ 中已完成

# 专利级拓展: 鲁棒GNN + 反事实谕示 + 时序超图 + 共形预测
# 随机平滑认证的 GNN 编码器 / Pearl do-calculus 调度恢复 / 时序超图卷积 / 共形预测滞后检测
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
    "RobustGNNCertifier": ".src.robust_gnn", "RobustSchedulerMixin": ".src.robust_gnn",
    "SchedulingStructuralCausalModel": ".src.counterfactual_oracle",
    "CounterfactualSchedulingOracle": ".src.counterfactual_oracle",
    "CounterfactualReport": ".src.counterfactual_oracle",
    "TemporalHypergraph": ".src.temporal_hypergraph",
    "TemporalHypergraphConv": ".src.temporal_hypergraph",
    "hypergraph_augmented_features": ".src.temporal_hypergraph",
    "ConformalStragglerPredictor": ".src.conformal_straggler",
    "OnlineQuantileEstimator": ".src.conformal_straggler",
    "ConformalPrediction": ".src.conformal_straggler",
    "ConformalSpeculationGate": ".src.conformal_straggler",
})

# 专利级拓展: Lyapunov碳调度 + 死锁验证 + 在线预测 + 调度自监控
# 李雅普诺夫碳感知准入 / 资源分配图死锁验证 / 自适应RLS执行时间预测 / 非参数CUSUM健康监控
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
    "LyapunovCarbonGate": ".src.lyapunov_carbon",
    "CarbonIntensityProvider": ".src.lyapunov_carbon",
    "AdmissionDecision": ".src.lyapunov_carbon",
    "CarbonMetrics": ".src.lyapunov_carbon",
    "carbon_aware_submit": ".src.lyapunov_carbon",
    "DeadlockVerifier": ".src.deadlock_verifier",
    "ResourceSpec": ".src.deadlock_verifier",
    "DeadlockReport": ".src.deadlock_verifier",
    "AdaptiveRLS": ".src.online_predictor",
    "TaskTimePredictor": ".src.online_predictor",
    "SchedulerHealthMonitor": ".src.scheduler_monitor",
    "NonparametricCUSUM": ".src.scheduler_monitor",
    "DegradationLevel": ".src.scheduler_monitor",
    "SchedulerSnapshot": ".src.scheduler_monitor",
    "snapshot_from_metrics": ".src.scheduler_monitor",
})

# 专利级拓展: 最优传输分配 + 纳什公平调度 + 管线重物质化 + 差分隐私
# Sinkhorn最优传输任务分配 / 多租户纳什均衡公平调度 / 管线重物质化检查点 / ε-差分隐私度量
__all__ += [
    "sinkhorn_assign", "OTAssigner",
    "NashFairScheduler", "TenantBid", "NashAllocation",
    "PipelineRematOptimizer", "RematDecision", "RematPlan",
    "DPCounter", "DPGauge", "DPHistogram",
    "DPPrivacyBudget", "DPMetricsCollector",
]
_MODULE_MAP.update({
    "sinkhorn_assign": ".src.ot_assigner", "OTAssigner": ".src.ot_assigner",
    "NashFairScheduler": ".src.nash_fair_scheduler",
    "TenantBid": ".src.nash_fair_scheduler",
    "NashAllocation": ".src.nash_fair_scheduler",
    "PipelineRematOptimizer": ".src.pipeline_remat",
    "RematDecision": ".src.pipeline_remat", "RematPlan": ".src.pipeline_remat",
    "DPCounter": ".src.dp_metrics", "DPGauge": ".src.dp_metrics",
    "DPHistogram": ".src.dp_metrics", "DPPrivacyBudget": ".src.dp_metrics",
    "DPMetricsCollector": ".src.dp_metrics",
})

# 专利级拓展: 因果发现 + PID伸缩 + 自适应负载均衡 + 拜占庭窃取
# Granger+转移熵因果依赖发现 / PID控制论弹性伸缩 / 自适应Power-of-d负载均衡 / 见证人BFT工作窃取
__all__ += [
    "transfer_entropy", "CausalDependencyDiscoverer",
    "PIDAutoscaler", "ziegler_nichols_tune",
    "AdaptivePowerOfD",
    "ByzantineResilientStealing", "StealTransaction", "NodeReputation",
]
_MODULE_MAP.update({
    "transfer_entropy": ".src.causal_discovery",
    "CausalDependencyDiscoverer": ".src.causal_discovery",
    "PIDAutoscaler": ".src.pid_autoscaler",
    "ziegler_nichols_tune": ".src.pid_autoscaler",
    "AdaptivePowerOfD": ".src.adaptive_load_balancer",
    "ByzantineResilientStealing": ".src.byzantine_stealing",
    "StealTransaction": ".src.byzantine_stealing",
    "NodeReputation": ".src.byzantine_stealing",
})

# 专利级拓展: 草图度量 + 活性验证 + 对抗老虎机 + 联邦蒸馏
# Count-Min+HLL亚线性度量 / 运行时LTL活性验证 / EXP3-IX对抗老虎机 / 联邦策略蒸馏
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
    "CountMinSketch": ".src.sketch_metrics",
    "HyperLogLog": ".src.sketch_metrics",
    "SketchMetrics": ".src.sketch_metrics",
    "LivenessMonitor": ".src.liveness_checker",
    "LivenessProperty": ".src.liveness_checker",
    "LivenessVerdict": ".src.liveness_checker",
    "starvation_freedom_property": ".src.liveness_checker",
    "progress_property": ".src.liveness_checker",
    "no_livelock_property": ".src.liveness_checker",
    "EXP3IX": ".src.adversarial_bandits",
    "AdversarialBanditScheduler": ".src.adversarial_bandits",
    "PolicyTeacher": ".src.federated_distill",
    "FederatedDistillationAggregator": ".src.federated_distill",
    "PolicyStudent": ".src.federated_distill",
    "federated_round": ".src.federated_distill",
})

# 专利级拓展: EVT尾部 + Hawkes到达 + OCO权重 + 谱划分
# GPD极值尾部预测 / Hawkes自激到达模型 / 在线凸优化权重自整定 / Fiedler向量谱划分
__all__ += [
    "fit_gpd_mle", "EVTTailPredictor",
    "HawkesArrivalModel",
    "OCOWeightOptimizer", "OCOSchedulingAdapter",
    "SpectralPartitioner",
]
_MODULE_MAP.update({
    "fit_gpd_mle": ".src.evt_tail", "EVTTailPredictor": ".src.evt_tail",
    "HawkesArrivalModel": ".src.hawkes_arrival",
    "OCOWeightOptimizer": ".src.oco_scheduler",
    "OCOSchedulingAdapter": ".src.oco_scheduler",
    "SpectralPartitioner": ".src.spectral_partition",
})

# ===== 专利级拓展: Wasserstein DRO + 分位数追踪 + MoE门控 + FTRL检查点 =====
# Wasserstein分布鲁棒调度 / 在线单调分位数追踪 / 混合专家策略门控 / FTRL遗憾最优检查点
__all__ += [
    "wasserstein1", "wasserstein_radius", "WassersteinRobustScheduler",
    "OnlineQuantileTracker",
    "MoEGatingNetwork", "MixtureOfExpertsScheduler",
    "FTRLCheckpointController",
]
_MODULE_MAP.update({
    "wasserstein1": ".src.wasserstein_dro",
    "wasserstein_radius": ".src.wasserstein_dro",
    "WassersteinRobustScheduler": ".src.wasserstein_dro",
    "OnlineQuantileTracker": ".src.quantile_tracker",
    "MoEGatingNetwork": ".src.mixture_experts",
    "MixtureOfExpertsScheduler": ".src.mixture_experts",
    "FTRLCheckpointController": ".src.regret_checkpoint",
})

# 专利级拓展: PAC-Bayes认证 + 切换代价优化 + 容量约束调度
# PAC-贝叶斯调度策略泛化认证 / L1稀疏切换代价在线优化 / 容量约束优先级隔离调度
__all__ += [
    "catoni_bound", "PACBayesCertifier",
    "SwitchingCostOptimizer",
    "CapacityConfig", "QueuedTask", "CapacityConstrainedScheduler",
]
_MODULE_MAP.update({
    "catoni_bound": ".src.pac_bayes_cert",
    "PACBayesCertifier": ".src.pac_bayes_cert",
    "SwitchingCostOptimizer": ".src.switching_cost_opt",
    "CapacityConfig": ".src.capacity_scheduler",
    "QueuedTask": ".src.capacity_scheduler",
    "CapacityConstrainedScheduler": ".src.capacity_scheduler",
})

# 专利级拓展: 学习型优先级 + 贝叶斯熔断 + 流行病Gossip溯源
# CDF学习型优先队列 / BOCD贝叶斯变点熔断 / 谣言中心性Gossip溯源
__all__ += [
    "PiecewiseLinearCDF", "LearnedPriorityQueue",
    "BOCDDetector", "BayesianCircuitBreaker",
    "GossipTrace", "EpidemicSourceDetector",
]
_MODULE_MAP.update({
    "PiecewiseLinearCDF": ".src.learned_priority",
    "LearnedPriorityQueue": ".src.learned_priority",
    "BOCDDetector": ".src.bayesian_breaker",
    "BayesianCircuitBreaker": ".src.bayesian_breaker",
    "GossipTrace": ".src.epidemic_gossip",
    "EpidemicSourceDetector": ".src.epidemic_gossip",
})

# 专利级拓展: 压缩共识 + 到达模拟器
# QSGD随机量化状态压缩共识 / 别名法离散事件到达模拟
__all__ += [
    "qsgd_compress", "qsgd_decompress", "compression_ratio",
    "CompressedConsensus",
    "AliasSampler", "DiscreteEventSimulator",
]
_MODULE_MAP.update({
    "qsgd_compress": ".src.compressed_consensus",
    "qsgd_decompress": ".src.compressed_consensus",
    "compression_ratio": ".src.compressed_consensus",
    "CompressedConsensus": ".src.compressed_consensus",
    "AliasSampler": ".src.arrival_simulator",
    "DiscreteEventSimulator": ".src.arrival_simulator",
})

# 专利级拓展: Anytime部分结果 + 集成元调度
# 可中断渐进精度截止期限调度 / 加权多数投票多策略集成
__all__ += [
    "AnytimeTask", "AnytimeScheduler",
    "WeightedMajorityEnsemble",
]
_MODULE_MAP.update({
    "AnytimeTask": ".src.anytime_scheduler",
    "AnytimeScheduler": ".src.anytime_scheduler",
    "WeightedMajorityEnsemble": ".src.ensemble_meta",
})

# 专利级拓展: 自动修复引擎 + 调用链追踪
# 闭环故障修复动作生成+风险评估 / 轻量分布式调用链追踪+依赖图推断
__all__ += [
    "ActionType", "RemediationAction", "RemediationEngine",
    "Span", "CallChainTracer",
]
_MODULE_MAP.update({
    "ActionType": ".src.remediation_engine",
    "RemediationAction": ".src.remediation_engine",
    "RemediationEngine": ".src.remediation_engine",
    "Span": ".src.call_chain_tracer",
    "CallChainTracer": ".src.call_chain_tracer",
})
# 推测复制 / 数据局部性 / 能力匹配
__all__ += [
    "SpeculativeDuplicationManager",
    "DataLocalityTracker", "DataLocalityScheduler",
    "CapabilityVector", "TaskRequirement", "CapabilityAwareScheduler",
]
_MODULE_MAP.update({
    "SpeculativeDuplicationManager": ".src.speculative_duplication",
    "DataLocalityTracker": ".src.data_locality_placement",
    "DataLocalityScheduler": ".src.data_locality_placement",
    "CapabilityAwareScheduler": ".src.capability_matching",
    "CapabilityVector": ".src.capability_matching",
    "TaskRequirement": ".src.capability_matching",
})

# 专利级拓展: 零拷贝状态传输 + 概率状态机
__all__ += [
    "ZeroCopyStateBuffer", "ZeroCopyTaskState", "ZeroCopyTransfer",
    "ProbabilisticGuard", "ProbabilisticStateMachine",
]
_MODULE_MAP.update({
    "ZeroCopyStateBuffer": ".src.zero_copy_state",
    "ZeroCopyTaskState": ".src.zero_copy_state",
    "ZeroCopyTransfer": ".src.zero_copy_state",
    "ProbabilisticGuard": ".src.probabilistic_sm",
    "ProbabilisticStateMachine": ".src.probabilistic_sm",
})

# 专利级拓展: 推测复制管理 + 取消传播
# 自适应副本数推测复制 / 频谱感知分布式取消传播
__all__ += [
    "SpeculativeDuplicationManager",
    "CancelPropagationManager",
]
_MODULE_MAP.update({
    "SpeculativeDuplicationManager": ".src.speculative_duplication",
    "CancelPropagationManager": ".src.cancel_propagation",

    "TDigest": ".src.quantile_tracker",
    "FTPLOnlineCache": ".src.data_locality_placement",
    "GaussianDPCounter": ".src.dp_metrics",
    "MomentsAccountant": ".src.dp_metrics",
    "Contract": ".src.anytime_scheduler",
    "ContractScheduler": ".src.anytime_scheduler",
    "DecayingElasticSketch": ".src.sketch_metrics",
    "KingmanDelayBound": ".src.capacity_scheduler",
    "ImportanceSamplingSimulator": ".src.arrival_simulator",
    "CounterfactualOutcomeModel": ".src.remediation_engine",
})
