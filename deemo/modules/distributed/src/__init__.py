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
    # —— 2026-08 广度拓展 ——
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
    # —— 2026-08 故障恢复与自适应容错 ——
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


# ===== GRL-Sched 拓展 (2026-08-03) =====
# 追加注册 — 保持既有映射不变，仅扩展懒加载表与符号导出
# GRL-Sched: 图强化学习任务调度 + 动态图划分
# 论文: GraphEdge — arXiv:2504.15905
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

# ===== 故障自愈与自适应容错拓展 (2025-07-16 → 2025-07-29) =====
# 因果故障传播 + 增量重调度 + 关键路径投机 + 自适应检查点
# 论文: DynaCausal (arXiv:2510.22613) / IDI (arXiv:2505.00930)
#       EFTR-HGNet (IEEE IoT-J 2025) / SPARe (arXiv:2603.00357)
# 这些模块已在上方 __all__ 与 _MODULE_MAP 中注册，此处不重复追加
