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

# ===== 故障自愈拓展 — 因果传播 + 增量调度 + 投机 + 自适应检查点 =====
# 各符号注册在上方 _MODULE_MAP 与 __all__ 中已完成
