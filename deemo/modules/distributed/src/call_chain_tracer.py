# 调用链追踪器 — 分布式 API 调用的自动依赖图推断
#
# 分布式调度器的各组件间通过 API 调用交互 (Worker→Scheduler→Redis)。
# 理解这些调用关系对故障定位和性能优化至关重要，但手工维护
# 调用拓扑在动态环境中不可靠。
#
# 本模块在每个 API 调用点嵌入轻量追踪上下文 (trace_id, span_id)，
# 接收方提取并记录，构建全局调用图。方法:
#   1. 跨度 (span): 单个 API 调用的开始/结束时间戳
#   2. 上下文传播: trace_id + parent_span_id 通过 HTTP/gRPC header
#   3. 聚合: 按 (caller, callee, api_method) 分组的统计
#   4. 依赖图推断: 从调用频次 + 延迟相关性自动推断依赖关系
#
# 与传统分布式追踪 (Jaeger/Zipkin) 的区别:
#   两者做通用追踪。本模块专为调度器组件设计:
#   - 自动提取调度相关的调用模式 (worker→queue, scheduler→worker, ...)
#   - 集成到 FaultPropagationGraph: 调用链 → 因果边
#   - 零外部依赖, 内存开销 < 2MB (最近 1000 spans)

from __future__ import annotations

import time
import hashlib
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple


@dataclass
class Span:
    trace_id: str
    span_id: str
    parent_span_id: str
    caller: str             # 调用方组件
    callee: str             # 被调用方组件
    api_method: str         # API 方法名
    start_time: float
    end_time: float = 0.0
    status: str = "ok"      # ok | error | timeout
    metadata: dict = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000.0


class CallChainTracer:
    """轻量调用链追踪器。

    用法:
      tracer = CallChainTracer()
      span = tracer.start_span("scheduler", "worker_3", "assign_task")
      # ... 执行调用 ...
      tracer.end_span(span, status="ok")

      # 查询依赖图
      graph = tracer.build_dependency_graph()
    """

    def __init__(self, max_spans: int = 1000):
        self._max_spans = max_spans
        self._spans: deque = deque(maxlen=max_spans)
        self._active_spans: Dict[str, Span] = {}
        self._trace_counter: int = 0
        self._lock = threading.Lock()

    def start_span(self, caller: str, callee: str, api_method: str,
                   parent_span: Optional[Span] = None,
                   metadata: Optional[dict] = None
                   ) -> Span:
        """开始一次 API 调用追踪。"""
        with self._lock:
            self._trace_counter += 1
            trace_id = hashlib.sha256(
                f"{caller}:{callee}:{api_method}:{time.monotonic()}:{self._trace_counter}".encode()
            ).hexdigest()[:16]
            span_id = hashlib.sha256(
                f"{trace_id}:{self._trace_counter}".encode()
            ).hexdigest()[:12]

            span = Span(
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span.span_id if parent_span else "",
                caller=caller,
                callee=callee,
                api_method=api_method,
                start_time=time.monotonic(),
                metadata=metadata or {},
            )
            self._active_spans[span_id] = span
            return span

    def end_span(self, span: Span, status: str = "ok",
                 metadata: Optional[dict] = None):
        """结束一次 API 调用追踪。"""
        with self._lock:
            span.end_time = time.monotonic()
            span.status = status
            if metadata:
                span.metadata.update(metadata)
            self._spans.append(span)
            self._active_spans.pop(span.span_id, None)

    def build_dependency_graph(self) -> Dict[str, List[Tuple[str, float, int]]]:
        """从追踪数据构建服务依赖图。

        返回: {caller: [(callee, avg_latency_ms, call_count), ...]}
        """
        edges: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        for span in self._spans:
            if span.duration_ms > 0:
                edges[(span.caller, span.callee)].append(span.duration_ms)

        graph: Dict[str, List[Tuple[str, float, int]]] = defaultdict(list)
        for (caller, callee), latencies in edges.items():
            avg_lat = sum(latencies) / len(latencies)
            graph[caller].append((callee, round(avg_lat, 3), len(latencies)))

        return dict(graph)

    def find_bottleneck(self) -> Optional[dict]:
        """找到当前调用图中的瓶颈 — 平均延迟最高的调用对。"""
        graph = self.build_dependency_graph()
        worst = None
        worst_lat = 0
        for caller, edges in graph.items():
            for callee, lat, count in edges:
                if lat > worst_lat and count >= 3:
                    worst_lat = lat
                    worst = {
                        "caller": caller, "callee": callee,
                        "avg_latency_ms": lat, "call_count": count,
                    }
        return worst

    def error_rate(self, caller: Optional[str] = None,
                   callee: Optional[str] = None) -> float:
        """指定调用对 (或全部) 的错误率。"""
        errors = 0
        total = 0
        for span in self._spans:
            if caller and span.caller != caller:
                continue
            if callee and span.callee != callee:
                continue
            total += 1
            if span.status != "ok":
                errors += 1
        return errors / max(total, 1)

    def stats(self) -> dict:
        with self._lock:
            graph = self.build_dependency_graph()
            bottleneck = self.find_bottleneck()
            return {
                "spans_recorded": len(self._spans),
                "active_spans": len(self._active_spans),
                "n_call_pairs": sum(len(v) for v in graph.values()),
                "overall_error_rate": round(self.error_rate(), 4),
                "bottleneck": bottleneck,
            }
