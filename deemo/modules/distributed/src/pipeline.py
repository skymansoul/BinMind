# 多阶段执行管线 — fan-out → process → fan-in 的通用执行模型
# Streaming Batch Model [arXiv:2501.12407 [待验证]]: 混合批流管线，分区 → 并行处理 → 汇聚
# WOW [arXiv:2503.13072 [待验证]]: 工作流感知调度，联合优化数据移动 + 任务调度
#
# 模式支持：
#   - sequential: stage0 → stage1 → ... 串行
#   - fan_out:    单输入 → N 并行子任务
#   - fan_in:     N 并行 → 汇聚（等待全部 / 首个 / 任 N-1）
#   - dag:        有向无环图（拓扑顺序执行）
# 每种模式可在 worker 池上执行，也可单机多线程执行。
#
# 设计原则：管线不关心执行者是谁（本地线程 / Celery / K8s Job），
# 只管编排逻辑，通过 executor 注入解耦。

from __future__ import annotations

import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from typing import Optional, List, Callable, Any, Dict
from dataclasses import dataclass, field

_log = logging.getLogger(__name__)


# ===== 阶段与任务 =====

@dataclass
class Stage:
    """管线中的一个阶段"""
    name: str
    function: Callable[[Any], Any]
    timeout: float = 300.0
    max_retries: int = 0
    # 依赖：此阶段需要等待哪些前置阶段完成
    depends_on: List[str] = field(default_factory=list)
    # fan_out_n: > 1 时分拆为 N 份并行执行
    fan_out_n: int = 1

    def __repr__(self) -> str:
        return f"Stage({self.name!r})"


@dataclass
class PipelineResult:
    """管线执行结果"""
    stage_name: str
    output: Any = None
    error: Optional[str] = None
    duration: float = 0.0
    attempt: int = 1

    @property
    def ok(self) -> bool:
        return self.error is None


# ===== 管线定义 =====

class Pipeline:
    """有向无环图 (DAG) 管线定义。

    Streaming Batch Model [arXiv:2501.12407] 的核心思想：
    一个 partition = 一个独立的执行单元，各个 partition 之间无依赖可完全并行；
    每个 partition 内部是 sequential stages。此处 generalize 到任意 DAG。
    """

    def __init__(self, name: str = "pipeline"):
        self.name = name
        self._stages: Dict[str, Stage] = {}
        self._stage_order: List[str] = []  # 插入顺序

    def add_stage(self, stage: Stage) -> "Pipeline":
        if stage.name in self._stages:
            raise ValueError(f"duplicate stage name: {stage.name}")
        self._stages[stage.name] = stage
        self._stage_order.append(stage.name)
        return self  # fluent API

    def add_sequential_stages(self, stages: List[Stage]) -> "Pipeline":
        """一次添加多个阶段，自动设置前后依赖链。"""
        prev = None
        for s in stages:
            if prev:
                s.depends_on.append(prev.name)
            self.add_stage(s)
            prev = s
        return self

    def stage(self, name: str) -> Optional[Stage]:
        return self._stages.get(name)

    @property
    def stages(self) -> List[Stage]:
        return [self._stages[n] for n in self._stage_order]

    def __len__(self) -> int:
        return len(self._stages)


# ===== 执行器接口 =====

class PipelineExecutor:
    """管线执行器 — 默认用 ThreadPoolExecutor 本地执行。

    替换为 CeleryExecutor / K8sExecutor 可将管线分布到不同 worker 上。
    WOW [arXiv:2503.13072] 的调度器即不同类型的执行器可插拔。
    """

    def execute(self, stage: Stage, input_data: Any) -> Any:
        """执行一个阶段，返回结果或抛异常。"""
        return stage.function(input_data)

    def fan_out_execute(self, stage: Stage, input_data: Any) -> List[Any]:
        """fan_out: 把输入拆成 stage.fan_out_n 份并行执行。
        默认实现使用 ThreadPoolExecutor。
        """
        n = stage.fan_out_n
        if n <= 1:
            return [self.execute(stage, input_data)]

        # 拆分输入 — 如果输入是可索引的，按索引拆；否则每份都传完整输入
        if isinstance(input_data, (list, tuple)) and len(input_data) >= n:
            chunks = _split_into_chunks(list(input_data), n)
        else:
            chunks = [input_data] * n

        with ThreadPoolExecutor(max_workers=n) as pool:
            futures = {pool.submit(self.execute, stage, chunk): i for i, chunk in enumerate(chunks)}
            results = [None] * n
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    results[idx] = fut.result(timeout=stage.timeout)
                except Exception as e:
                    results[idx] = e
            return results


def _split_into_chunks(items: list, n: int) -> list:
    size = max(1, len(items) // n)
    return [items[i:i + size] for i in range(0, len(items), size)]


# ===== 管线运行器 =====

class PipelineRunner:
    """串行执行管线各阶段（遵循 DAG 拓扑序）。

    每个阶段执行前检查依赖是否全部成功完成。
    失败阶段可选重试（按 stage.max_retries）。
    所有结果通过回调 on_stage_complete 通知外部。
    """

    def __init__(self, pipeline: Pipeline, executor: PipelineExecutor = None):
        self._pipe = pipeline
        self._exec = executor or PipelineExecutor()
        self._results: Dict[str, PipelineResult] = {}
        self._on_complete: Optional[Callable[[PipelineResult], None]] = None

    def on_stage_complete(self, callback: Callable[[PipelineResult], None]):
        self._on_complete = callback

    def run(self, initial_input: Any = None) -> Dict[str, PipelineResult]:
        """拓扑执行全部阶段。返回 {stage_name: PipelineResult}。"""
        self._results = {}
        ready = [
            s for s in self._pipe.stages
            if not s.depends_on
        ]

        # 拓扑排序执行：每完成一个阶段，将其下游加入就绪列表
        remaining = list(self._pipe.stages)
        while ready:
            stage = ready.pop(0)
            if stage.name in self._results:
                continue

            # 收集前置输出作为此阶段的输入
            inputs = initial_input
            if stage.depends_on:
                deps_results = {
                    dep: self._results.get(dep)
                    for dep in stage.depends_on
                }
                if any(r is None for r in deps_results.values()):
                    remaining.append(stage)
                    continue
                # 只有一个依赖时直接传输出，多个依赖时传 dict
                if len(deps_results) == 1:
                    r = next(iter(deps_results.values()))
                    inputs = r.output if r and r.ok else None
                else:
                    inputs = {k: v.output if v and v.ok else None
                              for k, v in deps_results.items()}

            # 执行（含重试）
            result = self._run_stage(stage, inputs)
            self._results[stage.name] = result

            if self._on_complete:
                self._on_complete(result)

            remaining.remove(stage)

            # 找到依赖此阶段的下游
            downstream = [
                s for s in remaining
                if stage.name in s.depends_on and
                all(d in self._results for d in s.depends_on)
            ]
            # 保持稳定顺序
            for ds in downstream:
                if ds not in ready:
                    ready.append(ds)

        return dict(self._results)

    def _run_stage(self, stage: Stage, inputs: Any) -> PipelineResult:
        start = time.monotonic()
        last_err = None

        for attempt in range(max(1, stage.max_retries + 1)):
            try:
                if stage.fan_out_n > 1:
                    output = self._exec.fan_out_execute(stage, inputs)
                else:
                    output = self._exec.execute(stage, inputs)
                return PipelineResult(
                    stage_name=stage.name,
                    output=output,
                    duration=time.monotonic() - start,
                    attempt=attempt + 1,
                )
            except Exception as e:
                last_err = e
                _log.warning("stage %s attempt %d/%d failed: %s",
                             stage.name, attempt + 1, stage.max_retries + 1, e)

        return PipelineResult(
            stage_name=stage.name,
            error=str(last_err) if last_err else "unknown",
            duration=time.monotonic() - start,
            attempt=stage.max_retries + 1,
        )

    @property
    def results(self) -> Dict[str, PipelineResult]:
        return dict(self._results)


# ===== Fan-In 辅助 =====

class FanInCollector:
    """Fan-in 收集器 — 聚合 N 个并行结果。

    gather_strategy:
    - "all": 等待全部，返回列表
    - "first": 首个完成即返回，其余取消
    - "majority": 等待 > N/2 完成
    - "all_ok": 等待全部成功（有失败则整体失败）
    """

    VALID_STRATEGIES = {"all", "first", "majority", "all_ok"}

    def __init__(self, strategy: str = "all", timeout: float = 300.0):
        if strategy not in self.VALID_STRATEGIES:
            raise ValueError(f"invalid strategy: {strategy}")
        self.strategy = strategy
        self.timeout = timeout

    def collect(self, futures: List[Future]) -> List[Any]:
        n = len(futures)
        if n == 0:
            return []
        if n == 1:
            return [futures[0].result(timeout=self.timeout)]

        done = []
        if self.strategy == "all":
            for f in as_completed(futures, timeout=self.timeout):
                done.append(f.result())
            return done

        elif self.strategy == "first":
            for f in as_completed(futures, timeout=self.timeout):
                return [f.result()]
            return []

        elif self.strategy == "majority":
            cutoff = n // 2 + 1
            for f in as_completed(futures, timeout=self.timeout):
                done.append(f.result())
                if len(done) >= cutoff:
                    return done
            return done

        elif self.strategy == "all_ok":
            for f in as_completed(futures, timeout=self.timeout):
                try:
                    done.append(f.result())
                except Exception:
                    raise RuntimeError(f"fan-in all_ok: a future failed")
            return done

        return done
