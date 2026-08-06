# 统一Fuzzing编排器 — 将28个子模块串联为端到端自动化管道
#
# 核心问题:
#   28个模块各自独立运行——需要手动串联。缺乏统一的编排层使得
#   "一键启动完整fuzzing+分析管道"无法实现。
#
# 本模块提供:
#   1. 管道阶段定义: 准备→Fuzz→分析→分诊→报告
#   2. 模块注册: 按接口类型注册各模块
#   3. 配置驱动: YAML/JSON配置控制管道行为
#   4. 钩子机制: 每个阶段支持pre/post钩子 (自定义扩展点)
#
# 管道阶段:
#   Stage 1 PREP:  语法推断 → 字段分割 → API分析 → Harness生成
#   Stage 2 FUZZ:  种子调度 → 变异选择 → 执行 → 覆盖追踪
#   Stage 3 ANALYZE: 崩溃聚类 → 污点分析 → 利用评估 → 不变量检查
#   Stage 4 TRIAGE:  去重 → 分类 → 评分 → 融合判定
#   Stage 5 REPORT:  Markdown → JSON → 摘要输出
#
# 设计原则:
#   - 每个阶段有默认模块, 但可替换
#   - 模块间通过共享的 Blackboard 传递数据 (不直接耦合)
#   - 管道可部分运行: 仅fuzz / 仅分析 / 仅报告

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class Stage(str, Enum):
    PREP = "prep"
    FUZZ = "fuzz"
    ANALYZE = "analyze"
    TRIAGE = "triage"
    REPORT = "report"


@dataclass
class StageResult:
    stage: Stage
    success: bool = True
    duration_s: float = 0.0
    output: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class PipelineResult:
    stages: List[StageResult] = field(default_factory=list)
    total_duration_s: float = 0.0
    summary: str = ""


class Blackboard:
    """模块间数据共享——发布/订阅模式, 避免模块间直接耦合"""
    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._hooks: Dict[str, List[Callable]] = defaultdict(list)

    def put(self, key: str, value: Any) -> None:
        self._data[key] = value
        # 触发钩子
        for hook in self._hooks.get(key, []):
            try:
                hook(value)
            except Exception:
                pass

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def on(self, key: str, callback: Callable) -> None:
        self._hooks[key].append(callback)

    def snapshot(self) -> Dict[str, Any]:
        return dict(self._data)


class FuzzOrchestrator:
    """统一Fuzzing编排器。

    典型用法:
        orch = FuzzOrchestrator()
        orch.configure({'target': 'libpng.so', 'timeout': 3600})
        orch.add_stage_handler(Stage.PREP, my_prep_handler)
        result = orch.run(stages=[Stage.PREP, Stage.FUZZ, Stage.ANALYZE,
                                   Stage.TRIAGE, Stage.REPORT])
        print(result.summary)
    """

    def __init__(self):
        self._handlers: Dict[Stage, List[Callable]] = defaultdict(list)
        self._blackboard = Blackboard()
        self._config: Dict[str, Any] = {}
        # 注册默认处理器
        self._register_defaults()

    def configure(self, config: Dict[str, Any]) -> None:
        self._config = config
        self._blackboard.put('config', config)

    def add_stage_handler(self, stage: Stage,
                           handler: Callable[[Blackboard], Dict[str, Any]]
                           ) -> None:
        """为某阶段添加处理器——每个阶段可有多个处理器(按序执行)"""
        self._handlers[stage].append(handler)

    def run(self, stages: Optional[List[Stage]] = None) -> PipelineResult:
        """执行管道——按顺序执行各阶段"""
        if stages is None:
            stages = list(Stage)
        result = PipelineResult()
        t0 = time.perf_counter()

        for stage in stages:
            sr = self._run_stage(stage)
            result.stages.append(sr)
            self._blackboard.put(f'stage_{stage.value}_done', sr.success)
            if not sr.success:
                break

        result.total_duration_s = time.perf_counter() - t0
        result.summary = self._build_summary(result)
        return result

    def _run_stage(self, stage: Stage) -> StageResult:
        handlers = self._handlers.get(stage, [])
        if not handlers:
            return StageResult(stage=stage, success=True, duration_s=0.0,
                                output={}, error="无处理器")

        t0 = time.perf_counter()
        stage_output: Dict[str, Any] = {}
        for i, handler in enumerate(handlers):
            try:
                output = handler(self._blackboard)
                if output:
                    stage_output[f'handler_{i}'] = output
            except Exception as exc:
                return StageResult(
                    stage=stage, success=False,
                    duration_s=time.perf_counter() - t0,
                    output=stage_output, error=str(exc))

        return StageResult(
            stage=stage, success=True,
            duration_s=time.perf_counter() - t0,
            output=stage_output)

    def _register_defaults(self) -> None:
        """注册每个阶段的默认处理器 (占位——实际使用时替换)"""
        def _prep_default(bb: Blackboard) -> Dict[str, Any]:
            return {'status': 'prep_complete'}

        def _fuzz_default(bb: Blackboard) -> Dict[str, Any]:
            return {'status': 'fuzz_complete', 'crashes': 0}

        def _analyze_default(bb: Blackboard) -> Dict[str, Any]:
            return {'status': 'analyze_complete'}

        def _triage_default(bb: Blackboard) -> Dict[str, Any]:
            return {'status': 'triage_complete'}

        def _report_default(bb: Blackboard) -> Dict[str, Any]:
            return {'format': 'markdown'}

        self._handlers[Stage.PREP] = [_prep_default]
        self._handlers[Stage.FUZZ] = [_fuzz_default]
        self._handlers[Stage.ANALYZE] = [_analyze_default]
        self._handlers[Stage.TRIAGE] = [_triage_default]
        self._handlers[Stage.REPORT] = [_report_default]

    @staticmethod
    def _build_summary(result: PipelineResult) -> str:
        lines = ["Fuzzing管道执行报告", "-" * 40]
        for sr in result.stages:
            status = "✓" if sr.success else "✗"
            lines.append(
                f"  [{status}] {sr.stage.value}: {sr.duration_s:.1f}s"
                f"{' ERROR: ' + sr.error if sr.error else ''}")
        lines.append(f"  总耗时: {result.total_duration_s:.1f}s")
        return "\n".join(lines)

    def blackboard(self) -> Blackboard:
        return self._blackboard
