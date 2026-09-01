"""
动态DAG编排器，运行时自适应扫描管道+BMA多源评分融合.

理论依据:
  Baird & Moin: HGAT+依赖图+漏洞链预测.
  Slyp: 可扩展MCP工具服务器+ReAct管道→DAG编排参考.
"""

from __future__ import annotations
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import logging
_log = logging.getLogger(__name__)


@dataclass
class DynamicScanTask:
    """动态扫描任务，运行时触发的新任务."""
    name: str
    runner: Callable
    trigger_condition: Callable[[Dict], bool]  # 中间结果→激活判定
    dependencies: List[str] = field(default_factory=list)
    priority: int = 0
    result: Optional[Dict] = None
    executed: bool = False


class DynamicDAGOrchestrator:
    """
    动态DAG扫描编排器，扩展ScanOrchestrator.

    增强点:
      1. 动态任务插入: 扫描中根据中间结果自动触发新任务
         (如发现加密函数→自动添加密码误用扫描)
      2. BMA评分融合: 贝叶斯模型平均融合NVD/EPSS/ExploitDB/GHSA
    """

    def __init__(self):
        self._tasks: Dict[str, DynamicScanTask] = {}
        self._adj: Dict[str, List[str]] = defaultdict(list)
        self._results: Dict[str, Any] = {}
        # BMA权重，各数据源历史预测准确度
        self._bma_weights = {"NVD": 0.30, "EPSS": 0.25, "ExploitDB": 0.25, "GHSA": 0.20}

    def register_task(self, task: DynamicScanTask):
        self._tasks[task.name] = task
        for dep in task.dependencies:
            self._adj[dep].append(task.name)

    def execute(self, initial_context: Dict) -> Dict[str, Any]:
        """执行动态DAG，支持运行时任务插入."""
        context = dict(initial_context)
        executed: Set[str] = set()
        pending = deque([
            name for name, t in self._tasks.items()
            if not t.dependencies
        ])

        while pending:
            name = pending.popleft()
            if name in executed:
                continue
            task = self._tasks[name]
            deps_done = all(d in executed for d in task.dependencies)
            if not deps_done:
                pending.append(name)
                continue

            try:
                task.result = task.runner(context)
                task.executed = True
                context[name] = task.result
                executed.add(name)
            except Exception as e:
                _log.error("任务 %s 失败: %s", name, e)

            # 动态发现: 检查新任务触发条件
            for t_name, t in self._tasks.items():
                if not t.executed and t.trigger_condition and t.trigger_condition(context):
                    if t_name not in pending and t_name not in executed:
                        pending.append(t_name)
                        _log.info("动态触发任务: %s", t_name)

            # 推送已完成任务的下游
            for neighbor in self._adj.get(name, []):
                if neighbor not in executed and neighbor not in pending:
                    pending.append(neighbor)

        self._results = context
        return context

    def bma_score(self, scores: Dict[str, float]) -> float:
        """
        贝叶斯模型平均(BMA)融合多源评分.

        权重=历史预测准确度. 融合分数 = sum(w_i * score_i) / sum(w_i)
        """
        total_w = 0.0
        weighted = 0.0
        for source, score in scores.items():
            w = self._bma_weights.get(source, 0.1)
            weighted += w * score
            total_w += w
        return weighted / max(0.001, total_w)

    def update_bma_weights(self, source: str, was_correct: bool):
        """BMA权重更新，基于预测正确性."""
        if source in self._bma_weights:
            old = self._bma_weights[source]
            delta = 0.02 if was_correct else -0.01
            self._bma_weights[source] = max(0.05, min(0.50, old + delta))
        # 重归一化
        total = sum(self._bma_weights.values())
        for k in self._bma_weights:
            self._bma_weights[k] /= total

    def get_results(self) -> Dict[str, Any]:
        return dict(self._results)


__all__ = ["DynamicScanTask", "DynamicDAGOrchestrator"]
