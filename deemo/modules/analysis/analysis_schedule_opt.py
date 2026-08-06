"""
分析管线调度优化 (Analysis Pipeline Schedule Optimizer, APSO)
---------------------------------------------------------------
基于历史执行数据优化分析管线的阶段调度顺序.

设计依据:
  分析管线通常按固定顺序执行 (反汇编→反编译→静态分析→符号执行→动态).
  但不同二进制的最优顺序不同——小二进制可能反编译极快, 大固件
  的符号执行可能永远不收敛. 固定顺序导致资源浪费.

  APSO 从历史执行数据学习每阶段的 (耗时, 产出率, 阻塞概率),
  在线重排阶段顺序以最大化早期产出:
    - 快速+高产出阶段提前 (尽早给用户反馈)
    - 易阻塞阶段延后 (避免阻塞后续阶段)
    - 高价值阶段提前 (漏洞发现率高的阶段优先)

算法:
  1. 每阶段维护 (avg_time, success_rate, finding_rate) 的三元组
  2. 按 score = finding_rate / (avg_time * (1 + block_probability)) 排序
  3. 依赖约束: 子阶段不早于父阶段
"""
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class StageProfile:
    """分析阶段的运行时画像."""
    name: str
    avg_time_s: float = 0.0
    success_rate: float = 1.0       # 成功完成率
    finding_rate: float = 0.0        # 每次执行的发现率
    block_probability: float = 0.0   # 阻塞后续阶段的概率
    n_executions: int = 0
    dependencies: List[str] = field(default_factory=list)


class AnalysisScheduleOptimizer:
    """分析管线调度优化器.

    用法:
      aso = AnalysisScheduleOptimizer()
      aso.register_stage('decompile', depends_on=['disasm'])
      aso.record_execution('decompile', elapsed_s=3.2, success=True, findings=1)
      order = aso.optimize_order()
    """

    def __init__(self):
        self._stages: Dict[str, StageProfile] = {}
        self._default_stages = [
            'disasm', 'decompile', 'static_analysis',
            'symbolic', 'dynamic', 'patching',
        ]

    def register_stage(self, name: str, depends_on: Optional[List[str]] = None):
        if name not in self._stages:
            self._stages[name] = StageProfile(name=name)
        if depends_on:
            self._stages[name].dependencies = list(depends_on)

    def record_execution(self, name: str, elapsed_s: float,
                         success: bool, findings: int = 0):
        """记录一次阶段执行."""
        sp = self._stages.get(name)
        if sp is None:
            sp = StageProfile(name=name)
            self._stages[name] = sp
        n = sp.n_executions
        sp.avg_time_s = (sp.avg_time_s * n + elapsed_s) / (n + 1)
        sp.success_rate = (sp.success_rate * n + (1.0 if success else 0.0)) / (n + 1)
        sp.finding_rate = (sp.finding_rate * n + findings) / (n + 1)
        sp.n_executions = n + 1

    def optimize_order(self) -> List[str]:
        """返回优化的阶段执行顺序."""
        # 计算每阶段的得分
        scores = {}
        for name, sp in self._stages.items():
            if sp.n_executions == 0:
                scores[name] = 0.5  # 未知阶段中等优先级
            else:
                penalty = sp.avg_time_s * (1.0 + sp.block_probability)
                scores[name] = sp.finding_rate / max(0.1, penalty)
        # 拓扑排序 + 得分优先级
        in_degree = {name: len(sp.dependencies) for name, sp in self._stages.items()}
        ready = [n for n, d in in_degree.items() if d == 0]
        order = []
        while ready:
            ready.sort(key=lambda n: scores.get(n, 0), reverse=True)
            current = ready.pop(0)
            order.append(current)
            for name, sp in self._stages.items():
                if current in sp.dependencies:
                    in_degree[name] -= 1
                    if in_degree[name] == 0:
                        ready.append(name)
        # 追加孤立节点
        for name in self._stages:
            if name not in order:
                order.append(name)
        return order

    def estimate_completion_time(self, order: Optional[List[str]] = None
                                 ) -> float:
        """估计管线完成时间 (关键路径)."""
        order = order or self.optimize_order()
        finish_time: Dict[str, float] = {}
        max_time = 0.0
        for name in order:
            sp = self._stages.get(name)
            t = sp.avg_time_s if sp else 1.0
            start = 0.0
            if sp:
                for dep in sp.dependencies:
                    start = max(start, finish_time.get(dep, 0))
            finish_time[name] = start + t
            max_time = max(max_time, finish_time[name])
        return max_time

    def suggest_parallel_groups(self) -> List[List[str]]:
        """建议可并行的阶段组."""
        order = self.optimize_order()
        finish_time: Dict[str, float] = {}
        groups: List[List[str]] = []
        for name in order:
            sp = self._stages.get(name)
            deps = sp.dependencies if sp else []
            start = max((finish_time.get(d, 0) for d in deps), default=0)
            finish_time[name] = start + (sp.avg_time_s if sp else 1.0)
            placed = False
            for group in groups:
                if all(finish_time.get(n, 0) <= start for n in group):
                    group.append(name)
                    placed = True
                    break
            if not placed:
                groups.append([name])
        return groups
