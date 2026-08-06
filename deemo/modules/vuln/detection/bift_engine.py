# -*- coding: utf-8 -*-
# 创建: 2026-08-01  |  BIFT编排引擎
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
二进制级前向污点分析——编排引擎与攻击面映射。

输出:
  1. 从每个输入源可达的危险操作列表(污点汇)
  2. 攻击面度量——按函数聚合的可达危险操作密度
  3. 污点传播深度——从输入到危险操作的平均步数(越小越危险)

攻击面可视化数据:
  每函数: 输入源数 + 可达汇数 + 传播深度
  → 生成攻击面热力图(高密度=优先审查)
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from .bift_taint import (
    TaintSource, TaintSink, TaintPath, TaintPropagator,
)

_log = logging.getLogger(__name__)


@dataclass
class AttackSurfaceMetric:
    """单函数的攻击面度量"""
    function_name: str
    input_sources: int = 0         # 此函数从多少输入源接收污点数据
    reachable_sinks: int = 0       # 此函数内有多少危险操作
    taint_depth_min: int = 999     # 从最近源到汇的最小步数
    # 综合指标
    attack_surface_score: float = 0.0  # [0,1]
    risk_level: str = "LOW"


@dataclass
class BiftReport:
    """BIFT完整报告"""
    binary_name: str
    total_sources: int = 0
    total_sinks: int = 0
    reached_sinks: int = 0          # 至少一条污点路径到达的汇
    total_paths: int = 0
    # 攻击面
    attack_surface: List[AttackSurfaceMetric] = field(default_factory=list)
    high_risk_functions: List[str] = field(default_factory=list)
    # 污点路径
    critical_paths: List[TaintPath] = field(default_factory=list)


# ============================================================================
# BIFT引擎
# ============================================================================


class BiftEngine:
    """二进制级前向污点分析引擎。

    使用示例:
        engine = BiftEngine()
        report = engine.analyze(functions, call_graph)
    """

    def __init__(self, max_taint_iterations: int = 20):
        self._propagator = TaintPropagator(max_taint_iterations)

    def analyze(self, functions: Dict[str, List[str]],
                 call_graph: Dict[str, List[str]] = None,
                 binary_name: str = ""
                 ) -> BiftReport:
        """执行跨函数前向污点分析。

        返回BiftReport。
        """
        reached_sinks, paths = self._propagator.propagate(
            functions, call_graph)

        # 攻击面度量——按函数聚合
        func_source_count: Dict[str, int] = defaultdict(int)
        func_sink_count: Dict[str, int] = defaultdict(int)
        for p in paths:
            func_source_count[p.source.function_name] += 1
            func_sink_count[p.sink.function_name] += 1

        all_funcs = set(functions.keys()) | set(func_source_count.keys()) | set(
            func_sink_count.keys())
        attack_surface = []
        for fname in all_funcs:
            srcs = func_source_count.get(fname, 0)
            snks = func_sink_count.get(fname, 0)
            if srcs == 0 and snks == 0:
                continue
            # 攻击面评分: 源×汇归一化
            score = min(1.0, (srcs * 0.3 + snks * 0.5) / 10.0)
            level = ("HIGH" if score >= 0.5 else
                     "MEDIUM" if score >= 0.2 else "LOW")
            attack_surface.append(AttackSurfaceMetric(
                function_name=fname,
                input_sources=srcs, reachable_sinks=snks,
                attack_surface_score=round(score, 3),
                risk_level=level))

        attack_surface.sort(key=lambda a: a.attack_surface_score, reverse=True)
        high_risk = [a.function_name for a in attack_surface
                     if a.risk_level == 'HIGH'][:10]

        # 关键路径——路径最短的(从源到汇步数最少→最危险)
        paths_sorted = sorted(paths, key=lambda p: p.path_length)

        return BiftReport(
            binary_name=binary_name,
            total_sources=len(set(p.source.source_id for p in paths)),
            total_sinks=len(reached_sinks) + sum(
                1 for f in functions.values()
                for insn in f if any(d in insn.lower() for d in
                                     ('memcpy','system','execve'))),
            reached_sinks=len(reached_sinks),
            total_paths=len(paths),
            attack_surface=attack_surface,
            high_risk_functions=high_risk,
            critical_paths=paths_sorted[:10])


# ============================================================================
# 便捷入口
# ============================================================================


def analyze_taint_flow(functions: Dict[str, List[str]],
                        call_graph: Dict[str, List[str]] = None,
                        binary_name: str = ""
                        ) -> BiftReport:
    """前向污点分析便捷入口"""
    return BiftEngine().analyze(functions, call_graph, binary_name)


__all__ = [
    "AttackSurfaceMetric",
    "BiftReport",
    "BiftEngine",
    "analyze_taint_flow",
]
