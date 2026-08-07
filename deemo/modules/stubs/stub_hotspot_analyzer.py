# stub_hotspot_analyzer.py — 运行时调用图热点分析
# 识别依赖图中被频繁穿越的路径（热点路径），
# 将这些路径上的桩标记为"高优先级验证+优化"目标。
#
# 问题:
#   依赖图是静态的 — 它表示"可能"的调用关系。
#   运行时实际调用模式可能与静态图差异显著:
#     a) 某些边从未被遍历 → 静态依赖是"僵尸边"
#     b) 某些路径贡献 >50% 的调用量 → 但排序器不感知
#     c) 热点路径上某个桩的性能问题被放大（每个调用都经过它）
#   不感知运行时调用热点会导致优化资源错配。
#
# 方法:
#   1. 从 StubHealthMonitor 的 caller_modules 重建运行时调用图
#   2. 计算每条边(调用方→被调用方)的调用频次
#   3. 路径热度 = 路径上各边频次的调和平均
#   4. 节点热度 = 经过该节点的全部路径热度之和
#   5. 输出: 热点节点排名 + 热点路径列表
#
# 应用:
# 热点节点 → 提升 AdaptiveGate 关键性评分
# 热点路径上的未实现桩 → 提升实现优先级
# 热点路径上的已实现桩 → 优先运行对抗测试
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


@_dc
class HotspotNode:
    """单个节点的热点评分。"""
    module_name: str
    total_inbound_calls: int = 0   # 入向调用总数
    total_outbound_calls: int = 0  # 出向调用总数
    unique_callers: int = 0
    unique_callees: int = 0
    heat_score: float = 0.0         # 综合热度 [0,∞)
    is_hotspot: bool = False        # heat_score ≥ 阈值
    percentile: float = 0.0         # 在所有节点中的百分位


@_dc
class HotspotEdge:
    """单条调用边的热度。"""
    caller: str
    callee: str
    call_count: int = 0
    edge_heat: float = 0.0          # 归一化热度


class HotspotAnalyzer:
    """运行时调用热点分析器。

    热度公式:
      node_heat = log(1 + inbound_calls) × unique_callers^0.5
      对数压缩高调用量差异，sqrt 给调用方多样性加权。
      被 1 个调用方调用 1000 次 < 被 10 个调用方各调用 100 次。
    """

    HOTSPOT_THRESHOLD_PERCENTILE = 0.75  # top 25%

    def analyze(self) -> tuple[list[HotspotNode], list[HotspotEdge]]:
        """分析运行时调用热点。"""
        # 1. 构建运行时调用图
        call_graph = self._build_runtime_callgraph()
        if not call_graph:
            return [], []

        # 2. 计算节点热度
        nodes = {}
        max_heat = 0.0
        for mod, info in call_graph.items():
            inbound = info['inbound']
            outbound = info['outbound']
            total_in = sum(inbound.values())
            import math
            heat = math.log(1 + total_in) * (len(inbound) ** 0.5)
            nodes[mod] = HotspotNode(
                module_name=mod,
                total_inbound_calls=total_in,
                total_outbound_calls=sum(outbound.values()),
                unique_callers=len(inbound),
                unique_callees=len(outbound),
                heat_score=round(heat, 2),
            )
            if heat > max_heat:
                max_heat = heat

        # 3. 归一化 + 百分位 + 热点标记
        if max_heat > 0:
            for node in nodes.values():
                node.heat_score = round(node.heat_score / max_heat, 3)
        sorted_nodes = sorted(nodes.values(), key=lambda n: -n.heat_score)
        total = len(sorted_nodes)
        for i, n in enumerate(sorted_nodes):
            n.percentile = round(1.0 - (i / max(total, 1)), 2)
            n.is_hotspot = n.percentile >= self.HOTSPOT_THRESHOLD_PERCENTILE

        # 4. 提取热点边
        max_edge = 0
        raw_edges = []
        for mod, info in call_graph.items():
            for callee, count in info['outbound'].items():
                raw_edges.append((mod, callee, count))
                if count > max_edge:
                    max_edge = count

        edges = []
        for caller, callee, count in raw_edges:
            edges.append(HotspotEdge(
                caller=caller, callee=callee,
                call_count=count,
                edge_heat=round(count / max(max_edge, 1), 3),
            ))
        edges.sort(key=lambda e: -e.edge_heat)

        return sorted_nodes, edges

    def hotspot_modules(self) -> list[str]:
        """返回热点模块名列表（用于优先级提升）。"""
        nodes, _ = self.analyze()
        return [n.module_name for n in nodes if n.is_hotspot]

# 运行时调用图重建
    @staticmethod
    def _build_runtime_callgraph() -> dict[str, dict]:
        """从 StubHealthMonitor 的 caller_modules 重建运行时调用图。

        返回: {module: {'inbound': {caller: count}, 'outbound': {callee: count}}}
        """
        try:
            from modules.stubs.stub_health_monitor import StubHealthMonitor
            mon = StubHealthMonitor()
            records = getattr(mon, '_records', {})
        except ImportError:
            return {}

        graph = _dd(lambda: {'inbound': _dd(int), 'outbound': _dd(int)})

        for stub_name, rec in records.items():
            for caller, count in rec.caller_modules.items():
                # caller → stub_name: 调用方调用此桩
                graph[stub_name]['inbound'][caller] += count
                graph[caller]['outbound'][stub_name] += count

        return dict(graph)

# 报告
    def hotspot_report(self) -> str:
        """生成 Markdown 热点分析报告。"""
        nodes, edges = self.analyze()
        lines = ['# 运行时调用热点分析', '']

        hotspots = [n for n in nodes if n.is_hotspot]
        lines.append(f'## 热点模块 ({len(hotspots)})')
        lines.append('| 模块 | 热度 | 入向调用 | 调用方数 | 百分位 |')
        lines.append('|------|-----:|---------:|---------:|-------:|')
        for n in hotspots[:15]:
            lines.append(
                f'| {n.module_name} | {n.heat_score:.2f} | '
                f'{n.total_inbound_calls} | {n.unique_callers} | '
                f'{n.percentile:.0%} |')

        if edges:
            lines.append(f'\n## 热点边 ({len(edges[:10])})')
            lines.append('| 调用方 | 被调用方 | 调用次数 | 边热度 |')
            lines.append('|--------|---------|---------:|-------:|')
            for e in edges[:10]:
                lines.append(
                    f'| {e.caller} | {e.callee} | '
                    f'{e.call_count} | {e.edge_heat:.2f} |')

        return '\n'.join(lines)


__all__ = ['HotspotNode', 'HotspotEdge', 'HotspotAnalyzer']
