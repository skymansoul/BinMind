import logging
import json
import os
import time
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class CoverageType(str, Enum):
    BLOCK = "block"
    FUNCTION = "function"
    LINE = "line"
    EDGE = "edge"


@dataclass
class CoverageData:
    binary_path: str
    coverage_type: CoverageType
    total_blocks: int
    covered_blocks: int
    coverage_rate: float
    function_coverage: Dict[str, float] = field(default_factory=dict)
    hotspots: List[Any] = field(default_factory=list)
    timestamp: str = ""
    fuzzer_name: str = ""
    # 边覆盖 — 格式: {"src_addr→dst_addr": count}
    edge_map: Dict[str, int] = field(default_factory=dict)
    # 块级命中计数 (hitcount) — 每块被命中的次数
    block_hitcounts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_path': self.binary_path,
            'coverage_type': self.coverage_type.value,
            'total_blocks': self.total_blocks,
            'covered_blocks': self.covered_blocks,
            'coverage_rate': self.coverage_rate,
            'function_coverage': self.function_coverage,
            'hotspots': self.hotspots,
            'timestamp': self.timestamp,
            'fuzzer_name': self.fuzzer_name,
            'edge_map': self.edge_map,
        }


@dataclass
class HeatmapCell:
    address: int
    covered: bool
    hit_count: int
    function_name: Optional[str] = None
    line_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': hex(self.address),
            'covered': self.covered,
            'hit_count': self.hit_count,
            'function_name': self.function_name,
            'line_number': self.line_number
        }


@dataclass
class CoverageVisualization:
    heatmap_data: List[HeatmapCell]
    summary: Dict[str, Any]
    coverage_trend: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'heatmap_data': [cell.to_dict() for cell in self.heatmap_data],
            'summary': self.summary,
            'coverage_trend': self.coverage_trend
        }


# 覆盖停滞检测结果

@dataclass
class StagnationReport:
    is_stagnant: bool
    plateau_cycles: int          # 连续无新覆盖的周期数
    current_rate: float
    stalled_since: str           # 停滞起始时间戳
    last_new_coverage_ts: str
    suggestion: str = ""


class FuzzCoverageVisualizer:

    # 停滞判定阈值: 连续 N 个样本覆盖率波动 < ε 即判为停滞
    _STAGNATION_WINDOW = 5
    _STAGNATION_EPSILON = 0.001

    def __init__(self, output_dir: str = './coverage_output'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

# 解析覆盖数据

    def parse_coverage_data(self, coverage_file: str) -> CoverageData:
        try:
            with open(coverage_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            return CoverageData(
                binary_path=data.get('binary_path', ''),
                coverage_type=CoverageType(data.get('coverage_type', 'block')),
                total_blocks=data.get('total_blocks', 0),
                covered_blocks=data.get('covered_blocks', 0),
                coverage_rate=data.get('coverage_rate', 0.0),
                function_coverage=data.get('function_coverage', {}),
                hotspots=data.get('hotspots', []),
                timestamp=data.get('timestamp', ''),
                fuzzer_name=data.get('fuzzer_name', ''),
                edge_map=data.get('edge_map', {}),
                block_hitcounts=data.get('block_hitcounts', {}))

        except Exception as e:
            logger.error("覆盖率数据解析失败: %s", e)
            return CoverageData(
                binary_path=coverage_file,
                coverage_type=CoverageType.BLOCK,
                total_blocks=0,
                covered_blocks=0,
                coverage_rate=0.0)

# 热力图生成

    def generate_heatmap(self, coverage_data: CoverageData) -> CoverageVisualization:
        heatmap_cells = []
        covered_count = 0

        for func_name, rate in coverage_data.function_coverage.items():
            func_addr = self._get_function_address(func_name)

            cell = HeatmapCell(
                address=func_addr,
                covered=rate > 0,
                hit_count=int(rate * 100),
                function_name=func_name
            )
            heatmap_cells.append(cell)

            if rate > 0:
                covered_count += 1

        summary = {
            'total_functions': len(coverage_data.function_coverage),
            'covered_functions': covered_count,
            'coverage_rate': coverage_data.coverage_rate,
            'hotspot_count': len(coverage_data.hotspots)
        }

        return CoverageVisualization(
            heatmap_data=heatmap_cells,
            summary=summary)

    def _get_function_address(self, func_name: str) -> int:
        try:
            if '@' in func_name:
                func_name = func_name.split('@')[0]
            return hash(func_name) & 0xFFFFFFFFFFFFFFFF
        except Exception:  # 修复: bare except → Exception (hash fallback)
            return 0

# 导出

    def export_visualization_data(self, visualization: CoverageVisualization, output_file: str) -> bool:
        try:
            output_path = os.path.join(self.output_dir, output_file)

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(visualization.to_dict(), f, indent=2)

            logger.info("可视化数据已导出: %s", output_path)
            return True
        except Exception as e:
            logger.error("可视化导出失败: %s", e)
            return False

    def get_json_api_response(self, coverage_data: CoverageData) -> Dict[str, Any]:
        visualization = self.generate_heatmap(coverage_data)
        return visualization.to_dict()

# 多文件合并

    def merge_multiple_coverage(self, coverage_files: List[str]) -> CoverageData:
        merged = CoverageData(
            binary_path="merged",
            coverage_type=CoverageType.BLOCK,
            total_blocks=0,
            covered_blocks=0,
            coverage_rate=0.0
        )
        all_function_coverage = {}
        all_hotspots = []
        merged_edges: Dict[str, int] = {}
        merged_hitcounts: Dict[str, int] = {}

        for file_path in coverage_files:
            try:
                coverage = self.parse_coverage_data(file_path)

                if coverage.total_blocks > merged.total_blocks:
                    merged.total_blocks = coverage.total_blocks

                merged.covered_blocks += coverage.covered_blocks

                for func, rate in coverage.function_coverage.items():
                    if func not in all_function_coverage or rate > all_function_coverage[func]:
                        all_function_coverage[func] = rate

                all_hotspots.extend(coverage.hotspots)

                # 合并边覆盖: 对同一 src→dst 边累加命中计数
                for edge_key, cnt in coverage.edge_map.items():
                    merged_edges[edge_key] = merged_edges.get(edge_key, 0) + cnt
                for blk, cnt in coverage.block_hitcounts.items():
                    merged_hitcounts[blk] = merged_hitcounts.get(blk, 0) + cnt

                if coverage.timestamp:
                    merged.timestamp = coverage.timestamp
            except Exception as e:
                logger.warning("覆盖率合并失败 %s: %s", file_path, e)

        merged.function_coverage = all_function_coverage
        merged.hotspots = all_hotspots
        merged.edge_map = merged_edges
        merged.block_hitcounts = merged_hitcounts

        if merged.total_blocks > 0:
            merged.coverage_rate = merged.covered_blocks / merged.total_blocks

        return merged

# 趋势分析

    def analyze_coverage_trend(self, coverage_history: List[CoverageData]) -> List[Dict[str, Any]]:
        trend = []

        for coverage in coverage_history:
            trend.append({
                'timestamp': coverage.timestamp,
                'coverage_rate': coverage.coverage_rate,
                'covered_blocks': coverage.covered_blocks,
                'total_blocks': coverage.total_blocks,
                'fuzzer_name': coverage.fuzzer_name
            })

        return trend

# 边覆盖率过渡矩阵

    def edge_transition_matrix(
        self, coverage: CoverageData,
        min_hitcount: int = 1
    ) -> Dict[str, Any]:
        """基于边命中计数构建过渡矩阵的稀疏表示。

        返回 {edges: [{src, dst, weight}], stats: {total_edges, active_edges}}
        weight = log2(hitcount + 1)，强调低频但仍有触达的边。
        将此矩阵喂入可视化工具可生成覆盖流向图。"""
        edges = []
        log2 = __import__('math').log2
        for key, cnt in coverage.edge_map.items():
            if cnt < min_hitcount:
                continue
            if '→' in key:
                src, dst = key.split('→')
            else:
                src, dst = key, key
            edges.append({
                'src': src,
                'dst': dst,
                'weight': round(log2(cnt + 1), 2)
            })
        return {
            'edges': edges,
            'stats': {
                'total_edges': len(coverage.edge_map),
                'active_edges': len(edges)
            }
        }

# 差分覆盖分析

    def diff_coverage(
        self, baseline: CoverageData, current: CoverageData
    ) -> Dict[str, Any]:
        """比较两个覆盖快照，输出新增/丢失的功能以及净增量。

        计算三类差集:
        - gained: current 中覆盖而 baseline 中未覆盖的函数
        - lost: baseline 中覆盖而 current 中丢失的函数 (回归)
        - rate_delta: 覆盖率净变化"""
        base_funcs: Set[str] = set()
        for fn, rate in baseline.function_coverage.items():
            if rate > 0:
                base_funcs.add(fn)
        curr_funcs: Set[str] = set()
        for fn, rate in current.function_coverage.items():
            if rate > 0:
                curr_funcs.add(fn)
        gained = sorted(curr_funcs - base_funcs)
        lost = sorted(base_funcs - curr_funcs)
        return {
            'rate_delta': round(current.coverage_rate - baseline.coverage_rate, 6),
            'gained_functions': gained,
            'gained_count': len(gained),
            'lost_functions': lost,
            'lost_count': len(lost),
            'net_change': len(gained) - len(lost),
            'baseline_timestamp': baseline.timestamp,
            'current_timestamp': current.timestamp,
        }

# 覆盖停滞检测

    def detect_stagnation(
        self, trend: List[Dict[str, Any]]
    ) -> StagnationReport:
        """检测覆盖增长是否已进入平台期。

        用最近 _STAGNATION_WINDOW 个样本的覆盖率方差判断:
        方差 < ε 则视为停滞。参考 EcoFuzz 的 exploration-vs-exploitation
        状态切换思想 — 停滞期应触发变异策略切换。"""
        if len(trend) < self._STAGNATION_WINDOW:
            return StagnationReport(
                is_stagnant=False, plateau_cycles=0,
                current_rate=trend[-1]['coverage_rate'] if trend else 0.0,
                stalled_since="", last_new_coverage_ts="",
            )

        recent = trend[-self._STAGNATION_WINDOW:]
        rates = [r['coverage_rate'] for r in recent]
        mean_rate = sum(rates) / len(rates)
        variance = sum((r - mean_rate) ** 2 for r in rates) / len(rates)

        stagnant = variance < self._STAGNATION_EPSILON

        # 追溯最后㇐次覆盖率递增的时间
        prev_rate = trend[-self._STAGNATION_WINDOW - 1]['coverage_rate'] if len(trend) > self._STAGNATION_WINDOW else rates[0]
        last_growth_idx = -1
        for idx in range(len(trend) - 2, max(0, len(trend) - 20), -1):
            if trend[idx]['coverage_rate'] < rates[-1] - self._STAGNATION_EPSILON:
                last_growth_idx = idx
                break

        suggestion = ""
        if stagnant:
            suggestion = (
                "覆盖增长停滞，建议: (1) 切换变异策略/字典 (2) 增大能量分配系数 "
                "(3) 引入新种子/语料库 (4) 检查目标是否已全部覆盖"
            )

        return StagnationReport(
            is_stagnant=stagnant,
            plateau_cycles=self._STAGNATION_WINDOW if stagnant else 0,
            current_rate=rates[-1],
            stalled_since=trend[-self._STAGNATION_WINDOW]['timestamp'] if stagnant else "",
            last_new_coverage_ts=trend[last_growth_idx]['timestamp'] if last_growth_idx >= 0 else "",
            suggestion=suggestion,
        )

# Flamegraph 折叠格式输出

    def export_flamegraph_collapsed(
        self, coverage: CoverageData, output_file: Optional[str] = None
    ) -> str:
        """生成 flamegraph.pl 兼容的 collapsed stack 格式。

        每行: func_stack hitcount
        其中 func_stack 为 "func_a;func_b;func_c" 的调用路径。
        无实际调用栈数据时，用 function_coverage 中的函数名作为叶节点。"""
        lines = []
        for fn, rate in coverage.function_coverage.items():
            sanitized = fn.replace(';', ':').replace(' ', '_')
            count = int(rate * 100)
            if count > 0:
                lines.append(f"{sanitized} {count}")
            else:
                lines.append(f"{sanitized} 1")
        output = "\n".join(lines)
        if output_file:
            out_path = os.path.join(self.output_dir, output_file)
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(output)
        return output

# 简易 HTML 报告

    def export_html_report(
        self, coverage: CoverageData, output_file: str = "coverage_report.html"
    ) -> str:
        """生成自包含 HTML 覆盖报告: 概要统计 + 函数级覆盖表。

        不含外部依赖，CSS 内联。用于邮件/CI 通知中的快速审阅。"""
        rows = []
        for fn, rate in sorted(
            coverage.function_coverage.items(),
            key=lambda kv: kv[1], reverse=True
        ):
            color = '#c8e6c9' if rate > 0.5 else ('#fff9c4' if rate > 0 else '#ffcdd2')
            rows.append(
                f'<tr style="background:{color}">'
                f'<td>{fn}</td>'
                f'<td>{rate:.2%}</td></tr>'
            )
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>覆盖报告 — {coverage.binary_path}</title>
<style>
body {{ font: 14px/1.5 system-ui,sans-serif; max-width:960px; margin:auto; padding:20px; }}
table {{ border-collapse:collapse; width:100%; }}
td,th {{ border:1px solid #ddd; padding:6px 12px; }}
th {{ background:#f5f5f5; text-align:left; }}
.metric {{ display:inline-block; margin:8px 24px 8px 0; }}
.metric .value {{ font-size:24px; font-weight:700; }}
</style></head><body>
<h1>覆盖报告</h1>
<p>目标: {coverage.binary_path} | 模糊器: {coverage.fuzzer_name} | 时间: {coverage.timestamp}</p>
<div>
<div class="metric"><span class="value">{coverage.coverage_rate:.2%}</span><br>覆盖率</div>
<div class="metric"><span class="value">{coverage.covered_blocks}</span><br>已覆盖块</div>
<div class="metric"><span class="value">{coverage.total_blocks}</span><br>总块数</div>
<div class="metric"><span class="value">{len(coverage.edge_map)}</span><br>已覆盖边</div>
</div>
<h2>函数覆盖明细</h2>
<table><tr><th>函数</th><th>覆盖率</th></tr>
{''.join(rows)}
</table></body></html>"""
        out_path = os.path.join(self.output_dir, output_file)
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return out_path


# 模块级便捷入口

def generate_coverage_heatmap(binary_path: str, coverage_file: str) -> Dict[str, Any]:
    visualizer = FuzzCoverageVisualizer()
    coverage_data = visualizer.parse_coverage_data(coverage_file)
    coverage_data.binary_path = binary_path
    return visualizer.get_json_api_response(coverage_data)
