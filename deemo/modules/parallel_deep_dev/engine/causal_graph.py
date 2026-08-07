"""
创建: 2026-05-08
修改:
2025-07-30 - extract_edges 委托给 causal_extractor.py
增量式因果影响传播图 — 多边类型依赖分析，支持实时变更冲击半径查询。

问题：并行 worker 修改文件时不知道自己的改动会影响哪些其他模块。
当前语义验证器仅检查跨文件的 import 符号是否存在，不评估行为影响。
例如 worker A 修改了 core/auth.py 的 create_token 函数签名，worker B 同时在
修改 api/handler.py（调用了 create_token），B 的代码将在合并后不可用。

方案：构建有向多类型依赖图，支持 O(log n) 增量更新和 O(k·d) 影响查询。
边类型反映"被影响的方式"，权重反映"被破坏的概率"：
  IMPORTS  (权重 0.2): 仅导入符号，未调用——影响最弱
  CALLS    (权重 0.5): 函数调用依赖——签名变化则调用方必受影响
  MUTATES  (权重 0.7): 赋值给导入对象的属性——破坏内部状态假设
  INHERITS (权重 0.6): 类继承——父类接口变化影响所有子类
  RAISES   (权重 0.3): 异常传播——新增异常类型可能破坏调用方的 except 子句

影响传播使用几何衰减：impact = Σ(edge_weight · decay^distance)。
decay ∈ (0, 1)，默认 0.5，确保 3 跳以上的影响降至 12.5% 以下。

与现有工作的差异：
  - causal-graph-mcp 建模 mutation/assertion/side-effect 边但需 SQLite 存储，
    不适合实时并行开发场景的内存增量更新
  - CHID 结合调用图 + 历史挖掘但用于 PR review 后处理，
    不适用于代码生成过程中的实时预警
  - 本模块采用惰性重解析策略：仅当文件被 worker 修改且被其他 worker 查询时才
    重新解析该文件的依赖边，将增量更新开销从 O(n) 降至 O(d)（d=变更文件数）
"""


import os
import threading
from collections import defaultdict
from dataclasses import dataclass


# 边类型与权重 — 反映"被破坏的概率"
EDGE_WEIGHTS: dict[str, float] = {
    "IMPORTS":  0.2,
    "CALLS":    0.5,
    "MUTATES":  0.7,
    "INHERITS": 0.6,
    "RAISES":   0.3,
}

DECAY_FACTOR: float = 0.5       # 每跳衰减因子
MAX_HOPS: int = 5                # 传播最大跳数


@dataclass
class CausalityEdge:
    """一条有向依赖边。source 依赖 target（source → target）。"""
    source: str          # 依赖方文件路径（相对于项目根目录）
    target: str          # 被依赖文件/符号
    edge_type: str       # IMPORTS | CALLS | MUTATES | INHERITS | RAISES
    symbol: str = ""     # 涉及的符号名
    lineno: int = 0      # 在 source 中的行号


@dataclass
class ImpactResult:
    """单次影响查询的结果条目。"""
    file: str
    distance: int         # 从变更源到该文件的跳数
    impact_score: float   # 0.0 - 1.0，累积影响分数
    paths: list[str]      # 传播路径描述


class CausalGraph:
    """增量更新的多边类型依赖图。线程安全。

    内部使用邻接表 + 反向索引双重结构：
    - _forward:  file → list[Edge]  正向边（谁依赖我 → 我影响谁）
    - _reverse:  file → list[Edge]  反向边（我依赖谁 → 查询时沿正向传播）
    - _stale:     已过时文件集合，下次查询/更新时触发惰性重解析

    惰性重解析策略：不在每次文件变更时立即重解析所有依赖，
    而是在查询涉及该文件时才重解析。对于 N 个 worker 各修改 1-3 个文件的
    典型场景，这避免了 O(N·M) 的全量重解析。"""

    def __init__(self) -> None:
        self._forward: dict[str, list[CausalityEdge]] = defaultdict(list)
        self._reverse: dict[str, list[CausalityEdge]] = defaultdict(list)
        self._stale: set[str] = set()
        self._lock = threading.Lock()

    # 构建与增量更新

    def build_from_files(self, filepaths: list[str]) -> int:
        """从文件列表构建初始依赖图。返回发现的边总数。"""
        count = 0
        for fpath in filepaths:
            if fpath.endswith(".py"):
                edges = _extract_edges(fpath)
                self._upsert_edges(fpath, edges)
                count += len(edges)
        return count

    def mark_stale(self, filepath: str) -> None:
        """标记文件为过时——worker 修改了此文件。不立即重解析。"""
        with self._lock:
            self._stale.add(filepath)

    def refresh_if_stale(self, filepath: str) -> int:
        """若文件标记为过时，重新解析并更新边。返回新边数量。"""
        with self._lock:
            if filepath not in self._stale:
                return 0
            self._stale.discard(filepath)

        if not os.path.isfile(filepath):
            self._remove_file(filepath)
            return 0

        edges = _extract_edges(filepath)
        self._upsert_edges(filepath, edges)
        return len(edges)

    # 影响查询 — 给定变更文件集，计算受影响的文件及影响分数

    def impact_query(
        self,
        changed_files: list[str],
        decay: float = DECAY_FACTOR,
        max_hops: int = MAX_HOPS,
    ) -> list[ImpactResult]:
        """查询受 changes 影响的文件及其影响分数。

        传播算法：类 BFS。从每个 changed_file 出发，沿正向边逐跳传播。
        同一文件可通过多条路径被影响，取最大影响分数。
        传播 weight 随 (decay^distance) 几何衰减。"""
        scores: dict[str, float] = {}
        paths: dict[str, list[str]] = {}

        with self._lock:
            current: set[str] = set(changed_files)
            for dist in range(1, max_hops + 1):
                next_wave: set[str] = set()
                hop_decay = decay ** (dist - 1)

                for node in current:
                    for edge in self._forward.get(node, []):
                        w = EDGE_WEIGHTS.get(edge.edge_type, 0.3)
                        score = w * hop_decay

                        existing = scores.get(edge.source, 0.0)
                        if score > existing:
                            scores[edge.source] = score
                            path_desc = (
                                f"{edge.source}:{edge.lineno} "
                                f"[{edge.edge_type}] {edge.symbol or '?'}"
                            )
                            paths[edge.source] = path_desc

                        next_wave.add(edge.source)

                current = next_wave - set(changed_files)
                if not current:
                    break

        return sorted(
            [
                ImpactResult(
                    file=f,
                    distance=min(
                        (i for i in range(1, max_hops + 1)
                         if any(
                             e.source == f
                             for e in self._forward.get(c, [])
                         )),
                        default=max_hops,
                    ),
                    impact_score=round(s, 4),
                    paths=[paths.get(f, "")],
                )
                for f, s in scores.items()
            ],
            key=lambda r: r.impact_score, reverse=True,
        )

    def blast_radius(
        self,
        changed_file: str,
        threshold: float = 0.1,
    ) -> list[str]:
        """返回单一变更文件的"影响半径"内的所有文件。
        仅包含影响分数 >= threshold 的文件。用于给 worker 快速预览。"""
        results = self.impact_query([changed_file])
        return [r.file for r in results if r.impact_score >= threshold]

    # 内部方法

    def _upsert_edges(self, filepath: str, edges: list[CausalityEdge]) -> None:
        with self._lock:
            # 移除旧边
            old_forward = [e for e in self._forward.get(filepath, [])]
            for e in old_forward:
                self._reverse[e.target].remove(e)
            self._forward[filepath] = list(edges)

            old_rev_targets = {e.target for e in old_forward}
            for e in edges:
                self._reverse[e.target].append(e)
            # 如果旧边中某些 target 不再被依赖，清理空列表
            for target in old_rev_targets:
                if target not in {e.target for e in edges}:
                    remaining = [
                        re for re in self._reverse.get(target, [])
                        if re.source != filepath
                    ]
                    if remaining:
                        self._reverse[target] = remaining
                    elif target in self._reverse:
                        del self._reverse[target]

    def _remove_file(self, filepath: str) -> None:
        with self._lock:
            old_edges = self._forward.pop(filepath, [])
            for e in old_edges:
                rev_list = self._reverse.get(e.target, [])
                self._reverse[e.target] = [x for x in rev_list if x.source != filepath]

    def stats(self) -> dict[str, int]:
        with self._lock:
            nodes = set(self._forward.keys()) | set(self._reverse.keys())
            return {
                "nodes": len(nodes),
                "edges": sum(len(v) for v in self._forward.values()),
                "stale_files": len(self._stale),
            }


# 静态边提取委托给 engine/causal_extractor.py
from parallel_deep_dev.engine.causal_extractor import extract_edges as _extract_edges


def build_causal_graph_from_root(root_dir: str) -> CausalGraph:
    """扫描 root_dir 下所有 .py 文件，构建初始因果图。"""
    graph = CausalGraph()
    py_files: list[str] = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            if fn.endswith(".py"):
                py_files.append(os.path.join(dirpath, fn))
    graph.build_from_files(py_files)
    return graph


def impact_to_blackboard(
    blackboard,
    graph: CausalGraph,
    changed_files: list[str],
) -> list[ImpactResult]:
    """执行影响查询并将高风险结果写入黑板。
    与 semantic_dedup.dedup_blackboard_deposit 接口风格一致。"""
    results = graph.impact_query(changed_files)
    high_impact = [r for r in results if r.impact_score >= 0.3]
    for r in high_impact[:8]:
        blackboard.deposit(
            "warning",
            f"因果影响: {os.path.basename(r.file)} 受变更影响 (score={r.impact_score:.3f}, dist={r.distance})",
            source_module="causal_graph",
            tags=["impact", "causal"],
        )
    return results
