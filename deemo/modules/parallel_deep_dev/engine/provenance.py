"""
创建: 2025-07-30
修改:
  2025-08-01 - 静态方法 _extract_top_level_symbols，记录器拆分
跨 Worker 代码溯源图 — 追踪并行 agent 间的代码贡献传播链。

问题：N 个 worker 并行生成代码且产出文件间存在 import 依赖时，
调试跨模块 bug 需要知道"哪个 worker 的哪次生成引入了这个逻辑"。
Agent Trace (Cursor 2026) 和 ai-blame (2026) 聚焦单 agent 的人/AI 二元归属，
不处理多 worker 交叉贡献的合并溯源。

方案：有向无环溯源图 (Provenance DAG)。
  节点：单次代码生成贡献 (worker_id, module, file, hash, timestamp)
  边：贡献间的依赖 (imports, inherits, calls, modifies)
  查询：blame(文件) → 贡献者链；blast(worker_id) → 影响半径

区别于 Agent Trace 的静态标注和 ai-blame 的单 agent 轨迹提取，
本模块处理并行 worker 间的交叉贡献传播与合并溯源。
"""

from __future__ import annotations

import ast
import hashlib
import os
import threading
import time
from dataclasses import dataclass, field


@dataclass
class ProvenanceNode:
    """单次代码生成贡献的溯源记录。"""
    node_id: str         # SHA-256(worker_id + filepath + timestamp) 前16字符
    worker_id: str       # 生成此代码的 worker 标识
    module_key: str      # worker 所属的子模块
    filepath: str        # 产出文件的绝对路径
    timestamp: float     # 生成时间 (time.time())
    content_hash: str    # 产出内容的 SHA-256 前16字符
    symbols: list[str]   # 此贡献导出的符号（函数名/类名）
    meta: dict = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    """贡献间的依赖边：source 的代码依赖 target 的代码。"""
    source_id: str       # 依赖方节点 ID
    target_id: str       # 被依赖方节点 ID
    edge_type: str       # imports | inherits | calls
    symbol: str = ""     # 涉及的符号名


@dataclass
class BlameResult:
    """溯源查询结果——"谁写了这段代码"。"""
    filepath: str
    line_start: int
    line_end: int
    worker_id: str
    module_key: str
    timestamp: float
    content_hash: str
    dependency_chain: list[str]  # 上游贡献者链（worker_id 列表）


class ProvenanceGraph:
    """跨 Worker 代码溯源图。线程安全。

    典型用法：
      pg = ProvenanceGraph()
      pg.record_contribution("worker_1", "core", "/path/to/auth.py", source)
      pg.record_contribution("worker_2", "api", "/path/to/handler.py", source)
      pg.record_dependency("handler.py", "auth.py", "imports", "create_token")
      pg.blame("/path/to/handler.py", 42)  → 返回溯源结果
    """

    def __init__(self):
        self._nodes: dict[str, ProvenanceNode] = {}
        self._edges: list[ProvenanceEdge] = []
        self._file_workers: dict[str, list[str]] = {}  # filepath → [node_id]
        self._symbol_index: dict[str, list[str]] = {}  # symbol → [node_id]
        self._lock = threading.Lock()

    # 贡献记录
    def record_contribution(
        self,
        worker_id: str,
        module_key: str,
        filepath: str,
        source: str,
        meta: dict | None = None,
    ) -> str:
        """记录一次 worker 代码生成贡献。返回节点 ID。

        自动提取源文件中的导出符号（顶层函数和类）。"""
        ts = time.time()
        content_hash = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:16]
        node_id = hashlib.sha256(
            f"{worker_id}:{filepath}:{ts}".encode()
        ).hexdigest()[:16]
        symbols = self._extract_top_level_symbols(source)

        node = ProvenanceNode(
            node_id=node_id, worker_id=worker_id,
            module_key=module_key, filepath=filepath,
            timestamp=ts, content_hash=content_hash,
            symbols=symbols, meta=meta or {},
        )

        with self._lock:
            self._nodes[node_id] = node
            self._file_workers.setdefault(filepath, []).append(node_id)
            for sym in symbols:
                self._symbol_index.setdefault(sym, []).append(node_id)

        return node_id

    # 依赖记录 — 当检测到跨 worker 的代码引用时调用
    def record_dependency(
        self,
        source_file: str,
        target_file: str,
        edge_type: str,
        symbol: str = "",
    ) -> bool:
        """记录贡献间的依赖边。source_file 导入了/调用了/继承了 target_file 的符号。

        自动解析：找到 source_file 和 target_file 的最新贡献节点并创建边。
        如果任一方无记录，返回 False（不影响主流程）。"""
        with self._lock:
            src_nodes = self._file_workers.get(source_file, [])
            tgt_nodes = self._file_workers.get(target_file, [])
            if not src_nodes or not tgt_nodes:
                return False

            # 使用最新的贡献节点（一个文件可能被多个 worker 修改）
            src_latest = max(src_nodes, key=lambda nid: self._nodes[nid].timestamp)
            tgt_latest = max(tgt_nodes, key=lambda nid: self._nodes[nid].timestamp)

            edge = ProvenanceEdge(
                source_id=src_latest, target_id=tgt_latest,
                edge_type=edge_type, symbol=symbol,
            )
            self._edges.append(edge)
            return True

    # 溯源查询
    def blame(
        self,
        filepath: str,
        line: int = 0,
    ) -> list[BlameResult]:
        """查询"谁为此文件/此行负责"。line=0 返回所有贡献者，line>0 返回最近贡献。"""
        with self._lock:
            node_ids = self._file_workers.get(filepath, [])
            if not node_ids:
                return []

            results: list[BlameResult] = []
            for nid in node_ids:
                node = self._nodes.get(nid)
                if node is None:
                    continue

                chain = self._trace_dependency_chain(nid, set())
                results.append(BlameResult(
                    filepath=node.filepath,
                    line_start=0,
                    line_end=0,
                    worker_id=node.worker_id,
                    module_key=node.module_key,
                    timestamp=node.timestamp,
                    content_hash=node.content_hash,
                    dependency_chain=chain,
                ))

            # 按时间降序——最近的贡献排在最前
            results.sort(key=lambda r: r.timestamp, reverse=True)
            return results

    def blast(
        self,
        worker_id: str,
    ) -> list[str]:
        """查询指定 worker 的影响半径——其贡献被哪些文件所依赖。"""
        with self._lock:
            affected: set[str] = set()
            worker_nodes = [
                nid for nid, node in self._nodes.items()
                if node.worker_id == worker_id
            ]
            for nid in worker_nodes:
                for edge in self._edges:
                    if edge.target_id == nid:
                        target_node = self._nodes.get(edge.source_id)
                        if target_node is not None:
                            affected.add(target_node.filepath)
            return sorted(affected)

    def contribution_graph(
        self,
        module_key: str | None = None,
    ) -> dict:
        """返回给定模块的贡献图摘要。module_key=None 返回全图。"""
        with self._lock:
            nodes = list(self._nodes.values())
            if module_key:
                nodes = [n for n in nodes if n.module_key == module_key]

            return {
                "contributions": [
                    {
                        "worker_id": n.worker_id,
                        "file": os.path.basename(n.filepath),
                        "symbols": n.symbols[:10],
                        "hash": n.content_hash,
                    }
                    for n in nodes
                ],
                "total_edges": len(self._edges),
                "total_contributions": len(nodes),
            }

    def merge_provenance(
        self,
        filepath: str,
        worker_id: str,
        source: str,
        base_node_id: str | None = None,
    ) -> str:
        """当 worker 修改已有文件时，创建新的贡献节点并链接到基础节点。
        这形成同一文件的修改链——git 的 commit 链等价物。"""
        # 确定模块 key
        module_key = ""
        if base_node_id:
            with self._lock:
                base = self._nodes.get(base_node_id)
                if base is not None:
                    module_key = base.module_key

        new_id = self.record_contribution(worker_id, module_key, filepath, source)
        if base_node_id:
            with self._lock:
                edge = ProvenanceEdge(
                    source_id=new_id, target_id=base_node_id,
                    edge_type="modifies", symbol="",
                )
                self._edges.append(edge)
        return new_id

    # 内部
    def _trace_dependency_chain(self, node_id: str, visited: set[str]) -> list[str]:
        """递归追踪上游依赖链（深度优先，限制 10 层防循环）。"""
        if node_id in visited or len(visited) >= 10:
            return []
        visited.add(node_id)

        chain: list[str] = []
        with self._lock:
            for edge in self._edges:
                if edge.source_id == node_id:
                    target = self._nodes.get(edge.target_id)
                    if target is not None:
                        chain.append(target.worker_id)
                        chain.extend(
                            self._trace_dependency_chain(edge.target_id, visited)
                        )
        return chain

    def stats(self) -> dict:
        with self._lock:
            workers = set(n.worker_id for n in self._nodes.values())
            modules = set(n.module_key for n in self._nodes.values())
            return {
                "total_contributions": len(self._nodes),
                "total_edges": len(self._edges),
                "unique_workers": len(workers),
                "unique_modules": len(modules),
            }

    @staticmethod
    def _extract_top_level_symbols(source: str) -> list[str]:
        """从 Python 源码提取顶层定义的函数名和类名。"""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        symbols: list[str] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef):
                symbols.append(node.name)
            elif isinstance(node, ast.ClassDef):
                symbols.append(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        symbols.append(target.id)
        return symbols


# 便捷函数委托给 engine/provenance_recorder.py
# record_worker_output / detect_and_record_dependencies
