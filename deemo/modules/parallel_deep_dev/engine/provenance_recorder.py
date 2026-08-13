"""
创建: 2024-10-11
溯源图便捷记录器 — 批量记录 worker 产出、自动检测跨文件依赖。

本模块提供面向 executor 的高层接口，
处理文件 I/O、批量记录、黑板集成等编排逻辑。
"""


import ast
import os
from parallel_deep_dev.engine._io import safe_read
from parallel_deep_dev.engine.provenance import ProvenanceGraph


def record_worker_output(
    pg: ProvenanceGraph,
    worker_id: str,
    module_key: str,
    filepaths: list[str],
    blackboard=None,
) -> list[str]:
    """批量记录 worker 的产出文件，并将溯源摘要写入黑板。
    返回创建的节点 ID 列表。"""
    node_ids: list[str] = []
    for fpath in filepaths:
        if not fpath.endswith(".py") or not os.path.isfile(fpath):
            continue
        source = safe_read(fpath)
        if source is None:
            continue
        nid = pg.record_contribution(worker_id, module_key, fpath, source)
        node_ids.append(nid)

    if blackboard is not None and node_ids:
        blackboard.deposit(
            "finding",
            f"Worker [{worker_id}] 产出溯源已记录: {len(node_ids)} 个文件, "
            f"模块 {module_key}",
            source_module="provenance",
            tags=["provenance", worker_id, module_key],
        )
    return node_ids


def detect_and_record_dependencies(
    pg: ProvenanceGraph,
    filepaths: list[str],
) -> int:
    """检测文件间的 import 依赖并自动记录溯源边。返回创建的边数。

    通过将 from X import Y 中的模块名映射到已知文件路径来建立边。
    映射策略：尝试将模块名后缀匹配到已知文件名，支持子包导入。
    例如 from core.auth import create_token → 匹配到 core/auth.py。"""
    edge_count = 0
    path_to_nodes: dict[str, str] = {}
    for fpath in filepaths:
        path_to_nodes[os.path.basename(fpath)] = fpath

    for fpath in filepaths:
        if not fpath.endswith(".py") or not os.path.isfile(fpath):
            continue
        source = safe_read(fpath)
        if source is None:
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                parts = node.module.split(".")
                # 从最深层模块名开始尝试匹配，子包导入优先匹配完整路径
                for i in range(len(parts)):
                    candidate = ".".join(parts[i:]) + ".py"
                    if candidate in path_to_nodes:
                        for alias in node.names:
                            ok = pg.record_dependency(
                                fpath, path_to_nodes[candidate],
                                "imports", alias.name,
                            )
                            if ok:
                                edge_count += 1
                        break
    return edge_count
