"""
Optional enhancement layer for run_pipeline_enhanced(): DESG construction,
entropy scheduling, and path diversity exploration.

Each module is silently skipped on ImportError. No modification to pipeline.py.
Activation is automatic when the corresponding data (CFG blocks, seed queue,
active paths) is available during the run.
"""


import logging
from typing import Any, Dict

_log = logging.getLogger(__name__)


def inject_desg(pipeline_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    在管线结果中注入 DESG 结构。

    从 cfg_extractor 的输出提取 CFG 块数据，
    为每个函数构建支配增强语义图。

    注入 key: pipeline_result['_desg_graphs'] = {func_name: desg_dict}
    """
    try:
        from core.desg_builder import build_desg, desg_structural_hash
    except ImportError:
        return pipeline_result

    cfg_data = pipeline_result.get("_cfg_data")
    if not cfg_data:
        return pipeline_result

    desg_graphs = {}
    hashes = []

    for func in cfg_data.get("functions", []):
        blocks = func.get("blocks", [])
        if len(blocks) < 2:
            continue

        try:
            desg = build_desg(blocks, compute_entropy=True)
            fname = func.get("name", "?")
            desg_graphs[fname] = desg
            h = desg_structural_hash(desg)
            hashes.append((fname, h))
        except Exception as e:
            _log.debug("DESG build failed for %s: %s", func.get("name", "?"), e)

    if desg_graphs:
        pipeline_result["_desg_graphs"] = desg_graphs
        pipeline_result["_desg_hashes"] = hashes
        _log.debug("DESG injected for %d function(s)", len(desg_graphs))

    return pipeline_result


def create_entropy_scheduler() -> Any:
    """
    创建熵调度器实例供模糊测试阶段使用。

    若 fuzzing 模块有活跃的种子队列，调度器接管能量分配。
    降级: ImportError 时返回 None，调用方使用默认均匀分配。
    """
    try:
        from core.entropy_scheduler import EntropySeedScheduler
        return EntropySeedScheduler()
    except ImportError:
        return None


def create_path_explorer(
    diversity_weight: float = 0.6,
) -> Any:
    """
    创建路径多样性探索器供符号执行阶段使用。

    降级: ImportError 时返回 None，调用方使用默认搜索策略。
    """
    try:
        from core.path_diversity_explorer import PathDiversityExplorer
        return PathDiversityExplorer(diversity_weight=diversity_weight)
    except ImportError:
        return None
