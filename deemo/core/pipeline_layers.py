"""增强管线编排器 — 调度所有插件注册器, 叠加到标准管线之上。
每个注册器由独立 try/except ImportError 块组成, 插件缺失时静默降级。"""

import logging
from typing import Any, Dict

from core.pipeline import run_pipeline, _hash_file
from core.pipeline_plugins_sym import _register_sym_layers
from core.pipeline_plugins_fuzz import _register_fuzz_layers
from core.pipeline_plugins_binary import _register_binary_layers
from core.pipeline_plugins_misc import _register_misc_layers

logger = logging.getLogger(__name__)


def run_pipeline_enhanced(binary_path: str, **kwargs) -> Dict[str, Any]:
    """增强管线: 在标准管线上叠加 53 个可选增强插件。

    API 兼容 run_pipeline。所有增强模块通过 ImportError 静默降级。
    插件按主题分入 4 个注册器: sym / fuzz / binary / misc。
    """
    result = run_pipeline(binary_path, **kwargs)
    if 'error' in result:
        return result

    sym_result = result.get('symbolic_execution')
    binfo = result.get('binary_info', {})
    binary_hash = _hash_file(binary_path)

    # 四个注册器按主题分别加载
    _register_sym_layers(result, binary_path, binfo, binary_hash, sym_result, kwargs, logger)
    _register_fuzz_layers(result, binary_path, binfo, binary_hash, kwargs, logger)
    _register_binary_layers(result, binary_path, binfo, binary_hash, kwargs, logger)
    _register_misc_layers(result, binary_path, binfo, kwargs, logger)

    return result
