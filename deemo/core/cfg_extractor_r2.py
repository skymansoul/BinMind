"""
CFG 提取器 radare2 后端与 DOT 导出。
"""


import json
import logging
import subprocess
from typing import Any, Dict, Optional

from config import R2_PATH

_log = logging.getLogger(__name__)


def extract_cfg_r2(
    binary_path: str,
    func_name: Optional[str],
    max_funcs: int,
) -> Dict[str, Any]:
    """通过 radare2 提取 CFG。"""
    result: Dict[str, Any] = {
        'binary': binary_path,
        'method': 'r2',
        'functions': [],
        'call_graph': {},
    }

    try:
        if func_name:
            proc = subprocess.run(
                [R2_PATH, '-q', '-e', 'io.color=false',
                 '-c', f's {func_name}', '-c', 'agfj', binary_path],
                capture_output=True, text=True, timeout=30,
            )
            try:
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    data = data[0] if data else {}
                blocks = []
                for block in data.get('blocks', []):
                    blocks.append({
                        'addr': block.get('offset', 0),
                        'size': block.get('size', 0),
                        'successors': [
                            j.get('offset', 0) for j in block.get('jump', 0)
                        ] if isinstance(block.get('jump'), list) else [],
                    })
                result['functions'].append({
                    'name': func_name,
                    'addr': data.get('offset', 0),
                    'size': data.get('size', 0),
                    'blocks': blocks,
                    'callees': [],
                })
            except (json.JSONDecodeError, KeyError):
                pass
        else:
            proc = subprocess.run(
                [R2_PATH, '-q', '-e', 'io.color=false',
                 '-c', 'afl', '-c', 'agj', binary_path],
                capture_output=True, text=True, timeout=30,
            )
            try:
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    for func_node in data[:max_funcs]:
                        result['functions'].append({
                            'name': func_node.get('name', ''),
                            'addr': func_node.get('offset', 0),
                            'size': func_node.get('size', 0),
                            'blocks': [],
                            'callees': [],
                        })
            except json.JSONDecodeError:
                pass

    except Exception as e:
        _log.debug("r2 CFG extraction failed: %s", e)

    return result


def cfg_to_dot(cfg_data: Dict[str, Any], func_name: str = '') -> str:
    """
    将 CFG 数据转为 Graphviz DOT 格式。

    Args:
        cfg_data: extract_cfg() 的返回值
        func_name: 要渲染的函数名（空字符串 = 渲染调用图）

    Returns:
        DOT 格式字符串
    """
    lines = ['digraph CFG {', '  rankdir=TB;', '  node [shape=box];']

    for func in cfg_data.get('functions', []):
        if func_name and func['name'] != func_name:
            continue

        lines.append(f'  // Function: {func["name"]}')
        for block in func.get('blocks', []):
            addr = block['addr']
            label = f'{func["name"]}\\n{addr:#x}'
            lines.append(
                f'  n_{addr:x} [label="{label}",fontsize=10];'
            )
            for succ in block.get('successors', []):
                lines.append(f'  n_{addr:x} -> n_{succ:x};')

    lines.append('}')
    return '\n'.join(lines)
