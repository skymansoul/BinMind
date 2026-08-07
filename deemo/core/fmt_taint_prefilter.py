"""
格式化字符串污点预过滤检测器。

在原有静态匹配+符号执行的基础上, 增加污点传播层降低误报。
"""


import subprocess
from typing import Any, Dict, List

from config import R2_PATH


def detect_with_taint_prefilter(
    binary_path: str,
    func_name: str = "",
    use_llm: bool = False,
) -> List[Dict[str, Any]]:
    """带污点预过滤的格式化字符串检测。

    先运行 taint_propagator 识别确实可达污点源的 sink,
    再对此子集运行完整的 3-level 检测。
    对非污点 sink 降低置信度 (但仍保留, 避免漏报)。

    与 detect_format_string_vulns 兼容: 参数相同, 返回值格式相同,
    可直接替换调用。
    """
    from core.format_string_detector import detect_format_string_vulns

    findings = detect_format_string_vulns(binary_path, func_name, use_llm)
    if not findings:
        return findings

    from core.taint_propagator import TaintPropagator
    tp = TaintPropagator()

    try:
        out = subprocess.check_output(
            [R2_PATH, '-q', '-c', f's {func_name}; pdc', binary_path],
            timeout=15, stderr=subprocess.DEVNULL,
        )
        pseudocode = out.decode('utf-8', errors='replace')
        taint_paths = tp.propagate(pseudocode, func_name)
    except Exception:
        return findings

    # 构建污点 sink 集合
    tainted_sinks = set()
    for tp_path in taint_paths:
        if tp_path.sink_type == 'FORMAT':
            tainted_sinks.add(tp_path.sink_func)

    # 调整置信度: 非污点 sink → 置信度打 6 折
    for f in findings:
        fmt_func = f.get('format_func', '')
        if fmt_func not in tainted_sinks:
            f['confidence'] = round(f.get('confidence', 0.5) * 0.6, 4)
            f['taint_filtered'] = True
        else:
            f['taint_verified'] = True
            f['taint_source'] = next(
                (tp.source_func for tp in taint_paths
                 if tp.sink_func == fmt_func), '',
            )

    return findings
