"""
Format-string use-def chain verification.

format_string_detector Level 1 flags every printf(var) as vulnerable,
including cases where var was safely snprintf'd or is a constant string.

Traces var source along the IR use-def chain (max 5 hops).
Hits user-input source → confirmed. Hits safe-format call → filtered.
Unresolved → keep original confidence.
"""

from core.taint_engine_light import LightweightTaintEngine


def verify_format_arg_source(
    format_arg: str,
    ir_lines: list[str],
    call_pc: int = -1,
) -> tuple[str, float]:
    """Verify the format argument's origin.

    Returns (source_category, adjusted_confidence):
      - ('user_input', 0.85): traced to fgets/read/recv within 5 hops
      - ('safe_format', 0.20): traced to safe snprintf/sprintf formatting
      - ('const_string', 0.10): string literal
      - ('unknown', 0.50): exceeds 5 hops or unresolved
    """
    engine = LightweightTaintEngine(max_backtrack_hops=5)
    engine.build_defuse_graph(ir_lines)

    # 找 format_arg 的最后一次定义位置
    def_pc = call_pc
    if call_pc < 0:
        def_pc = _find_var_in_ir(format_arg, ir_lines)

    if def_pc < 0:
        return ('unknown', 0.50)

    value_set = engine.trace_source(format_arg, def_pc)

    if value_set.is_user_controlled(threshold=0.4):
        return ('user_input', 0.85)
    if value_set.is_constant():
        return ('const_string', 0.10)

    # 检查是否来自安全格式化 (snprintf 等)
    conf = value_set.confidences.get('safe_format', 0.0)
    if conf > 0.3:
        return ('safe_format', 0.15)

    return ('unknown', 0.50)


def filter_format_findings(
    findings: list[dict],
    ir_lines: list[str],
) -> list[dict]:
    """对格式字符串检测结果进行 use-def 链过滤。

    保留 confirmed user_input 和 unknown, 移除 safe_format 和 const_string。
    对 confirmed 的提升置信度, 对 unknown 保留原值。"""
    filtered = []
    for f in findings:
        arg = f.get('format_arg', '')
        if not arg:
            filtered.append(f)
            continue

        source, conf = verify_format_arg_source(arg, ir_lines, f.get('call_address', -1))

        if source == 'safe_format':
            continue
        if source == 'const_string':
            continue

        if source == 'user_input':
            f['confidence'] = max(f.get('confidence', 0.6), conf)
            f['taint_source'] = 'user_input'
            f['taint_verified'] = True

        filtered.append(f)

    return filtered


def _find_var_in_ir(var_name: str, ir_lines: list[str]) -> int:
    """在 IR 行列表中查找变量最后一次定义的行号。"""
    for i in range(len(ir_lines) - 1, -1, -1):
        line = ir_lines[i].strip()
        if line.startswith(f'{var_name} = ') or line.startswith(f'{var_name}='):
            return i
    return -1
