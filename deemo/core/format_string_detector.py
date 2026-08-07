"""
格式化字符串漏洞检测与偏移分析。

检测 printf/fprintf/sprintf/snprintf 系列函数的格式化字符串漏洞：
1. 静态识别 vararg 调用中格式化参数来自用户输入的代码模式
2. 利用 angr 符号执行或动态爆破计算格式化字符串在栈上的参数偏移
3. 输出偏移值和利用建议（直接修改 GOT / 泄露地址 / 任意写）

多层检测策略:
  Level 1 — 静态模式匹配: 在反编译代码中搜索 printf(buf) 等危险模式
  Level 2 — 符号执行: 将格式化参数符号化，追踪到栈上位置计算偏移
  Level 3 — LLM 辅助: 调用 LLM 分析反编译代码判断格式化字符串利用可行性

辅助函数拆分至 fmt_helpers.py 和 fmt_confidence.py。
"""


import logging
import os
import re
from typing import Any, Dict, List, Optional

from config import R2_PATH
from core.fmt_helpers import (
    _FORMAT_FUNCTIONS,
    list_user_functions as _list_user_functions,
    decompile_function as _decompile_function,
    static_format_detect as _static_format_detect,
    compute_format_offset as _compute_format_offset,
    detect_indirect_format_call as _detect_indirect_format_call,
)
from core.fmt_confidence import (
    llm_enhance_findings as _llm_enhance_findings,
    format_offset_to_arg_position,
)

_log = logging.getLogger(__name__)

_DIRECT_CALL_PATTERN = re.compile(
    r'(printf|fprintf|sprintf|snprintf|dprintf)\s*\(\s*([^,"]+)',
)


def detect_format_string_vulns(
    binary_path: str,
    func_name: Optional[str] = None,
    use_llm: bool = False,
) -> List[Dict[str, Any]]:
    """
    检测二进制中格式化字符串漏洞。

    返回值列表，每个条目描述一个潜在的格式化字符串漏洞点：
      - function: 包含漏洞的函数名
      - call_address: 危险调用的地址（0 表示未知）
      - format_func: 格式化函数名
      - offset: 格式化字符串在栈上的参数偏移 (-1 表示未知)
      - confidence: 检测置信度 0.0-1.0
      - description: 人类可读描述
      - exploitation: 利用建议
    """
    findings: List[Dict[str, Any]] = []

    if not os.path.isfile(binary_path):
        return findings

    # Level 0: 汇编级回退检测
    try:
        from core.asm_detector import detect_from_assembly
        asm_findings = detect_from_assembly(binary_path, func_name)
        for af in asm_findings:
            if af.get('type') == 'format-string':
                findings.append(af)
    except ImportError:
        pass
    except Exception as e:
        _log.debug("Assembly FMT detection failed: %s", e)

    if func_name:
        target_funcs = [func_name]
    else:
        target_funcs = _list_user_functions(binary_path)

    # Level 1: 静态模式匹配
    for fname in target_funcs[:50]:
        decompiled = _decompile_function(binary_path, fname)
        if not decompiled:
            continue

        static_findings = _static_format_detect(fname, decompiled)
        # Level 1.5: 污点追踪
        try:
            from core.taint_source_tracker import trace_taint_source
            call_sigs = [(f['format_func'], f['format_arg']) for f in static_findings]
            taint_result = trace_taint_source(decompiled, fname, call_sigs)
            for f in static_findings:
                tv = taint_result.get(f['format_func'], {})
                if tv.get('tainted'):
                    f['confidence'] = min(1.0, f['confidence'] + 0.10)
                    f['taint_source'] = tv.get('source', 'user-controlled')
                else:
                    f['confidence'] = f['confidence'] * 0.40
                    f['taint_source'] = f'safe: {tv.get("source", "N/A")}'
        except ImportError:
            pass
        # Level 1.7: def-use链追踪
        try:
            from core.taint_flow_tracker import is_format_arg_user_controlled
            for f in static_findings:
                if f.get('confidence', 0) < 0.4:
                    continue
                disasm = _decompile_function(binary_path, fname)
                if not disasm:
                    continue
                lines = disasm.split('\n')
                for li, line in enumerate(lines):
                    if f['format_func'] in line and 'call' in line.lower():
                        controlled, src = is_format_arg_user_controlled(
                            lines, li, 'rdi')
                        if controlled and src.source_type == 'input_function':
                            f['confidence'] = min(1.0, f['confidence'] + 0.15)
                            f['def_use_trace'] = src.detail
                        elif src.source_type == 'constant':
                            f['confidence'] *= 0.5
                            f['def_use_trace'] = f'safe(constant): {src.detail}'
                        break
        except ImportError:
            pass
        findings.extend(static_findings)

    # Level 2: 约束验证
    try:
        from core.constraint_verifier import batch_verify
        findings = batch_verify(binary_path, findings, max_points=8)
    except ImportError:
        pass

    # Level 2.5: 符号执行偏移计算
    for finding in findings:
        if finding.get('confidence', 0) < 0.50:
            continue
        try:
            offset = _compute_format_offset(binary_path, finding)
            if offset >= 0:
                finding['offset'] = offset
                finding['confidence'] = min(1.0, finding['confidence'] + 0.15)
        except Exception:
            pass

    # Level 3: LLM 辅助
    if use_llm and findings:
        findings = _llm_enhance_findings(findings, binary_path)

    # Level 1.5: 污点分析增强
    for fname in target_funcs[:50]:
        decompiled = _decompile_function(binary_path, fname)
        if not decompiled:
            continue
        try:
            from core.taint_lite import analyze_taint
            state = analyze_taint(decompiled, fname)
            for warn in state.warnings:
                if warn['sink'] in _FORMAT_FUNCTIONS:
                    findings.append({
                        'function': fname, 'call_address': 0,
                        'format_func': warn['sink'],
                        'format_arg': warn['tainted_var'],
                        'offset': -1, 'confidence': 0.75,
                        'description': (
                            f'Tainted var {warn["tainted_var"]} reaches '
                            f'{warn["sink"]} via data-flow analysis'),
                        'exploitation': (
                            'User input reaches format string via '
                            'data-flow propagation.'),
                    })
        except ImportError:
            pass

    # Level 1.6: 间接调用检测
    for fname in target_funcs[:50]:
        decompiled = _decompile_function(binary_path, fname)
        if not decompiled:
            continue
        indirect_findings = _detect_indirect_format_call(fname, decompiled)
        findings.extend(indirect_findings)

    findings.sort(key=lambda f: (-f['confidence'], f['function']))
    return findings


def detect_with_taint_prefilter(
    binary_path: str,
    func_name: str = "",
    use_llm: bool = False,
) -> List[Dict[str, Any]]:
    """
    带污点预过滤的格式化字符串检测。

    先运行 taint_propagator 识别确实可达污点源的 sink,
    再对此子集运行完整的 3-level 检测。
    对非污点 sink 降低置信度 (但仍保留, 避免漏报)。
    """
    findings = detect_format_string_vulns(binary_path, func_name, use_llm)
    if not findings:
        return findings

    from core.taint_propagator import TaintPropagator
    tp = TaintPropagator()

    try:
        import subprocess, json
        from config import R2_PATH
        out = subprocess.check_output(
            [R2_PATH, '-q', '-c', f's {func_name}; pdc', binary_path],
            timeout=15, stderr=subprocess.DEVNULL,
        )
        pseudocode = out.decode('utf-8', errors='replace')
        taint_paths = tp.propagate(pseudocode, func_name)
    except Exception:
        return findings

    tainted_sinks = set()
    for tp_path in taint_paths:
        if tp_path.sink_type == 'FORMAT':
            tainted_sinks.add(tp_path.sink_func)

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
