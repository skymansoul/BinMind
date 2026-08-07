"""
栈溢出分析器静态层 — 静态CFG分析/canary检测/策略推荐/exploit参数/pattern回退.

"""


import logging
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# 危险函数调用的常见缓冲区大小模式（用于静态估算）
_DIRTY_CALLS = {
    'gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'read',
    'fgets', 'recv', 'recvfrom', 'getline',
}


def _static_overflow_analysis(
    binary_path: str,
    func_name: str,
    binfo: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """静态回退分析(增强版)——反向污点追踪 + 缓冲区大小估算.

    对每个危险调用做反向def-use链追踪, 验证参数是否来自用户输入源.
    若参数来自安全源(常量字符串/snprintf格式化), 不标记为危险.
    """
    result: Dict[str, Any] = {'overflowable': False, 'padding': 0, 'insights': []}

    try:
        from core.decompiler import decompile_function
        decomp = decompile_function(binary_path, func_name)
        pseudocode = decomp.get('pseudocode', '')

        if not pseudocode:
            return result

        # 污点追踪 —— 验证危险调用的参数是否来自用户输入
        try:
            from core.taint_source_tracker import trace_taint_source
            call_sigs = []
            import re as _re
            for call in _DIRTY_CALLS:
                for m in _re.finditer(rf'({call})\s*\(\s*([^,)]+)', pseudocode):
                    call_sigs.append((call, m.group(2).strip()))

            taint_result = trace_taint_source(pseudocode, func_name, call_sigs)
            tainted_calls = {k for k, v in taint_result.items()
                           if v.get('tainted')}
            if tainted_calls:
                result['overflowable'] = True
                result['insights'].append(
                    f"Taint tracking: {len(tainted_calls)} dangerous call(s) "
                    f"with user-controlled buffer"
                )
                result['insights'].append(
                    f"Tainted calls: {', '.join(sorted(tainted_calls)[:3])}"
                )
            else:
                result['overflowable'] = False
                result['insights'].append(
                    "Taint tracking: dangerous calls found but args not user-controlled"
                )
        except ImportError:
            for call in _DIRTY_CALLS:
                if call in pseudocode:
                    result['overflowable'] = True
                    result['insights'].append(
                        f"Static pattern: dangerous call to {call} detected (taint tracker unavailable)"
                    )

        # 估算缓冲区大小
        if result['overflowable']:
            import re
            buf_matches = re.findall(
                r'char\s+\w+\s*\[(\d+)\]', pseudocode
            )
            if buf_matches:
                max_buf = max(int(m) for m in buf_matches)
                bits = binfo.get('bits', 64) if binfo else 64
                saved_rbp = 8 if bits == 64 else 4
                result['padding'] = max_buf + saved_rbp
                result['insights'].append(
                    f"Estimated padding: {max_buf}B buffer + {saved_rbp}B saved rbp = {result['padding']}"
                )
            else:
                result['padding'] = 72
                result['insights'].append(
                    "No local buffer declaration found, using default padding=72"
                )

    except Exception as e:
        _log.debug("Static overflow analysis failed: %s", e)

    return result


def _detect_canary_in_function(binary_path: str, func_name: str) -> bool:
    """检测目标函数是否启用了栈 canary 保护。

    通过 r2 反汇编搜索 __stack_chk_fail 调用来判断。
    """
    try:
        import subprocess
        from config import R2_PATH

        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', f's {func_name}', '-c', 'pdf~__stack_chk', binary_path],
            capture_output=True, text=True, timeout=30,
        )
        if '__stack_chk_fail' in proc.stdout:
            return True
    except Exception:
        pass

    # angr 回退
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        for f in cfg.functions.values():
            if f.name == func_name:
                for block in f.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            target = insn.operands[0].imm
                            callee = cfg.functions.get(target)
                            if callee and callee.name == '__stack_chk_fail':
                                return True
    except Exception:
        pass

    return False


def _recommend_strategy(
    analysis: Dict[str, Any],
    binfo: Optional[Dict[str, Any]],
    libc_info: Optional[Dict[str, Any]],
) -> str:
    """基于分析结果推荐利用策略。"""
    if not analysis.get('overflowable'):
        return 'no-overflow-detected'

    has_canary = analysis.get('has_canary', False)

    if not has_canary:
        return 'direct-ret-overwrite'

    if analysis.get('canary_leak_path'):
        return 'canary-leak-then-overwrite'

    return 'brute-force-or-alternative'


def _build_exploit_params(
    analysis: Dict[str, Any],
    binfo: Optional[Dict[str, Any]],
    libc_info: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """构建 exploit 生成所需的参数集。"""
    params: Dict[str, Any] = {
        'offset': analysis.get('padding', 64),
        'has_canary': analysis.get('has_canary', False),
        'strategy': analysis.get('strategy', 'unknown'),
    }

    if libc_info and libc_info.get('symbols'):
        syms = libc_info['symbols']
        if 'system' in syms:
            params['system_offset'] = syms['system']
        if 'str_bin_sh' in syms:
            params['binsh_offset'] = syms['str_bin_sh']

    if binfo:
        params['arch'] = binfo.get('arch', 'x86-64')
        params['bits'] = binfo.get('bits', 64)

    return params


def analyze_with_pattern_fallback(
    binary_path: str,
    func_name: str,
    binfo: Optional[Dict[str, Any]] = None,
    libc_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """angr 优先, 失败时用 pattern_fallback 做汇编级模式匹配。

    返回格式与 analyze_stack_overflow 完全兼容。
    """
    from core.stack_overflow_analyzer import analyze_stack_overflow
    result = analyze_stack_overflow(binary_path, func_name, binfo, libc_info)

    # angr 成功 → 直接返回
    if result.get('overflowable') and not result.get('error'):
        result['method'] = 'angr'
        return result

    # angr 失败/超时/无结果 → 回退到 pattern_fallback
    import subprocess, json
    from config import R2_PATH
    from core.pattern_fallback import match_patterns

    try:
        out = subprocess.check_output(
            [R2_PATH, '-q', '-c', f's {func_name}; pdbj', binary_path],
            timeout=15, stderr=subprocess.DEVNULL,
        )
        disasm = json.loads(out)
        text = '\n'.join(op.get('disasm', '') for op in disasm.get('ops', []))
    except Exception:
        result['method'] = 'angr_failed'
        return result

    matches = match_patterns(text)
    so_matches = [m for m in matches if m.vuln_type == 'stack_overflow']

    if so_matches:
        best = so_matches[0]
        result['overflowable'] = True
        result['padding'] = 0
        result['has_canary'] = False
        result['strategy'] = 'pattern_fallback'
        result['method'] = 'pattern_fallback'
        result['pattern_confidence'] = best.confidence
        result['pattern_desc'] = best.pattern_desc
    else:
        result['method'] = 'pattern_fallback_no_match'

    return result
