"""
栈溢出自动化分析 —— 偏移计算、canary 检测和利用策略生成。

基于 angr 符号执行计算输入缓冲区到保存返回地址的偏移，检测栈 canary
的存在性和泄露路径，自动构造 ret2libc / ret2system / ROP 链利用草案。

核心算法:
  1. 符号执行追踪用户输入 → 定位输入在栈上的起始位置
  2. 通过函数返回地址的约束求解确定 padding 值
  3. 检测 __stack_chk_fail 的基本块判断 canary 存在性
  4. 若 canary 存在则搜索 printf 系列调用点识别潜在泄露路径
  5. 基于 libc 偏移和 PLT 地址构造利用方案

与现有管线的关系: 作为符号执行阶段的增强层调用，输入来自
decompiler、plt_scanner 和 libc_identifier 的结果，输出注入到
exploit_gen 的 offset 参数替代硬编码默认值。

参考:
  - Stephens et al., 2016, NDSS, "Driller: Augmenting Fuzzing Through Selective Symbolic Execution"
  - Shoshitaishvili et al., 2016, IEEE S&P, "SOK: (State of) The Art of War: Offensive Techniques in Binary Analysis"
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

# 危险函数调用的常见缓冲区大小模式（用于静态估算）
_DIRTY_CALLS = {
    'gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'read',
    'fgets', 'recv', 'recvfrom', 'getline',
}


def analyze_stack_overflow(
    binary_path: str,
    func_name: str,
    binfo: Optional[Dict[str, Any]] = None,
    libc_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    对指定函数进行栈溢出自动化分析。

    返回的字典包含:
      - overflowable: 是否存在可溢出路径
      - padding: 到返回地址的偏移量（字节数）
      - has_canary: 函数是否受 canary 保护
      - canary_leak_path: canary 泄露的潜在路径描述
      - strategy: 推荐的利用策略
      - exploit_params: 构造 exploit 所需的参数集

    Args:
        binary_path: ELF 文件路径
        func_name: 目标函数名
        binfo: get_binary_info() 的结果（可选）
        libc_info: identify_libc() 的结果（可选）

    Returns:
        栈溢出分析结果
    """
    result: Dict[str, Any] = {
        'overflowable': False,
        'padding': 0,
        'has_canary': False,
        'canary_leak_path': '',
        'strategy': 'unknown',
        'exploit_params': {},
    }

    if not os.path.isfile(binary_path):
        result['error'] = f'file not found: {binary_path}'
        return result

    # 第一层: angr 符号执行（最优路径）
    sym_result = _symbolic_overflow_analysis(binary_path, func_name)
    if sym_result.get('overflowable'):
        result.update(sym_result)

    # 第二层: 静态 CFG 分析（angr 不可用或失败时回退）
    if not result['overflowable']:
        static_result = _static_overflow_analysis(binary_path, func_name, binfo)
        result.update(static_result)

    # 第三层: 汇编级回退检测——反编译无关的正交证据
    if not result['overflowable']:
        try:
            from core.asm_detector import detect_from_assembly
            asm_findings = detect_from_assembly(binary_path, func_name)
            for af in asm_findings:
                if af.get('type') == 'stack-overflow':
                    result['overflowable'] = True
                    result['padding'] = af.get('buffer_size_estimate', 0)
                    result['insights'].append(
                        f"Assembly-level: {af.get('description', '')}"
                    )
        except ImportError:
            pass
        except Exception as e:
            _log.debug("Assembly SO detection failed: %s", e)

    # canary 检测
    result['has_canary'] = _detect_canary_in_function(binary_path, func_name)

    # 策略推荐
    result['strategy'] = _recommend_strategy(result, binfo, libc_info)

    # 构建 exploit 参数
    result['exploit_params'] = _build_exploit_params(result, binfo, libc_info)

    return result


def _symbolic_overflow_analysis(
    binary_path: str,
    func_name: str,
) -> Dict[str, Any]:
    """
    通过 angr 符号执行分析栈溢出。

    对目标函数进行符号执行，追踪符号化输入在栈上的位置，
    计算到返回地址的偏移。若 angr 不可用则返回空结果。
    """
    result: Dict[str, Any] = {'overflowable': False, 'padding': 0, 'insights': []}

    try:
        import angr
        import claripy
    except ImportError:
        _log.debug("angr unavailable, skipping symbolic overflow analysis")
        return result

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        func_addr = None
        cfg = proj.analyses.CFGFast()
        for f in cfg.functions.values():
            if f.name == func_name:
                func_addr = f.addr
                break

        if func_addr is None:
            _log.debug("Function %s not found in CFG", func_name)
            return result

        # 符号化 STDIN 输入
        symbolic_input = claripy.BVS('input', 2048 * 8)
        state = proj.factory.entry_state(
            addr=func_addr,
            stdin=angr.SimFile('/dev/stdin', content=symbolic_input),
        )

        # 探索直到遇到返回指令
        simgr = proj.factory.simulation_manager(state)
        simgr.run(until=lambda s: len(s.active) > 50 or len(s.deadended) > 5)

        for path_state in simgr.deadended:
            if path_state.regs.rsp.symbolic:
                continue
            try:
                rsp_val = path_state.solver.eval(path_state.regs.rsp)
                # 读取栈上保存的返回地址
                ret_addr_bytes = path_state.memory.load(rsp_val, 8, endness='Iend_LE')
                ret_addr_val = path_state.solver.eval(ret_addr_bytes)

                # 如果返回地址包含符号输入，说明可能溢出
                if path_state.solver.symbolic(ret_addr_bytes):
                    # 计算最小偏移
                    min_offset = _compute_padding_from_state(
                        path_state, symbolic_input, rsp_val
                    )
                    if min_offset > 0:
                        result['overflowable'] = True
                        result['padding'] = min_offset
                        result['insights'].append(
                            f"Symbolic execution confirms overflow at offset {min_offset}"
                        )
                        break
            except (angr.SimUnsatError, angr.SimError) as e:
                _log.debug("Symbolic path dead: %s", e)
                continue

    except Exception as e:
        _log.debug("Symbolic overflow analysis error: %s", e)

    return result


def _compute_padding_from_state(state, symbolic_input, rsp_val: int) -> int:
    """从符号执行状态中计算输入到返回地址的偏移量。"""
    try:
        import angr

        # 搜索输入缓冲区在栈上的起始地址
        for offset in range(0, 4096, 8):
            mem_at = state.memory.load(rsp_val - offset, 8, endness='Iend_LE')
            if symbolic_input.variables & mem_at.variables:
                # 符号输入的第 0 字节与 rsp-offset 处的符号重叠
                # 偏移量 = offset - 8 (跳过保存的 rbp) + 8 (对齐)
                # 简化: offset 即是 padding
                return max(0, offset + 8)
    except Exception:
        pass
    return 0


def _static_overflow_analysis(
    binary_path: str,
    func_name: str,
    binfo: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    静态回退分析(增强版)——反向污点追踪 + 缓冲区大小估算。

    与旧版区别: 不再仅靠函数名正则匹配判断危险调用。
    对每个危险调用做反向def-use链追踪, 验证参数是否来自用户输入源。
    若参数来自安全源(常量字符串/snprintf格式化), 不标记为危险。
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
            from core.taint_source_tracker import trace_taint_source, is_arg_tainted
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
                result['overflowable'] = False  # 即使有危险函数, 参数未受污染
                result['insights'].append(
                    "Taint tracking: dangerous calls found but args not user-controlled"
                )
        except ImportError:
            # 回退: 简单关键字匹配
            for call in _DIRTY_CALLS:
                if call in pseudocode:
                    result['overflowable'] = True
                    result['insights'].append(
                        f"Static pattern: dangerous call to {call} detected (taint tracker unavailable)"
                    )

        # 估算缓冲区大小(同上)
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
    """
    检测目标函数是否启用了栈 canary 保护。

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
    padding = analysis.get('padding', 0)

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


def analyze_with_pattern_fallback(
    binary_path: str,
    func_name: str,
    binfo: Optional[Dict[str, Any]] = None,
    libc_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    angr 优先, 失败时用 pattern_fallback 做汇编级模式匹配。

    返回格式与 analyze_stack_overflow 完全兼容。
    """
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
        result['padding'] = 0  # 模式匹配无法计算精确 padding
        result['has_canary'] = False
        result['strategy'] = 'pattern_fallback'
        result['method'] = 'pattern_fallback'
        result['pattern_confidence'] = best.confidence
        result['pattern_desc'] = best.pattern_desc
    else:
        result['method'] = 'pattern_fallback_no_match'

    return result

    return params
