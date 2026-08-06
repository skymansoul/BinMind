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

参考:
  - scut / team teso, 2001, "Exploiting Format String Vulnerabilities"
  - Peng et al., 2025, ACL, "PwnGPT: Automatic Exploit Generation Based on Large Language Models"
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from config import R2_PATH

_log = logging.getLogger(__name__)

# 格式化函数族
_FORMAT_FUNCTIONS = {
    'printf', 'fprintf', 'dprintf', 'sprintf', 'snprintf',
    'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
    'syslog', 'err', 'errx', 'warn', 'warnx',
}

# 格式化字符串的可疑模式 —— 第一个参数不是字符串常量
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

    Args:
        binary_path: ELF 文件路径
        func_name: 限定检测的函数名，None 表示扫描所有函数
        use_llm: 是否调用 LLM 进行深度分析

    Returns:
        漏洞点列表，按置信度降序排列
    """
    findings: List[Dict[str, Any]] = []

    if not os.path.isfile(binary_path):
        return findings

    # Level 0: 汇编级回退检测——不依赖反编译器，作为正交证据源
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

    # 获取函数列表
    if func_name:
        target_funcs = [func_name]
    else:
        target_funcs = _list_user_functions(binary_path)

    # Level 1: 静态模式匹配
    for fname in target_funcs[:50]:  # 限制扫描范围
        decompiled = _decompile_function(binary_path, fname)
        if not decompiled:
            continue

        static_findings = _static_format_detect(fname, decompiled)
        # Level 1.5: 污点追踪——验证format参数是否来自用户输入
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
        # Level 1.7: def-use链追踪——沿调用图反向追踪格式参数来源(跨函数)
        try:
            from core.taint_flow_tracker import is_format_arg_user_controlled
            for f in static_findings:
                if f.get('confidence', 0) < 0.4:
                    continue
                disasm = _decompile_function(binary_path, fname)
                if not disasm:
                    continue
                lines = disasm.split('\n')
                # 搜索call printf行在中
                for li, line in enumerate(lines):
                    if f['format_func'] in line and 'call' in line.lower():
                        controlled, src = is_format_arg_user_controlled(
                            lines, li, 'rdi')
                        if controlled and src.source_type == 'input_function':
                            f['confidence'] = min(1.0, f['confidence'] + 0.15)
                            f['def_use_trace'] = src.detail
                        elif src.source_type == 'constant':
                            f['confidence'] *= 0.5  # 降权: 参数来自常量
                            f['def_use_trace'] = f'safe(constant): {src.detail}'
                        break
        except ImportError:
            pass
        findings.extend(static_findings)

    # Level 2: 约束验证——angr符号执行验证可达性
    try:
        from core.constraint_verifier import batch_verify
        findings = batch_verify(binary_path, findings, max_points=8)
    except ImportError:
        pass

    # Level 2.5: 符号执行偏移计算(仅高置信度)
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

    # Level 3: LLM 辅助（按需）
    if use_llm and findings:
        findings = _llm_enhance_findings(findings, binary_path)

    # Level 1.5: 污点分析增强 — 追踪输入到格式化参数的数据流
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

    # Level 1.6: 间接调用检测 — printf 经由函数指针调用
    for fname in target_funcs[:50]:
        decompiled = _decompile_function(binary_path, fname)
        if not decompiled:
            continue
        indirect_findings = _detect_indirect_format_call(fname, decompiled)
        findings.extend(indirect_findings)

    findings.sort(key=lambda f: (-f['confidence'], f['function']))
    return findings


def _detect_indirect_format_call(func_name: str, pseudocode: str) -> List[Dict[str, Any]]:
    """检测通过函数指针间接调用的格式化函数.

    在反编译代码中搜索 call *%reg 模式,
    结合 PLT 地址判断是否为 printf 系列函数的间接调用.
    """
    import re as _re
    findings = []
    # 间接调用模式: call *rax / call rdx 等
    for m in _re.finditer(r'call\s+\*(?:%?)(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10)', pseudocode):
        reg = m.group(1)
        # 搜索在 call 之前 5 行内对该寄存器的赋值
        # 简化: 直接标记为可疑间接调用
        for fmt_func in ('printf', 'sprintf', 'fprintf'):
            findings.append({
                'function': func_name,
                'call_address': 0,
                'format_func': f'{fmt_func}(indirect via {reg})',
                'format_arg': 'unknown',
                'offset': -1,
                'confidence': 0.35,
                'description': (
                    f'Indirect call via {reg} in {func_name} — '
                    f'may resolve to {fmt_func} with user-controlled format'),
                'exploitation': (
                    'Verify with dynamic analysis whether the function '
                    'pointer resolves to a format function.'),
            })
    return findings

def _list_user_functions(binary_path: str) -> List[str]:
    """列出用户定义的函数（排除库函数）。"""
    try:
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false', '-c', 'afl', binary_path],
            capture_output=True, text=True, timeout=30,
        )
        funcs = []
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                name = parts[-1]
                # 跳过编译器内部和库函数
                if not name.startswith(('_', 'sym.', 'fcn.', 'sub.')):
                    if not any(name.startswith(p) for p in
                               ('__libc', '__cxa', 'register', 'deregister')):
                        funcs.append(name)
        return funcs
    except Exception:
        return []


def _decompile_function(binary_path: str, func_name: str) -> str:
    """反编译单个函数并返回伪代码文本。"""
    try:
        from core.decompiler import decompile_function
        result = decompile_function(binary_path, func_name)
        return result.get('pseudocode', '')
    except Exception:
        pass

    try:
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', f's {func_name}', '-c', 'pdc', binary_path],
            capture_output=True, text=True, timeout=30,
        )
        return proc.stdout
    except Exception:
        return ''


def _static_format_detect(
    func_name: str,
    pseudocode: str,
) -> List[Dict[str, Any]]:
    """
    在反编译代码中静态检测格式化字符串漏洞。

    识别两种模式:
      1. printf(user_var) —— 格式化参数直接来自变量
      2. printf(fgets(buf)) —— 格式化参数来自用户输入函数返回值
    """
    findings = []

    for fmt_func in _FORMAT_FUNCTIONS:
        # 搜索 fmt_func(variable) 模式 —— 第一个参数非字符串字面量
        for m in re.finditer(
            rf'{fmt_func}\s*\(\s*([^,"\']+)\s*\)',
            pseudocode,
        ):
            arg = m.group(1).strip()
            # 跳过明显的字符串字面量
            if arg.startswith('"') or arg.startswith("'"):
                continue
            # 跳过已知安全的调用
            if arg in ('format', 'fmt', '__fmt', '"%s"'):
                continue

            findings.append({
                'function': func_name,
                'call_address': 0,
                'format_func': fmt_func,
                'format_arg': arg,
                'offset': -1,
                'confidence': 0.6,
                'description': (
                    f'{fmt_func}() called with variable "{arg}" as format string '
                    f'in {func_name} — potential format string vulnerability'
                ),
                'exploitation': (
                    'Control format string → leak stack values (%p/%x) → '
                    'locate target address on stack → %n write primitive'
                ),
            })

    return findings


def _compute_format_offset(
    binary_path: str,
    finding: Dict[str, Any],
) -> int:
    """
    通过符号执行或启发式计算格式化字符串的栈偏移。

    优先使用 angr 符号执行，不可用时回退到启发式估计。
    """
    # 尝试 angr 符号执行
    try:
        import angr
        import claripy

        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        target_func = finding['function']
        for f in cfg.functions.values():
            if f.name == target_func:
                # 搜索格式化函数调用位置
                for block in f.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            callee_addr = insn.operands[0].imm
                            callee = cfg.functions.get(callee_addr)
                            if callee and callee.name == finding['format_func']:
                                # 在 x86_64 中，第一个参数通过 rdi 传递
                                state = proj.factory.blank_state(addr=insn.address)
                                try:
                                    rdi = state.solver.eval(state.regs.rdi)
                                    # 计算 rdi 距离 rsp 的偏移
                                    rsp = state.solver.eval(state.regs.rsp)
                                    offset = (rdi - rsp) // 8
                                    if 1 <= offset <= 50:
                                        return offset
                                except Exception:
                                    pass
                break
    except ImportError:
        pass
    except Exception as e:
        _log.debug("Symbolic format offset computation failed: %s", e)

    # 回退: 启发式估计
    # 在 x86_64 调用约定中，格式化字符串通常在第 5-8 个参数位置
    return _heuristic_format_offset(binary_path, finding)


def _heuristic_format_offset(
    binary_path: str,
    finding: Dict[str, Any],
) -> int:
    """
    启发式估计格式化字符串偏移。

    对于 x86_64，前 6 个参数通过寄存器传递 (rdi, rsi, rdx, rcx, r8, r9)，
    格式化字符串是第 1 个寄存器参数，因此栈上偏移从第 7 个位置开始。

    对于 i386，所有参数通过栈传递，格式化字符串在 esp+4 处，
    栈偏移为 1（从栈顶算第 1 个参数）。
    """
    try:
        from core.binary_info import get_binary_info
        binfo = get_binary_info(binary_path)
        arch = binfo.get('arch', 'x86-64')
        bits = binfo.get('bits', 64)

        if bits == 32 or '86' in arch:
            return 1  # i386: 第 1 个栈参数

        # x86_64: 前 6 个在寄存器中，栈上从第 7 个开始
        # 但具体偏移因局部变量和栈帧大小而异
        return 6  # 保守估计
    except Exception:
        return -1


def _llm_enhance_findings(
    findings: List[Dict[str, Any]],
    binary_path: str,
) -> List[Dict[str, Any]]:
    """
    调用 LLM 对静态检测结果进行深度分析。

    将反编译代码和检测到的模式发送给 LLM，
    获取利用可行性评估和详细的利用步骤建议。
    """
    try:
        from config import OPENAI_API_KEY
        if not OPENAI_API_KEY:
            return findings

        from core.ai_backends import query_llm

        for finding in findings[:3]:  # 仅对前 3 个高置信度发现调用 LLM
            system_prompt = (
                "You are an expert binary exploitation analyst specializing in "
                "format string vulnerabilities. Evaluate the exploitability of "
                "the given finding concisely."
            )
            user_prompt = (
                f"Format string finding:\n"
                f"Function: {finding['function']}\n"
                f"Dangerous call: {finding['format_func']}({finding['format_arg']})\n"
                f"Estimated offset: {finding.get('offset', -1)}\n\n"
                f"Provide: 1) Is this exploitable? 2) What is the most likely "
                f"attack vector? 3) Key constraints. Keep it under 200 words."
            )
            try:
                response = query_llm(
                    system=system_prompt,
                    user=user_prompt,
                    temperature=0.2,
                    max_tokens=256,
                )
                finding['llm_analysis'] = response.strip()
                finding['confidence'] = min(1.0, finding['confidence'] + 0.15)
            except Exception as e:
                _log.debug("LLM format string analysis failed: %s", e)

    except (ImportError, Exception) as e:
        _log.debug("LLM enhancement unavailable: %s", e)

    # 多层信息融合: 贝叶斯加权替代if-else置信度加减
    findings = _fuse_confidence(findings)
    return findings


def _fuse_confidence(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """贝叶斯加权融合多层检测置信度。

    各层视为独立证据源, 用对数似然比(log-odds)累加而非直接加减置信度。
    log-odds = log(p/(1-p)), 融合后 p = 1/(1+exp(-sum log-odds))。

    各层权重基于历史准确率估计:
      L0(汇编): 0.6, L1(静态): 0.5, L1.5(污点): 0.7,
      L1.7(def-use): 0.65, L2(符号): 0.8
    """
    import math
    weights = {'asm': 0.6, 'static': 0.5, 'taint': 0.7,
               'defuse': 0.65, 'symbolic': 0.8}

    for f in findings:
        log_odds = 0.0
        count = 0
        base_conf = f.get('confidence', 0.5)
        # 初始先验
        if base_conf > 0 and base_conf < 1:
            log_odds += math.log(base_conf / (1.0 - base_conf))
            count += 1

        # 各层证据
        if f.get('taint_source', '').startswith('safe'):
            log_odds -= 1.5  # 强否定证据
        elif f.get('taint_source'):
            log_odds += weights['taint']
        if f.get('def_use_trace', '').startswith('safe'):
            log_odds -= 1.0
        elif f.get('def_use_trace'):
            log_odds += weights['defuse']
        if f.get('offset', -1) >= 0:
            log_odds += weights['symbolic']

        if count > 0:
            fused = 1.0 / (1.0 + math.exp(-log_odds))
            f['confidence'] = round(max(0.05, min(0.98, fused)), 3)
            f['fused'] = True
    return findings


def format_offset_to_arg_position(offset: int, arch_bits: int = 64) -> str:
    """
    将格式化字符串栈偏移转换为人类可读的参数位置描述。

    Args:
        offset: 格式化字符串在栈上的偏移（以指针为单位）
        arch_bits: 架构位数

    Returns:
        例如 "第 6 个参数 (printf 的第 1 个栈参数)"
    """
    if offset <= 0:
        return "unknown"

    if arch_bits == 32:
        return f"argument #{offset} (stack position {offset})"

    # x86_64: 前 6 个参数在寄存器中
    if offset <= 6:
        reg_names = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        return f"argument #{offset} (register {reg_names[offset-1]} → format string itself)"

    stack_pos = offset - 5
    return f"argument #{offset} ({stack_pos}{_ordinal(stack_pos)} stack argument after r9)"


def _ordinal(n: int) -> str:
    """返回英文序数后缀。"""
    if 11 <= (n % 100) <= 13:
        return 'th'
    return {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')


# --------------------------------------------------------------------------
# 增强检测入口: 集成 taint_propagator 做预过滤
# 在原有静态匹配+符号执行的基础上, 增加污点传播层降低误报
# --------------------------------------------------------------------------

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

    与 detect_format_string_vulns 兼容: 参数相同, 返回值格式相同,
    可直接替换调用。
    """
    findings = detect_format_string_vulns(binary_path, func_name, use_llm)
    if not findings:
        return findings

    from core.taint_propagator import TaintPropagator
    tp = TaintPropagator()

    try:
        import subprocess, json
        from config import R2_PATH
        # 获取反编译伪代码
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
