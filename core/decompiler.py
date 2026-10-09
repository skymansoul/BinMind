# core/decompiler.py - 反编译接口 (radare2 / Ghidra 回退 + LLM 辅助审查)

import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Dict, List, Optional

from config import (
    DEFAULT_DECOMPILER, R2_PATH, SUBPROCESS_TIMEOUT,
    GHIDRA_TIMEOUT, OPENAI_API_KEY, AI_PROVIDER, LLM_ENDPOINTS,
)
from modules.llm_client import is_ai_configured, call_llm_simple

logger = logging.getLogger(__name__)


def strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)


def _run_radare2(binary_path: str, commands: List[str], timeout: int = 300) -> str:
    cmd = [R2_PATH, '-q', '-e', 'scr.color=false', '-e', 'scr.interactive=false']
    for c in commands:
        cmd.extend(['-c', c])
    cmd.append(binary_path)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding='utf-8', errors='replace',
                              timeout=timeout)
        return proc.stdout
    except subprocess.TimeoutExpired:
        return ''
    except FileNotFoundError:
        logger.warning("radare2 not found at %s", R2_PATH)
        return ''


# ---- r2 分析级别与调用图缓存 ----
# 原实现按"每个函数各起一个 radare2 进程"反编译, 且调用图按目标函数逐个
# 取回, 每个进程都从零跑一次全量分析(aaa)。N 个目标函数会产生约 3N+2 次
# 全量分析, 端到端耗时主要由这里决定。本节把分析级别做成可配置, 并让
# 调用图取回只做一次、供多个函数复用。

_BATCH_MARK = 'BINMIND-PDC:'
_BATCH_ASM_MARK = 'BINMIND-ASM:'
_BATCH_LINE_RE = re.compile(r'^BINMIND-(PDC|ASM):(.*)$')

_CALL_GRAPH_CACHE = {}
_CALL_GRAPH_CACHE_LIMIT = 4

# 伪代码进程内缓存: 主流水线已经反编译过的函数, 其它检测器(format_string_
# detector / rule_engine / stack_overflow_* 等)还会各自再调一次
# decompile_function 重新反编译。缓存后这些调用不再启动 radare2, 每次省下
# 一整次全量分析(aaa)。键含 decompiler, 避免不同后端结果互相覆盖。
_DECOMP_CACHE = {}
_DECOMP_CACHE_LIMIT = 256


def clear_decompile_cache() -> None:
    """清空伪代码与调用图缓存(换样本批处理时调用, 避免内存累积)。"""
    _DECOMP_CACHE.clear()
    _CALL_GRAPH_CACHE.clear()


def _decomp_cache_key(binary_path, func_name, decompiler):
    return (binary_path, func_name, decompiler or DEFAULT_DECOMPILER)


def _decomp_cache_put(key, result) -> None:
    if len(_DECOMP_CACHE) >= _DECOMP_CACHE_LIMIT:
        _DECOMP_CACHE.pop(next(iter(_DECOMP_CACHE)))
    _DECOMP_CACHE[key] = dict(result)


def _r2_analysis_level() -> str:
    """radare2 分析级别。

    默认 'aaa'(全量, 与历史结果口径一致)。设为 'aa' 可显著提速, 代价是
    间接调用与引用恢复变少, 属于精度与速度的显式取舍, 需先用评测脚本
    A/B 对比后再改。
    """
    return (os.environ.get('BINMIND_R2_ANALYSIS_LEVEL') or 'aaa').strip() or 'aaa'


def _fetch_call_graph_raw(binary_path: str, timeout: int = 60) -> str:
    """取回并缓存 r2 全局调用图(agCj)的原始输出。

    调用图与"要问哪个函数"无关, 一次分析取回一次即可复用于多个函数。
    """
    cached = _CALL_GRAPH_CACHE.get(binary_path)
    if cached is not None:
        return cached
    raw = _run_radare2(binary_path, [_r2_analysis_level(), 'agCj'],
                       timeout=timeout)
    if len(_CALL_GRAPH_CACHE) >= _CALL_GRAPH_CACHE_LIMIT:
        _CALL_GRAPH_CACHE.pop(next(iter(_CALL_GRAPH_CACHE)))
    _CALL_GRAPH_CACHE[binary_path] = raw
    return raw


def list_function_infos(binary_path: str) -> List[Dict]:
    """返回 r2 发现的函数元数据: {name, address, size}."""
    raw = _run_radare2(binary_path, ['aa', 'afl'], timeout=60)
    funcs = []
    for line in raw.splitlines():
        parts = strip_ansi(line).split()
        if len(parts) < 3:
            continue
        name = parts[-1]
        try:
            address = int(parts[0], 16) if parts[0].startswith('0x') else int(parts[0])
        except ValueError:
            address = 0
        size = 0
        for token in parts[1:-1]:
            try:
                size = int(token, 16) if token.startswith('0x') else int(token)
                break
            except ValueError:
                continue
        funcs.append({'name': name, 'address': address, 'size': size})
    return funcs


def list_functions(binary_path: str) -> List[str]:
    """返回 r2 发现的全部函数名。"""
    return [f['name'] for f in list_function_infos(binary_path)]


# r2 pdc 对 MSVC PE 的导入函数输出寄存器风格间接调用
# (rcx=参数; qword [sym.imp.*_malloc] ())。检测器正则无法从中
# 提取调用名与参数, 导致 malloc/free/memset 等完全失明。此函数
# 将调用前的寄存器参数合并为 C 风格调用, 便于下游检测器识别。
_MSVC_CALL_RE = re.compile(
    r'^(\s*)(?:qword\s*\[\s*sym\.imp\.[^\]]*?\.dll_|sub\.\w+\.dll_|sym\.)(\w+)\s*\]?\s*\(\)')
_MSVC_REG_NAME = (r'(?:r(?:[0-9]+|[a-d][xip]?|[sd]i|[b]p|[s]p)|'
                  r'e(?:[abcd]x|[sd]i|[b]p|[s]p)|r\d+[a-z]?)')
_MSVC_REG_ASSIGN = re.compile(
    r'^(\s*)(%s)\s*=\s*([^;]+?)\s*$' % _MSVC_REG_NAME)
_MSVC_REG_ALIAS = {
    'rax': ('eax',), 'rbx': ('ebx',), 'rcx': ('ecx',), 'rdx': ('edx',),
    'rsi': ('esi',), 'rdi': ('edi',), 'r8': ('r8d',), 'r9': ('r9d',),
}
_MSVC_RECURSIVE = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                   'r8', 'r9', 'r10', 'r11', 'r8d', 'r9d',
                   'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'}


def _msvc_clean(expr: str) -> str:
    """清理 r2 表达式行尾注释。"""
    return re.sub(r'\s*//.*$', '', expr).strip()


def _msvc_find_reg(lines: List[str], idx: int, reg: str):
    """向上查找最近的 reg = expr 赋值, 返回 (行号, 表达式)。"""
    names = (reg,) + _MSVC_REG_ALIAS.get(reg, ())
    for j in range(idx - 1, max(-1, idx - 12), -1):
        m = _MSVC_REG_ASSIGN.match(lines[j])
        if m and m.group(2) in names:
            return j, _msvc_clean(m.group(3))
    return None, None


# 移位赋值: rcx <<= 2 等价 rcx = rcx << 2 (malloc(n*4) 的乘法形态)
_MSVC_SHIFT_ASSIGN = re.compile(
    r'^(\s*)(%s)\s*<<<=\s*([^;]+?)\s*$' % _MSVC_REG_NAME)
# 调用行(返回值语义): atoi(...) / malloc(...) 等
_MSVC_CALL_LINE = re.compile(r'^\s*(\w+)\s*\(.*\)\s*$')
# MSVC import 间接调用行: qword [sym.imp.*.dll_NAME] () / sub.*.dll_NAME ()
_MSVC_IMP_CALL = re.compile(
    r'^\s*(?:qword\s*\[\s*sym\.imp\.[^\]]*?\.dll_|sub\.\w+\.dll_)(\w+)\s*\]?\s*\(\)')
# 无返回值语义的行首关键字
_MSVC_NOT_CALL = {'push', 'pop', 'if', 'while', 'for', 'switch', 'goto',
                  'return', 'jl', 'jg', 'jle', 'jge', 'je', 'jne', 'jb',
                  'ja', 'jmp', 're', 'call', 'else', 'do'}


def _msvc_call_before(lines: List[str], idx: int):
    """向上查找紧邻的函数调用行, 返回调用文本(寄存器=调用返回值场景)。

    最近 8 行内、跳过注释与标签行(loc_xxx:)后第一条非空语句是调用行
    时才认定; 遇到其他语句立即停止 — 返回值不会跨语句存活。
    MSVC import 间接调用(qword [sym.imp.*_atoi] ())规范化为 atoi()。
    """
    for k in range(idx - 1, max(-1, idx - 8), -1):
        s = lines[k].strip()
        if not s or s.startswith('//'):
            continue
        if s.endswith(':') and re.match(r'^[\w.]+:$', s):
            continue  # 基本块标签行, 非语句
        m = _MSVC_IMP_CALL.match(s)
        if m:
            return f'{m.group(1)}(?)'
        m = _MSVC_CALL_LINE.match(s)
        if m and m.group(1) not in _MSVC_NOT_CALL:
            return s
        return None
    return None


def _msvc_resolve_reg(lines: List[str], idx: int, reg: str,
                      depth: int = 0) -> str:
    """链式解析寄存器最终表达式 (rcx=rax; rax=dword[size] → dword[size])。

    向上取最近的语义行: 移位赋值(rcx <<= 2)折叠为 base<<n;
    普通赋值递归解析; 返回值寄存器(rax/eax)无显式赋值时, 若前邻
    函数调用行则视为该调用的返回值(ebx=eax + atoi(...) → atoi(...)),
    使污点链(malloc 参数 ← atoi)可被下游检测器识别。
    """
    if depth > 6:
        return '?'
    names = (reg,) + _MSVC_REG_ALIAS.get(reg, ())
    for j in range(idx - 1, max(-1, idx - 12), -1):
        line = lines[j]
        ms = _MSVC_SHIFT_ASSIGN.match(line)
        if ms and ms.group(2) in names:
            base = _msvc_resolve_reg(lines, j, reg, depth + 1)
            return f'{base} << {_msvc_clean(ms.group(3))}'
        m = _MSVC_REG_ASSIGN.match(line)
        if m and m.group(2) in names:
            v = _msvc_clean(m.group(3))
            if v in _MSVC_RECURSIVE:
                return _msvc_resolve_reg(lines, j, v, depth + 1)
            return v
    # 无显式赋值: 返回值寄存器前邻函数调用则为调用返回值
    if reg in ('rax', 'eax'):
        call = _msvc_call_before(lines, idx)
        if call:
            return call
    return '?'


def _normalize_msvc_calls(pseudocode: str) -> str:
    """MSVC 反编译伪代码调用规整化: 寄存器参数合并为 C 风格调用。

    处理 malloc/free/memset/memcpy/atoi, 并把 qword [ptr] 内存引用
    变量化为 ptr, 使下游检测器(heap/int/uaf)能正常识别堆操作。
    兼容两种形态: MSVC import 间接调用(qword [sym.imp.*_malloc] ())与
    mingw 直调空参形态(sym.malloc ())——参数均由调用前寄存器赋值提供。
    """
    lines = pseudocode.splitlines()
    out = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _MSVC_CALL_RE.match(line)
        if m:
            fn = m.group(2)
            indent = m.group(1)
            if fn in ('malloc', 'calloc', 'realloc'):
                size = (_msvc_resolve_reg(lines, i, 'rcx')
                        or _msvc_resolve_reg(lines, i, 'ecx') or '?')
                # 跳过调用后的注释行(r2 常输出 // void *malloc(?)),
                # 再查找返回值捕获: qword [var] = rax(MSVC) 或 p = rax(mingw)
                j = i + 1
                while j < n and re.match(r'^\s*//', lines[j]):
                    j += 1
                if j < n:
                    m2 = re.match(
                        r'^(\s*)(?:qword\s*\[\s*(\w+)\s*\]|(\w[\w]*))\s*=\s*rax\s*$',
                        lines[j])
                    if m2:
                        lhs = m2.group(2) or m2.group(3)
                        out.append(
                            f"{m2.group(1)}{lhs} = {fn}({size})")
                        i = j + 1
                        continue
                out.append(f"{indent}{fn}({size})")
            elif fn == 'free':
                out.append(f"{indent}free({_msvc_resolve_reg(lines, i, 'rcx') or '?'})")
            elif fn == 'memset':
                out.append(f"{indent}memset("
                           f"{_msvc_resolve_reg(lines, i, 'rcx') or '?'}, "
                           f"{_msvc_resolve_reg(lines, i, 'edx') or '?'}, "
                           f"{_msvc_resolve_reg(lines, i, 'r8') or _msvc_resolve_reg(lines, i, 'r8d') or '?'})")
            elif fn == 'memcpy':
                out.append(f"{indent}memcpy("
                           f"{_msvc_resolve_reg(lines, i, 'rcx') or '?'}, "
                           f"{_msvc_resolve_reg(lines, i, 'rdx') or '?'}, "
                           f"{_msvc_resolve_reg(lines, i, 'r8') or _msvc_resolve_reg(lines, i, 'r8d') or '?'})")
            elif fn == 'atoi':
                out.append(f"{indent}atoi({_msvc_resolve_reg(lines, i, 'rcx') or '?'})")
            else:
                # 通用参数还原: 非白名单的 sym.* 空参调用(如 __mingw_printf),
                # 按 x64 调用约定解析 rcx/rdx/r8/r9, 使 free 后经输出函数
                # 传入的指针可被下游 UAF 检测器识别(call(printf) 参数解引用)
                args = []
                for _reg in ('rcx', 'rdx', 'r8', 'r9'):
                    _v = _msvc_resolve_reg(lines, i, _reg)
                    if _v and _v != '?':
                        args.append(_v)
                    else:
                        break
                if args:
                    out.append(f"{indent}{fn}({', '.join(args)})")
                else:
                    out.append(line)
            i += 1
            continue
        out.append(line)
        i += 1
    pc = '\n'.join(out)
    # 内存引用变量化: qword [ptr] -> ptr (仅单一变量, 复合索引保留)
    pc = re.sub(r'\b(?:qword|dword|byte|word)\s*\[\s*(\w+)\s*\]', r'\1', pc)
    return pc


# C 运行时/标准库函数名集合, 用于过滤调用图中的 CRT 噪声
# 只收录最常见的; 不追求完备, 遗漏的 CRT 函数由 simulation 排除规则兜底
_CRT_NAMES = {
    'malloc', 'free', 'calloc', 'realloc',
    'memcpy', 'memset', 'memmove', 'memcmp',
    'strcpy', 'strncpy', 'strcat', 'strncat', 'strlen', 'strcmp', 'strncmp',
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
    'puts', 'putchar', 'fputc', 'fwrite', 'fread', 'fopen', 'fclose', 'fflush',
    'exit', 'abort', 'atexit',
    'atoi', 'atof', 'strtol', 'strtod',
    'setvbuf', 'signal', 'system',
    'strnlen', 'wcrtomb', 'mbrtowc', 'localeconv',
}


def get_callees(binary_path: str, func_name: str,
                all_funcs: List[str] = None) -> List[str]:
    """返回指定函数调用的全部用户函数名(call graph 子节点)。

    通过 radare2 全局调用图(agCj)提取, 用于 priority 匹配后
    扩展 target_funcs, 覆盖漏洞代码在 main 调用的子函数中的场景。
    过滤 CRT/标准库函数, 仅保留可能的用户函数。
    """
    raw = _fetch_call_graph_raw(binary_path, timeout=60)
    if not raw.strip():
        return []
    func_set = set(all_funcs) if all_funcs else None
    # 构建去前缀映射用于模糊匹配目标函数
    by_stripped = {}
    if all_funcs:
        for f in all_funcs:
            stripped = f.split('.')[-1] if '.' in f else f
            by_stripped.setdefault(stripped, f)
    target_stripped = func_name.split('.')[-1] if '.' in func_name else func_name
    callees = []
    try:
        for node in json.loads(raw):
            node_name = node.get('name', '')
            # 匹配目标函数: 精确匹配或去前缀匹配
            if node_name != func_name:
                node_stripped = node_name.split('.')[-1] if '.' in node_name else node_name
                if node_stripped != target_stripped:
                    continue
            for imp in node.get('imports', []):
                if not imp or imp == func_name:
                    continue
                # 过滤 CRT 函数: 已知名或下划线开头
                imp_stripped = imp.split('.')[-1] if '.' in imp else imp
                if imp_stripped in _CRT_NAMES:
                    continue
                if imp_stripped.startswith('_'):
                    continue
                # 过滤导入函数(sym.imp.*)
                if '.imp.' in imp:
                    continue
                # agCj 和 afl 的函数名前缀可能不同(dbg. vs sym.)
                # 用去前缀名匹配 all_funcs, 统一为 afl 命名
                resolved = imp
                if func_set is not None and imp not in func_set:
                    resolved = by_stripped.get(imp_stripped, '')
                    if not resolved:
                        continue
                if resolved not in callees:
                    callees.append(resolved)
            break
    except (json.JSONDecodeError, TypeError):
        pass
    return callees


def get_callees_map(binary_path: str, func_names,
                    all_funcs: List[str] = None) -> Dict[str, List[str]]:
    """一次取回调用图, 为多个函数同时计算被调用者。

    与逐个调用 get_callees 结果一致: 调用图已缓存, 这里的多次调用不会
    再启动 radare2, 只重复内存解析。
    """
    return {name: get_callees(binary_path, name, all_funcs)
            for name in (func_names or [])}


def decompile_functions_batch(binary_path: str, func_names,
                              decompiler: str = 'auto',
                              include_asm: bool = False,
                              timeout: int = 180) -> Dict[str, Dict]:
    """在一次 radare2 进程内反编译多个函数。

    返回 {func_name: {'pseudocode': str, 'raw_asm': str}}。只收录解析出
    非空伪代码的函数; 其余不出现, 调用方应回退到 decompile_function。

    include_asm=False 时不取 pdf 反汇编: 主流水线的规则检测与 AI 研判
    只消费伪代码, 取反汇编等于把反编译开销再翻一倍。

    已知边界: 若某函数名在 r2 中 seek 失败, pdc 会停留在上一个函数的
    位置并输出与上一段逐字相同的文本; 这类重复段按不可信处理并丢弃,
    由调用方回退单函数路径复核。
    """
    out: Dict[str, Dict] = {}
    names = [n for n in (func_names or []) if n]
    if decompiler not in ('auto', 'r2') or not names:
        return out

    cmds = [_r2_analysis_level()]
    for name in names:
        cmds.append('s %s' % name)
        cmds.append('?e %s%s' % (_BATCH_MARK, name))
        cmds.append('pdc')
        if include_asm:
            cmds.append('?e %s%s' % (_BATCH_ASM_MARK, name))
            cmds.append('pdf')

    raw = _run_radare2(binary_path, cmds, timeout=timeout)
    if not raw.strip():
        logger.warning("batch decompile produced no output")
        return out

    sections = {}
    key = None
    buf = []
    for line in raw.splitlines():
        m = _BATCH_LINE_RE.match(line.strip())
        if m:
            if key is not None:
                sections[key] = '\n'.join(buf)
            key = (m.group(1), m.group(2).strip())
            buf = []
        elif key is not None:
            buf.append(line)
    if key is not None:
        sections[key] = '\n'.join(buf)

    prev = None
    for name in names:
        pseudo = sections.get(('PDC', name), '')
        if not pseudo.strip():
            continue
        norm = _normalize_msvc_calls(strip_ansi(pseudo))
        if norm and norm == prev:
            logger.debug("batch pdc duplicate section for %s, skipped", name)
            prev = norm
            continue
        prev = norm
        out[name] = {
            'pseudocode': norm,
            'raw_asm': strip_ansi(sections.get(('ASM', name), '')),
        }
        # 回填进程内缓存: 批量路径的结果对后续 decompile_function 调用可见,
        # 使检测器不再各自重新反编译。
        _decomp_cache_put(
            _decomp_cache_key(binary_path, name, decompiler), out[name])
    return out


def decompile_function(binary_path: str, func_name: str,
                       decompiler: str = None) -> Dict:
    """反编译单个函数(带进程内缓存), 返回 {name, pseudocode, raw_asm}。

    同一 (目标, 函数, 后端) 在本进程内只真正反编译一次。主流水线已批量
    反编译过的函数, 后续检测器再问时直接命中缓存, 不再启动 radare2 ——
    这是消除"多检测器各自重复反编译"的关键。
    """
    key = _decomp_cache_key(binary_path, func_name, decompiler)
    cached = _DECOMP_CACHE.get(key)
    if cached is not None:
        logger.debug("decompile cache hit: %s", func_name)
        return dict(cached)
    result = _decompile_function_uncached(binary_path, func_name, decompiler)
    _decomp_cache_put(key, result)
    return result


def _decompile_function_uncached(binary_path: str, func_name: str,
                                 decompiler: str = None) -> Dict:
    """真正执行反编译的路径(无缓存), 由 decompile_function 调用。

    decompiler='auto' 时先试 r2, 失败回退 Ghidra。
    """
    if decompiler is None:
        decompiler = DEFAULT_DECOMPILER

    result = {
        'name': func_name,
        'pseudocode': '',
        'raw_asm': '',
        'decompiler': decompiler,
    }

    if decompiler in ('auto', 'r2'):
        # try r2 decompiler
        # pdc 对病态循环函数可能挂满超时(2026-09-16 评测实锤: io_loop_counter
        # 的 main 挂满 120s 拖死整批), 30s 快速放弃转 Ghidra 回退, 正常函数(<2s)无影响
        raw = _run_radare2(binary_path, ['aaa', f's {func_name}', 'pdc'], timeout=30)
        result['pseudocode'] = _normalize_msvc_calls(strip_ansi(raw))
        # pdc 病态时 pdf 大概率同病态(同一函数图), 同样 30s 快速放弃
        raw_asm = _run_radare2(binary_path, ['aaa', f's {func_name}', 'pdf'], timeout=30)
        result['raw_asm'] = strip_ansi(raw_asm)
        if result['pseudocode'].strip():
            result['decompiler'] = 'r2'
            return result

    if decompiler in ('auto', 'ghidra'):
        ghidra_result = _decompile_ghidra(binary_path, func_name)
        if ghidra_result:
            result['pseudocode'] = ghidra_result.get('pseudocode', '')
            result['decompiler'] = 'ghidra'
            return result

    return result


def _decompile_ghidra(binary_path: str, func_name: str) -> Optional[Dict]:
    """Ghidra headless 反编译; 未配置 GHIDRA_HOME 时返回 None。"""
    try:
        ghidra_home = os.environ.get('GHIDRA_HOME', '')
        if not ghidra_home:
            return None

        with tempfile.TemporaryDirectory() as tmpdir:
            analyze_headless = os.path.join(ghidra_home, 'support', 'analyzeHeadless')
            cmd = [
                analyze_headless,
                tmpdir, 'TempProject',
                '-import', binary_path,
                '-postScript', 'DecompileFunction.java', func_name,
            ]
            subprocess.run(cmd, capture_output=True, timeout=GHIDRA_TIMEOUT)
            # 脚本产物: <func_name>.c
            out_file = os.path.join(tmpdir, f'{func_name}.c')
            if os.path.isfile(out_file):
                with open(out_file, encoding='utf-8') as fh:
                    return {'pseudocode': fh.read(), 'source': 'ghidra'}
    except Exception as err:
        logger.debug("ghidra headless failed for %s: %s", func_name, err)
    return None


# AI 辅助分析

_AI_SYSTEM_PROMPT = """You are a binary reverse-engineering expert.
Analyze the provided decompiled C code for security vulnerabilities.
Report buffer overflows, format string bugs, integer overflows,
use-after-free, double-free, race conditions, and logic flaws.
For each vulnerability found, provide:
- type: the vulnerability class
- severity: Critical/High/Medium/Low
- location: function name or address
- description: what makes this exploitable
- cwe: the CWE number if applicable
Output as JSON with a "vulnerabilities" array."""


# 启发式危险函数模式, 降级模拟分析时用于推断候选漏洞
_DANGER_PATTERNS = [
    (re.compile(r'\bstrcpy\s*\(', re.IGNORECASE), 'buffer_overflow',
     'CWE-120', 'strcpy 无边界检查', 'High'),
    (re.compile(r'\bstrcat\s*\(', re.IGNORECASE), 'buffer_overflow',
     'CWE-120', 'strcat 无边界检查', 'High'),
    (re.compile(r'\bgets\s*\(', re.IGNORECASE), 'buffer_overflow',
     'CWE-242', 'gets 为不安全函数', 'Critical'),
    (re.compile(r'\bsprintf\s*\(', re.IGNORECASE), 'format_string',
     'CWE-134', 'sprintf 潜在格式化字符串漏洞', 'High'),
    (re.compile(r'\bprintf\s*\([^)]*%[^\)]*\)', re.IGNORECASE), 'format_string',
     'CWE-134', 'printf 含格式化占位符', 'Medium'),
    (re.compile(r'\bmemcpy\s*\(', re.IGNORECASE), 'buffer_overflow',
     'CWE-120', 'memcpy 需检查长度参数', 'Medium'),
    (re.compile(r'\bfree\s*\(', re.IGNORECASE), 'use_after_free',
     'CWE-416', 'free 后需置空指针', 'Low'),
    (re.compile(r'\bmalloc\s*\(', re.IGNORECASE), 'integer_overflow',
     'CWE-190', 'malloc 参数需检查整数溢出', 'Low'),
    (re.compile(r'\bsystem\s*\(', re.IGNORECASE), 'command_injection',
     'CWE-78', 'system 调用需检查输入来源', 'High'),
]


def _heuristic_analyze(func_name: str, pseudocode: str) -> Dict:
    """启发式模拟分析: 基于危险函数模式推断候选漏洞, 返回结构化结果。

    无 LLM 配置时作为降级路径, 保证管道拿到非空 findings。
    """
    vulns = []
    for pat, vtype, cwe, desc, severity in _DANGER_PATTERNS:
        for m in pat.finditer(pseudocode):
            vulns.append({
                'type': vtype,
                'severity': severity,
                'location': func_name,
                'description': desc,
                'cwe': cwe,
                'evidence_snippet': pseudocode[max(0, m.start() - 20):m.end() + 20],
            })

    return {
        'function': func_name,
        'vulnerabilities': vulns,
        'summary': f'启发式模拟分析: 识别 {len(vulns)} 个候选漏洞' if vulns
                   else '启发式模拟分析: 未发现明显危险函数调用',
        'pseudocode': pseudocode,
        'simulation': True,
        'analysis_mode': 'heuristic_fallback',
    }


def ai_analyze_function(func_name: str, pseudocode: str,
                        binary_info: Dict = None) -> Dict:
    """LLM 审查反编译代码, 走 modules.llm_client 统一入口。

    未配置 AI 时降级为启发式模拟分析, 返回带 simulation 标记的结构化结果。
    """
    if not pseudocode or not pseudocode.strip():
        return {'function': func_name, 'vulnerabilities': [], 'summary': ''}

    # 未配置 AI 凭据时降级为启发式模拟, 不返回空结果
    if not is_ai_configured():
        logger.info("AI 未配置, 函数 %s 降级为启发式模拟分析", func_name)
        return _heuristic_analyze(func_name, pseudocode)

    context = f'Arch: {binary_info.get("arch", "unknown")}, ' \
              f'Format: {binary_info.get("format", "unknown")}' \
              if binary_info else ''

    user_prompt = f"""Analyze this decompiled function for vulnerabilities.

Binary context: {context}
Function: {func_name}

```c
{pseudocode[:8000]}
```

Report vulnerabilities as JSON."""

    try:
        result = call_llm_simple(
            prompt=user_prompt,
            system_prompt=_AI_SYSTEM_PROMPT,
            temperature=0.3,
        )

        # 统一入口返回 simulation=True 时降级为启发式
        if result.get('simulation'):
            logger.info("LLM 调用进入模拟模式, 函数 %s 降级为启发式分析", func_name)
            heuristic = _heuristic_analyze(func_name, pseudocode)
            heuristic['llm_error'] = result.get('error', '')
            return heuristic

        response = result.get('text', '')
        findings = result.get('findings', [])

        if findings:
            return {
                'function': func_name,
                'vulnerabilities': findings,
                'summary': f'LLM 分析: 识别 {len(findings)} 个漏洞',
                'pseudocode': pseudocode,
                'simulation': False,
                'model': result.get('model', ''),
            }

        # LLM 返回但未解析出 findings, 尝试原始 JSON 提取
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            parsed = json.loads(json_match.group(0))
            parsed['function'] = func_name
            parsed['pseudocode'] = pseudocode
            parsed['simulation'] = False
            return parsed

        return {
            'function': func_name,
            'vulnerabilities': [],
            'summary': response[:200] if response else 'LLM 未返回有效内容',
            'pseudocode': pseudocode,
            'simulation': False,
        }
    except Exception as e:
        logger.warning("AI analysis failed for %s: %s, 降级为启发式", func_name, e)
        heuristic = _heuristic_analyze(func_name, pseudocode)
        heuristic['llm_error'] = str(e)
        return heuristic
