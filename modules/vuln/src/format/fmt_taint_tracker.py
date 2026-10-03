"""FMT-SPEC 污点追踪器 — 二进制级寄存器逆向追踪: 格式串来源→函数参数 vs .rdata.

核心: 对每个printf调用, 前向追踪格式串寄存器的来源指令.
  mov reg,[rbp+0x10] → 函数参数 (可能用户可控) → TAINTED
  lea reg,[rip+off] → .rdata 常量 → SAFE

创建: 2025-04-17
"""
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 外部输入源

# 调用这些函数后, rax 或特定寄存器包含外部数据
_INPUT_SOURCES = {
    'recv', 'recvfrom', 'recvmsg', 'fgets', 'fgetc', 'getc',
    'getchar', 'read', 'fread', 'gets', 'gets_s',
    'scanf', 'fscanf', 'sscanf', 'getenv', 'getenv_s',
    'getpass', 'GetEnvironmentVariable', 'RegQueryValueEx',
    'getopt', 'getopt_long', '__getmainargs', 'GetCommandLineW',
    'CommandLineToArgvW', '__wgetmainargs',
}

# 这些调用返回后, 特定内存地址包含用户数据
_ARGV_ACCESS_RE = re.compile(
    r'(?:mov|lea).*(?:argv|argc|argv\[)', re.I)

# 这些是printf-family函数
_PRINTF_FNS = {
    'printf', 'fprintf', 'sprintf', 'snprintf', 'dprintf',
    'vsprintf', 'vsnprintf', 'vfprintf', 'vprintf', 'syslog',
    '__mingw_printf', '__printf_chk', '__fprintf_chk',
    # MinGW variants (GCC/MinGW O0样本广泛使用)
    '__mingw_fprintf', '__mingw_sprintf', '__mingw_snprintf',
    '__mingw_vfprintf', '__mingw_vsprintf', '__mingw_vsnprintf',
    '__mingw_vprintf', '__mingw_dprintf',
}

# Windows x64: 格式串参数在哪个寄存器
_FMT_ARG_REG = {
    'printf': 'rcx', 'fprintf': 'rdx', 'sprintf': 'rdx',
    'snprintf': 'r8', 'dprintf': 'rdx', 'vsprintf': 'rdx',
    'vsnprintf': 'r8', 'vfprintf': 'rdx', 'vprintf': 'rcx',
    'syslog': 'rdx', '__mingw_printf': 'rcx',
    '__printf_chk': 'rdx', '__fprintf_chk': 'r8',
    # MinGW variants — 遵循对应POSIX函数的参数约定
    '__mingw_fprintf': 'rdx', '__mingw_sprintf': 'rdx',
    '__mingw_snprintf': 'r8', '__mingw_vfprintf': 'rdx',
    '__mingw_vsprintf': 'rdx', '__mingw_vsnprintf': 'r8',
    '__mingw_vprintf': 'rcx', '__mingw_dprintf': 'rdx',
}


def _canon(r: str) -> str:
    m = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
         'esi': 'rsi', 'edi': 'rdi', 'r8d': 'r8', 'r9d': 'r9',
         'r10d': 'r10', 'r11d': 'r11'}
    return m.get(r.lower(), r.lower())


@dataclass
class TaintResult:
    """单个printf调用点的污点分析结果."""
    call_addr: int
    func: str
    fmt_reg: str
    tainted: bool = False
    source: str = ""                  # 污染来源 (argv/recv/getenv/...)
    taint_chain: List[str] = field(default_factory=list)  # 污染传播路径
    confidence: float = 0.0
    reason: str = ""


@dataclass
class TaintReport:
    """完整污点分析报告."""
    total_printf_calls: int
    tainted: List[TaintResult]
    safe_rdata: List[TaintResult]     # 格式串来自.rdata
    unknown: List[TaintResult]        # 无法确定来源
    input_sources_found: List[str]


def _trace_reg_source(objdump_lines: List[str], call_idx: int,
                      target_reg: str, max_back: int = 40) -> str:
    """逆向追踪格式串寄存器的来源.

    返回 'param:rbp+0x10' (函数形参) | 'rdata:0x...' (.rdata) |
    'mov:rax' (寄存器链) | 'imm:0x...' (常量) | 'unknown'。
    """
    canon_target = _canon(target_reg)
    # 要追踪的候选寄存器 (包括32位子寄存器)
    candidates = {canon_target}
    if canon_target.startswith('r'):
        candidates.add('e' + canon_target[1:])  # e.g. rcx → ecx
    elif canon_target.startswith('e'):
        candidates.add('r' + canon_target[1:])  # e.g. ecx → rcx

    for j in range(call_idx - 1, max(call_idx - max_back - 1, -1), -1):
        il = objdump_lines[j].strip().lower()
        if not il:
            continue
        # 函数边界检测: 遇到 <fn_name>: 标签行停止回溯
        if re.match(r'^[0-9a-f]+\s+<.+>:', il):
            break

        # mov dst, [rbp+off] 或 mov dst, [rsp+off] → 来自函数参数
        # -O1+常用 rsp 相对寻址访问参数; mov dst, [rbp-off] → 负偏移局部变量
        stack_load = re.search(
            r'\bmov\s+(\w+),\s*(?:qword\s+ptr\s+)?\[(\w+)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
            il)
        if stack_load and _canon(stack_load.group(1)) in candidates:
            base_reg = stack_load.group(2)
            sign = stack_load.group(3)
            off_str = stack_load.group(4)
            off = int(off_str, 16 if '0x' in off_str else 10)
            if sign == '-':
                off = -off
            # rsp 正偏移或 rbp 正偏移 = 函数参数 (Windows x64: rcx=[rbp+0x10])
            if (base_reg == 'rbp' and off >= 0x10) or \
               (base_reg == 'rsp' and off >= 0x08):
                return f'param:{base_reg}+0x{off:x}'
            # 负偏移 = 局部变量, 继续追踪
            # 找谁写入了这个栈槽: 搜索前一条 mov [rbp-off], src
            for k in range(j - 1, max(j - max_back - 1, -1), -1):
                kl = objdump_lines[k].strip().lower()
                if not kl:
                    continue
                stack_store = re.search(
                    r'\bmov\s+(?:qword\s+ptr\s+)?\[rbp\s*[-]\s*(0x[0-9a-f]+|\d+)\],\s*(\w+)',
                    kl)
                if stack_store:
                    s_off = int(stack_store.group(1), 16 if '0x' in stack_store.group(1) else 10)
                    if s_off == abs(off):
                        src_reg = _canon(stack_store.group(2))
                        # 递归追踪写入源
                        if src_reg in ('rbp', 'rsp', 'rip'):
                            return f'stack:rbp-0x{s_off:x}'
                        # 检查写入源是不是来自函数参数
                        inner = _trace_reg_source(
                            objdump_lines, k, src_reg, max_back=max_back)
                        if inner.startswith('param:'):
                            return inner
                        return f'stack:rbp-0x{s_off:x}<={src_reg}<={inner}'

        # lea reg, [rip+off] → .rdata
        lea_rip = re.search(
            r'\blea\s+(\w+),\s*\[rip\s*([+\-])\s*(0x[0-9a-f]+)\]', il)
        if lea_rip and _canon(lea_rip.group(1)) in candidates:
            sign = -1 if lea_rip.group(2) == '-' else 1
            off = int(lea_rip.group(3), 16) * sign
            addr_m = re.match(r'\s*([0-9a-f]+):', objdump_lines[j])
            if addr_m:
                insn_addr = int(addr_m.group(1), 16)
                target_va = insn_addr + 7 + off
                return f'rdata:0x{target_va:x}'

        # mov reg, reg → 追踪源寄存器
        mov_rr = re.search(r'\bmov\s+(\w+),\s*(\w+)\s*$', il)
        if mov_rr and _canon(mov_rr.group(1)) in candidates:
            src = _canon(mov_rr.group(2))
            if src in ('rbp', 'rsp', 'rip'):
                return f'imm:{src}'
            # 递归追踪
            inner = _trace_reg_source(
                objdump_lines, j, src, max_back=max_back)
            if inner != 'unknown':
                return f'mov:{src}<={inner}'
            return f'mov:{src}'

        # mov reg, imm → 常量, 非用户输入
        mov_imm = re.search(
            r'\bmov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$', il)
        if mov_imm and _canon(mov_imm.group(1)) in candidates:
            return f'imm:{mov_imm.group(2)}'

        # xor reg, reg → 清零, 非用户输入
        xor_m = re.search(r'\bxor\s+(\w+),\s*\1\b', il)
        if xor_m and _canon(xor_m.group(1)) in candidates:
            return 'imm:0(zero)'

        # call → 检查是否是输入源 (argv传递)
        call_m = re.search(
            r'\bcall\s+(?:[0-9a-f]+\s+<)?(\S+?)(?:@plt)?>?\b', il)
        if call_m and candidates:
            callee = call_m.group(1).lower()
            if callee in _INPUT_SOURCES:
                return f'input:{callee}'
            # wrapper 函数检测: 名称含格式/打印关键词则参数视为格式串来源
            _wrapper_kw = ('format', 'print', 'snprintf', 'sprintf',
                           'fprintf', 'log', 'msg', 'debug', 'trace')
            if any(kw in callee for kw in _wrapper_kw):
                # 递归追踪该 call 前一个参数寄存器的来源 (Windows x64: rcx)
                inner = _trace_reg_source(
                    objdump_lines, j, 'rcx', max_back=max_back)
                if inner.startswith('param:') or inner.startswith('input:'):
                    return f'wrapper:{callee}<=rcx<{inner}'

    return 'unknown'


class FmtTaintTracker:
    """二进制格式串污点追踪器 — 检测"格式串=函数形参"模式.

    所有11个CVE FMT样本遵循: wrapper_fn(user_input) → printf(user_input).
    对每个printf, 逆向追踪格式串寄存器到来源指令.
    """

    def _build_fn_summary(self, objdump_lines: List[str]) -> Dict[str, Dict[int, str]]:
        """预处理objdump构建callgraph,为每个函数生成参数来源摘要.

        返回 {fn_name: {param_slot: source_type}}.
        """
        fn_label_re = re.compile(r'^([0-9a-f]+)\s+<(.+)>:')
        summary: Dict[str, Dict[int, str]] = {}
        cur_fn = None
        cur_params: Dict[int, str] = {}
        arg_regs = ['rcx', 'rdx', 'r8', 'r9']  # Windows x64 前四个参数
        for line in objdump_lines:
            ll = line.strip()
            m = fn_label_re.match(ll)
            if m:
                if cur_fn and cur_params:
                    summary[cur_fn] = cur_params
                cur_fn = m.group(2)
                cur_params = {}
                continue
            if cur_fn:
                ll_lower = ll.lower()
                # 检测函数内部是否将参数传入输入源或格式函数
                for slot_idx, reg in enumerate(arg_regs):
                    if f'mov {reg},' in ll_lower or f'lea {reg},' in ll_lower:
                        if any(s in ll_lower for s in _INPUT_SOURCES):
                            cur_params[slot_idx] = 'input'
                        elif any(f'call' in ll_lower and p in ll_lower
                                 for p in _PRINTF_FNS):
                            cur_params[slot_idx] = 'printf_arg'
        if cur_fn and cur_params:
            summary[cur_fn] = cur_params
        return summary

    def analyze(self, objdump_lines: List[str]) -> TaintReport:
        """扫描objdump: 对每个printf调用逆向追踪格式串来源."""
        results: List[TaintResult] = []
        sources: List[str] = []

        addr_pat = re.compile(r'\s*([0-9a-f]+):\s+')
        printf_pat = re.compile(
            r'\bcall\s+(?:[0-9a-f]+\s+<)?('
            + '|'.join(re.escape(f) for f in _PRINTF_FNS)
            + r')(?:@plt)?>?\b', re.I)

        for i, line in enumerate(objdump_lines):
            il = line.strip()
            if not il:
                continue
            il_lower = il.lower()

            # 检测输入源 (用于报告)
            for src in _INPUT_SOURCES:
                if f'call' in il_lower and src.lower() in il_lower:
                    sources.append(src)

            # printf-family call
            printf_m = printf_pat.search(il_lower)
            if not printf_m:
                continue

            func = printf_m.group(1).lower()
            fmt_reg = _FMT_ARG_REG.get(func, 'rcx')
            addr_m = addr_pat.match(il)
            call_addr = int(addr_m.group(1), 16) if addr_m else 0

            # 前向追踪: printf前40条指令找fmt_reg的来源
            fmt_source = _trace_reg_source(
                objdump_lines, i, fmt_reg, max_back=40)

            result = TaintResult(
                call_addr=call_addr, func=func, fmt_reg=fmt_reg)
            result.source = fmt_source

            if 'param:' in fmt_source:
                result.tainted = True
                result.confidence = 0.80
                result.reason = (
                    f'{func}@{call_addr:x}: format arg ({fmt_reg}) '
                    f'traces to function parameter ({fmt_source})')
            elif 'rdata:' in fmt_source:
                result.tainted = False
                result.confidence = 0.0
                result.reason = (
                    f'{func}@{call_addr:x}: format arg from .rdata (safe)')
            else:
                result.tainted = False
                result.confidence = 0.25
                result.source = fmt_source
                result.reason = (
                    f'{func}@{call_addr:x}: format arg source unknown')

            results.append(result)

        return TaintReport(
            total_printf_calls=len(results),
            tainted=[r for r in results if r.tainted],
            safe_rdata=[r for r in results
                       if not r.tainted and 'rdata:' in r.source],
            unknown=[r for r in results
                    if not r.tainted and 'rdata:' not in r.source],
            input_sources_found=list(set(sources)),
        )


# 便捷函数

def analyze_binary_taint(binary_path: str) -> TaintReport:
    """objdump反汇编→污点分析 (一体式)."""
    proc = subprocess.run(
        ['objdump', '-d', '-M', 'intel', binary_path],
        capture_output=True, text=True, timeout=30,
        encoding='utf-8', errors='replace')
    if proc.returncode != 0:
        return TaintReport(0, [], [], [], [])
    tracker = FmtTaintTracker()
    return tracker.analyze(proc.stdout.split('\n'))


# smoke test
def _check():
    import os, glob
    test_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..',
                            'exploit', 'tests', 'regression', 'build', 'gcc', 'O0')
    for s in sorted(glob.glob(os.path.join(test_dir, 'cve_fmt_*.exe')))[:1]:
        r = analyze_binary_taint(s)
        tainted = [t for t in r.tainted]
        print(f"{os.path.basename(s)}: {r.total_printf_calls} calls, "
              f"{len(tainted)} tainted → {'OK' if tainted else 'WARN'}")

if __name__ == "__main__":
    _check()
