"""FMT-SAC 完整管线 — 反汇编→格式化调用点→来源分类→一致性→判定.

创建: 2023-11-17
设计决策:
  - 格式化函数识别: printf/sprintf/snprintf/fprintf/vprintf 系列,
    含 MinGW 前缀 (__mingw_printf) 与 PLT 变体.
  - 格式串寄存器: printf/__mingw_printf→rcx, sprintf 类→rcx,
    fprintf→rdx, syslog→rdx. 前向数据流取自 PCFV AccessExtractor 的
    call_arg_labels 通道无法覆盖 → 直接扫描 call 指令前对参数寄存器的
    定义指令.
"""
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional

# heap 目录提供 insn_parser / pcfv 基础设施
_HEAP_DIR = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '..', 'heap'))
if _HEAP_DIR not in sys.path:
    sys.path.insert(0, _HEAP_DIR)

from .types import SacVerdict, FmtCall, CallVerdict, FmtSource
from .fmt_parser import parse_specifiers, extract_rdata_strings
from .source_classify import SourceClassifier
from .arg_consistency import ArgConsistency, _norm_name
from .engine import SacEngine

_FMT_FUNCS = ('vsnprintf', 'snprintf', 'vsprintf', 'vfprintf', 'fprintf',
              'vprintf', 'dprintf', 'sprintf', 'printf', 'syslog')

# fmt 参数位置: printf=1(rcx) sprintf=2(rdx) snprintf=3(r8) fprintf=2(rdx)
_FMT_REG = {
    'printf': 'rcx', 'vprintf': 'rcx',
    'sprintf': 'rdx', 'vsprintf': 'rdx',
    'snprintf': 'r8', 'vsnprintf': 'r8',
    'fprintf': 'rdx', 'vfprintf': 'rdx', 'dprintf': 'rdx',
    'syslog': 'rdx',
}


@dataclass
class SacReport:
    """一次完整 FMT-SAC 扫描报告."""
    binary_path: str = ""
    n_functions: int = 0
    n_calls: int = 0
    confirmed: int = 0
    likely: int = 0
    possible: int = 0
    filtered: int = 0
    elapsed_ms: float = 0.0
    verdicts: List[CallVerdict] = field(default_factory=list)
    error: str = ""


def analyze_fmt_sac(binary_path: str, timeout_s: int = 60) -> SacReport:
    """FMT-SAC 管线入口."""
    t0 = time.time()
    report = SacReport(binary_path=binary_path)
    asm = _disassemble(binary_path, timeout_s)
    if not asm:
        report.error = 'disasm-empty'
        report.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return report

    rdata_text = _dump_rdata(binary_path, timeout_s)
    rdata_strings = dict(extract_rdata_strings(rdata_text))
    rdata_addrs = set(rdata_strings.keys())

    functions = _parse_functions(asm)
    report.n_functions = len(functions)
    sample_id = os.path.basename(binary_path)
    const_callers = _build_const_callers(functions, rdata_addrs)

    for fn_name, insns in functions:
        if len(insns) < 3:
            continue
        calls = _extract_fmt_calls(insns, fn_name)
        if not calls:
            continue
        tracer = _make_tracer(insns)
        classifier = SourceClassifier(insns, rdata_addrs,
                                      const_callers, fn_name)
        consistency = ArgConsistency(insns)
        engine = SacEngine(consistency)
        for call in calls:
            src, detail = classifier.classify(
                call.fmt_reg, call.addr, tracer)
            call.source = src
            call.source_detail = detail
            fmt_text = ''
            rdata_tgt = _rdata_target(insns, call)
            if rdata_tgt is not None:
                from .fmt_parser import resolve_rdata_text
                fmt_text = resolve_rdata_text(rdata_strings, rdata_tgt)
            specs, has_n, _ = parse_specifiers(fmt_text)
            call.n_specifiers = specs
            call.has_pct_n = has_n
            call.writable_out = any(
                f in _norm_name(call.function)
                for f in ('sprintf', 'vsprintf', 'snprintf', 'vsnprintf'))
            cv = engine.evaluate(call, sample_id)
            report.verdicts.append(cv)
            report.n_calls += 1
            if cv.verdict == SacVerdict.SAFE_FILTERED:
                report.filtered += 1
            elif cv.verdict == SacVerdict.CONFIRMED:
                report.confirmed += 1
            elif cv.verdict == SacVerdict.LIKELY:
                report.likely += 1
            else:
                report.possible += 1

    report.elapsed_ms = round((time.time() - t0) * 1000, 1)
    return report


def _extract_fmt_calls(insns: list, fn_name: str) -> List[FmtCall]:
    """扫描 call 指令, 识别格式化函数并绑定 fmt 寄存器.
    名字匹配按最长优先, 避免 fprintf 被 printf 子串误配."""
    calls: List[FmtCall] = []
    for insn in insns:
        if insn.mnemonic not in ('call', 'callq'):
            continue
        callee = insn.operands.lower()
        name = None
        for f in _FMT_FUNCS:
            if f in callee:
                name = f
                break
        if name is None:
            continue
        calls.append(FmtCall(
            function=name, addr=insn.addr,
            fmt_reg=_FMT_REG.get(name, 'rcx')))
    return calls


def _rdata_target(insns: list, call: FmtCall) -> Optional[int]:
    """调用点前 fmt 寄存器的 lea-rip 目标 (经 mov 链传播)."""
    idx = next((i for i, insn in enumerate(insns)
                if insn.addr == call.addr), None)
    if idx is None:
        return None
    reg = call.fmt_reg
    for j in range(idx - 1, max(0, idx - 12) - 1, -1):
        insn = insns[j]
        if insn.mnemonic.startswith('call'):
            break
        if ',' not in insn.operands:
            continue
        dst = insn.operands.split(',')[0].strip()
        src = insn.operands.split(',')[-1].strip()
        if insn.mnemonic == 'lea' and 'rip' in src:
            m = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]', src)
            if m:
                disp = int(m.group(2), 16)
                return insn.addr + 7 + (
                    disp if m.group(1) == '+' else -disp)
        if insn.mnemonic.startswith('mov') and '[' not in dst:
            src_m = re.search(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x)\b',
                              dst)
            if src_m and src_m.group(1).lower() == reg:
                reg = src.strip() if re.match(
                    r'^r[0-9a-d]+[bwd]?$|^[er]?[abcd]x$',
                    src.strip().lower()) else reg
    return None


def _probe_fmt(insns: list, call: FmtCall) -> str:
    """非常量格式串: 从栈槽加载处读默认值不可行, 返回空串."""
    return ''


def _disassemble(elf_path: str, timeout_s: int) -> str:
    for tool in ('objdump', 'llvm-objdump'):
        try:
            proc = subprocess.run(
                [tool, '-d', '-M', 'intel', elf_path],
                capture_output=True, text=True, timeout=timeout_s)
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ""


def _dump_rdata(elf_path: str, timeout_s: int) -> str:
    try:
        proc = subprocess.run(
            ['objdump', '-s', '-j', '.rdata', elf_path],
            capture_output=True, text=True, timeout=timeout_s)
        if proc.returncode == 0:
            return proc.stdout
    except Exception:
        pass
    return ""


def _parse_functions(asm_text: str):
    from insn_parser import Instruction, is_user_function

    functions = []
    current_fn = ""
    current_insns = []
    fn_header_re = re.compile(r'^[0-9a-fA-F]+\s+<([^>]+)>:\s*$')
    asm_line_re = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s)+)\s*(.+)$')
    for line in asm_text.split('\n'):
        line = line.rstrip()
        m = fn_header_re.match(line)
        if m:
            if current_insns and is_user_function(current_fn,
                                                  len(current_insns)):
                functions.append((current_fn, current_insns))
            current_fn = m.group(1)
            current_insns = []
            continue
        m = asm_line_re.match(line)
        if m:
            addr = int(m.group(1), 16)
            raw = (m.group(3) or '').strip()
            if ' ' in raw:
                parts = raw.split(None, 1)
                mn = parts[0].lower()
                op = parts[1] if len(parts) > 1 else ''
            else:
                mn = raw.lower()
                op = ''
            current_insns.append(Instruction(
                addr=addr, mnemonic=mn, operands=op, raw=raw))
    if current_insns and is_user_function(current_fn, len(current_insns)):
        functions.append((current_fn, current_insns))
    return functions


def _make_tracer(insns: list):
    from pcfv.value_flow import ValueFlowTracer
    return ValueFlowTracer(insns)


def _build_const_callers(functions, rdata_addrs: set) -> dict:
    """摘要: 被调函数的 fmt 参数寄存器在所有调用点是否均为 lea-rip 常量.
    fmt 位置: 格式化函数按 _FMT_REG, 其余默认 rcx."""
    stats: dict = {}
    for fn_name, insns in functions:
        for insn in insns:
            if insn.mnemonic not in ('call', 'callq'):
                continue
            callee = insn.operands.lower()
            if '<' not in callee:
                continue
            name = callee.split('<')[-1].split('>')[0].split('@')[0]
            fmt_reg = 'rcx'
            for f in _FMT_FUNCS:
                if f in name:
                    fmt_reg = _FMT_REG.get(f, 'rcx')
                    break
            stats.setdefault(name, {'total': 0, 'const': 0})
            stats[name]['total'] += 1
            idx = next((i for i, x in enumerate(insns)
                        if x.addr == insn.addr), None)
            if idx is None:
                continue
            if _is_const_fmt_arg(insns, idx, fmt_reg, rdata_addrs):
                stats[name]['const'] += 1
    return {n: s['const'] == s['total'] and s['total'] > 0
            for n, s in stats.items()}


def _is_const_fmt_arg(insns: list, call_idx: int, reg: str,
                      rdata_addrs: set) -> bool:
    """调用点前 reg 的定义链是否最终为 lea-rip 指向 rdata."""
    seen = 0
    cur = reg
    for _depth in range(3):
        found = False
        for j in range(call_idx - 1, max(0, call_idx - 10) - 1, -1):
            x = insns[j]
            if x.mnemonic.startswith('call'):
                break
            if ',' not in x.operands:
                continue
            dst = x.operands.split(',')[0].strip()
            if not re.match(r'^r[0-9a-d]+[bwd]?$|^[er]?[abcd]x$',
                            dst.lower()):
                continue
            if dst.lower() != cur:
                continue
            found = True
            src = x.operands.split(',')[-1].strip()
            if x.mnemonic == 'lea' and 'rip' in src:
                m = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]',
                              src)
                if m:
                    disp = int(m.group(2), 16)
                    tgt = x.addr + 7 + (
                        disp if m.group(1) == '+' else -disp)
                    return any(a <= tgt < a + 40 for a in rdata_addrs)
                return False
            if '[' in src:
                return False  # 栈/堆加载 → 非常量
            src_m = re.match(r'^(r[0-9a-d]+[bwd]?|[er]?[abcd]x)$',
                             src.lower())
            if src_m:
                cur = src_m.group(1)
                call_idx = j
                break
            return False
        if not found:
            return False
        seen += 1
        if seen >= 3:
            break
    return False
