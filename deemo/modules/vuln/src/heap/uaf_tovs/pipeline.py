"""TOVS 完整管线 — 反汇编→free/use候选→时序与身份验证→报告.

创建: 2026-06-10
设计决策:
  - 逐用户函数独立执行, 候选对提取与 PCFV 共享 func_analyzer 产物,
    验证器复用 pcfv.cfg/pcfv.value_flow 基础设施.
  - 报告字段与既有 UAFReport 对齐 (confirmed/possible/filtered),
    便于与 uaf_orchestrator 直接对比.
"""
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import List

from .types import TovsVerdict, PairVerdict
from .free_use_pairs import extract_pairs
from .cross_fn_events import extract_cross_fn_pairs
from .engine import TovsEngine


@dataclass
class TovsReport:
    """一次完整 TOVS 扫描报告."""
    binary_path: str = ""
    n_functions: int = 0
    n_pairs: int = 0
    confirmed: int = 0
    possible: int = 0
    filtered: int = 0
    elapsed_ms: float = 0.0
    verdicts: List[PairVerdict] = field(default_factory=list)
    error: str = ""


def analyze_uaf_tovs(binary_path: str, timeout_s: int = 60) -> TovsReport:
    """TOVS 管线入口."""
    t0 = time.time()
    report = TovsReport(binary_path=binary_path)
    asm = _disassemble(binary_path, timeout_s)
    if not asm:
        report.error = 'disasm-empty'
        report.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return report

    functions = _parse_functions(asm)
    report.n_functions = len(functions)
    sample_id = os.path.basename(binary_path)
    malloc_summary = _build_malloc_summary(functions)

    for fn_name, insns in functions:
        if len(insns) < 3:
            continue
        fa = _analyze_function(fn_name, insns)
        pairs = extract_pairs(fa, fn_name)
        pairs.extend(extract_cross_fn_pairs(insns, fn_name,
                                            malloc_summary))
        if not pairs:
            continue
        tracer = _make_tracer(insns)
        engine = TovsEngine(insns, tracer)
        for pair in pairs:
            pv = engine.evaluate(pair, sample_id)
            report.verdicts.append(pv)
            report.n_pairs += 1
            if pv.verdict == TovsVerdict.CONFIRMED:
                report.confirmed += 1
            elif pv.verdict == TovsVerdict.POSSIBLE:
                report.possible += 1
            else:
                report.filtered += 1

    report.elapsed_ms = round((time.time() - t0) * 1000, 1)
    return report


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


def _parse_functions(asm_text: str):
    import re
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


def _analyze_function(fn_name: str, insns: list):
    from func_analyzer import analyze_function
    return analyze_function(fn_name, insns)


def _make_tracer(insns: list):
    from pcfv.value_flow import ValueFlowTracer
    return ValueFlowTracer(insns)


def _build_malloc_summary(functions) -> dict:
    """函数是否内含 malloc 调用 → 调用点返回标签摘要."""
    summary = {}
    for fn_name, insns in functions:
        has = any(i.mnemonic in ('call', 'callq')
                  and any(a in i.operands.lower()
                          for a in ('malloc', 'calloc', 'realloc'))
                  for i in insns)
        if has:
            summary[fn_name] = True
    return summary
