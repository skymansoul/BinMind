"""PCFV 完整管线 — 反汇编→函数级提取→判定引擎→结构化报告.

创建: 2023-09-23
设计决策:
  - 对每个用户函数独立运行 AccessExtractor + PCFVEngine,
    跨函数指针传播不做 (v1): 单函数内关联失败即 UNPROVEN, 保证不误杀.
  - 报告输出与基线 HeapAnalysisReport 字段兼容 (confirmed/likely/
    uncertain/filtered_fp/raw_findings), 便于直接对比消融.
"""
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .types import Verdict, FindingVerdict, Evidence
from .access_extractor import AccessExtractor
from .engine import PCFVEngine
from .loop_bound import LoopBoundExtractor


@dataclass
class PCFVReport:
    """一次完整扫描的报告."""
    binary_path: str = ""
    raw_findings: int = 0
    confirmed: int = 0
    likely: int = 0
    uncertain: int = 0
    filtered_fp: int = 0
    fp_reduction_pct: float = 0.0
    elapsed_sec: float = 0.0
    n_functions: int = 0
    verdicts: List[FindingVerdict] = field(default_factory=list)
    error: str = ""


def analyze_heap_pcfv(binary_path: str, timeout_s: int = 60,
                      rule_enabled: dict = None
                      ) -> PCFVReport:
    """PCFV 管线入口: 反汇编 → 逐函数提取 → 判定.

    rule_enabled: 规则开关 (消融实验), None=全开.
    """
    t0 = time.time()
    report = PCFVReport(binary_path=binary_path)
    asm_text = _disassemble(binary_path, timeout_s)
    if not asm_text:
        report.error = 'disasm-empty'
        report.elapsed_sec = round(time.time() - t0, 3)
        return report

    functions = _parse_functions(asm_text)
    report.n_functions = len(functions)
    engine = PCFVEngine(rule_enabled)

    for fn_name, insns in functions:
        if len(insns) < 3:
            continue
        extractor = AccessExtractor(fn_name, insns)
        # 无 malloc 的函数仍可能通过入口参数(交叉函数)访问堆对象,
        # 不能跳过: arg-ptr 访问在引擎中保守保留
        # TODO: 过程间分配大小摘要可将 arg-ptr 判定升级为精确判定
        loop_bx = LoopBoundExtractor(insns, extractor.tracer)
        mallocs = extractor.mallocs
        # 函数级复用对象: 守卫提取器与指令索引 (避免每访问点重建)
        from .guard_dominance import GuardExtractor
        guard_extractor = GuardExtractor(insns)
        insn_index = {i.addr: i for i in insns}

        for acc in extractor.accesses:
            # 循环累积: store 在最内层循环体内时附加迭代信息
            if acc['kind'] == 'store':
                loop = loop_bx.is_in_loop(acc['addr'])
                if loop is not None:
                    acc['kind'] = 'loop_store'
                    acc['loop_iters'] = loop['iters']
                    acc['loop_stride'] = loop['stride']
            fv = engine.evaluate_access(acc, mallocs, insns,
                                        guard_extractor, insn_index)
            fv.sample_id = os.path.basename(binary_path)
            report.verdicts.append(fv)
            if fv.verdict == Verdict.SAFE_FILTERED:
                report.filtered_fp += 1
            elif fv.verdict == Verdict.CONFIRMED:
                report.confirmed += 1
            elif fv.verdict == Verdict.LIKELY:
                report.likely += 1
            else:
                report.uncertain += 1

    report.raw_findings = len(report.verdicts)
    total = max(1, report.raw_findings)
    report.fp_reduction_pct = round(report.filtered_fp / total * 100, 1)
    report.elapsed_sec = round(time.time() - t0, 3)
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
    """解析 objdump 输出为按函数分组的指令列表 (复用 insn_parser 语义)."""
    import re
    import sys
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
