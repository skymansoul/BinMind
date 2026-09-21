"""分配契约流保持 集成管线 — 反汇编 → 检测 → 误报压缩 → 报告.

  - 复用 orchestrator.analyze_heap 得到原始 findings, 再以 分配契约流保持
    压缩器压制可证明安全的写点. 压缩前后指标对比即误报率降幅.
  - 指令文本与地址表从 parse_instructions 获取, 与检测器共用同一
    解析结果, 保证地址对齐.
  - 无 objdump 时返回空报告, 不抛异常.
"""

import os
import sys
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_cur = os.path.dirname(os.path.abspath(__file__))
_parent = os.path.dirname(_cur)
for _p in (_cur, _parent):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from alloc_contract.fp_compressor import FpCompressor, CompressResult
from alloc_contract.allocator_geometry import usable_size

DEFAULT_ABI = 'win64'


@dataclass
class AcfpcReport:
    binary_path: str = ""
    abi: str = DEFAULT_ABI
    base_findings: int = 0
    kept_findings: int = 0
    suppressed: int = 0
    confirmed: int = 0
    n_contracts: int = 0
    n_writes: int = 0
    suppress_rate: float = 0.0
    elapsed_sec: float = 0.0
    findings: List[dict] = field(default_factory=list)
    suppressed_sites: List[dict] = field(default_factory=list)


# TODO: 与 tests/_common/disasm 收敛, 消除反汇编解析的双份实现

def _disassemble(elf_path: str) -> str:
    for tool in ('objdump', 'llvm-objdump'):
        try:
            proc = subprocess.run(
                [tool, '-d', '-M', 'intel', elf_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ""


def _collect_instructions(asm_text: str):
    """从 objdump 文本提取 (指令行, 地址) 列表.

    objdump 输出格式不固定: MinGW PE 用 tab 分隔 地址/字节/指令,
    Linux ELF 可能用空格. 按段容错解析."""
    lines, addrs = [], []
    import re
    for raw in asm_text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.strip().startswith('.'):
            continue
        m = re.match(r'^\s*([0-9a-f]+):', line)
        addr = int(m.group(1), 16) if m else 0
        body = line[m.end():] if m else line
        if 'file format' in body or 'Disassembly' in body:
            continue
        if '\t' in body:
            segs = [s for s in body.split('\t') if s.strip()]
            if not segs:
                continue
            insn = segs[-1].strip()
        else:
            toks = body.split()
            if not toks:
                continue
            i = 0
            while i < len(toks) and re.fullmatch(r'[0-9a-f]{2}', toks[i]):
                i += 1
            if i >= len(toks):
                continue
            insn = ' '.join(toks[i:])
        if not insn or insn.startswith(';') or insn.startswith('.'):
            continue
        if not re.match(r'^[a-z][a-z0-9]*', insn, re.I):
            continue
        lines.append(insn)
        addrs.append(addr)
    return lines, addrs


def run_acfpc_pipeline(binary_path: str, findings: Optional[List] = None,
                       abi: str = DEFAULT_ABI,
                       mode: str = 'strict',
                       timeout_s: int = 60) -> AcfpcReport:
    """完整 分配契约流保持 管线: 反汇编 → 检测 → 压缩."""
    t0 = time.time()
    report = AcfpcReport(binary_path=binary_path, abi=abi)
    asm_text = _disassemble(binary_path)
    if not asm_text:
        report.elapsed_sec = round(time.time() - t0, 3)
        return report
    instructions, addrs = _collect_instructions(asm_text)
    if not instructions:
        report.elapsed_sec = round(time.time() - t0, 3)
        return report

    import_map = {}
    try:
        from .pe_imports import build_import_map
        import_map = build_import_map(binary_path, asm_text)
    except Exception:
        import_map = {}

    base = findings
    if base is None:
        try:
            from orchestrator import analyze_heap
            rep = analyze_heap(binary_path, timeout_s=timeout_s)
            base = rep.findings
        except Exception:
            base = []

    report.base_findings = len(base)
    compressor = FpCompressor(abi=abi, mode=mode)
    result: CompressResult = compressor.compress(
        instructions, list(base), addrs, import_map)
    report.kept_findings = len(result.kept)
    report.suppressed = result.stats.suppressed
    report.confirmed = result.stats.confirmed
    report.n_contracts = result.stats.n_contracts
    report.n_writes = result.stats.total_writes
    total = max(1, report.base_findings)
    report.suppress_rate = round(report.suppressed / total * 100, 1)
    report.findings = [dict(f) if not isinstance(f, dict) else f
                       for f in result.kept]
    report.suppressed_sites = [
        {'idx': s.insn_idx, 'addr': s.addr, 'reason': s.reason,
         'evidence': s.evidence, 'contract_idx': s.contract_idx}
        for s in result.suppressed_sites]
    report.elapsed_sec = round(time.time() - t0, 3)
    return report
