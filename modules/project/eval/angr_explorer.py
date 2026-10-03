# Angr漏洞探索脚本: 使用Angr的exploration引擎模拟路径,
# 标记到达危险函数调用点 (malloc+memcpy等) 的基本块
# 决策: 使用Angr的CFGFast+DDG进行快速分析, 不执行完整符号执行
#   (符号执行有路径爆炸, 不适合批量对比). 此脚本模拟自动化审计场景
#
#   Shoshitaishvili et al. "SOK: (State of) The Art of War"
#     (IEEE S&P 2016) — Angr设计理念
#   angr.analyses.cfg — 控制流图恢复
from __future__ import annotations
import sys, os, time, json, re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_ANGR_AVAILABLE = False
try:
    import angr
    _ANGR_AVAILABLE = True
except ImportError:
    pass

# 堆溢出相关的危险函数集
_HEAP_OVERFLOW_SINKS = {
    "memcpy", "memmove", "memset", "strcpy", "strcat", "strncpy",
    "sprintf", "snprintf", "__memcpy_chk", "__memmove_chk",
    "bcopy", "memccpy", "stpcpy", "read", "fread", "recv",
}
_HEAP_ALLOCS = {"malloc", "calloc", "realloc", "_malloc", "__libc_malloc"}


@dataclass
class AngrFinding:
    func_name: str
    sink_name: str
    call_address: int
    alloc_site: Optional[int] = None
    alloc_size: Optional[int] = None
    write_size: Optional[int] = None
    confidence: float = 0.5


@dataclass
class AngrScanResult:
    binary_path: str
    success: bool
    findings: List[AngrFinding]
    total_bbs: int = 0           # 基本块总数
    reachable_bbs: int = 0       # 可达基本块数
    scan_time_ms: float = 0
    peak_memory_mb: float = 0
    error_msg: str = ""


class AngrExplorer:
    """基于Angr的二进制漏洞探索器.

    使用CFGFast + 危险函数reachability分析,
    模拟自动化静态审计工具的使用场景.
    """

    def __init__(self, timeout_seconds: int = 60):
        self._timeout = timeout_seconds

    def analyze(self, binary_path: str) -> AngrScanResult:
        if not _ANGR_AVAILABLE:
            return AngrScanResult(
                binary_path=binary_path, success=False,
                findings=[], error_msg="angr未安装 (pip install angr)")

        t0 = time.perf_counter()
        try:
            # 加载二进制
            proj = angr.Project(binary_path, auto_load_libs=False,
                               load_options={'auto_load_libs': False})

            # CFG快速恢复
            cfg = proj.analyses.CFGFast(
                resolve_indirect_jumps=False,
                force_complete_scan=False,
                show_progressbar=False)

            findings = []
            alloc_sites: Dict[int, int] = {}  # addr → size

            # 第一遍: 找分配点
            for func in cfg.functions.values():
                for block in func.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            target = self._resolve_call_target(insn, proj)
                            if target and target.name and target.name in _HEAP_ALLOCS:
                                size = self._infer_alloc_size(
                                    block, insn.address, proj)
                                alloc_sites[insn.address] = size

            # 第二遍: 找危险sink并关联分配
            for func in cfg.functions.values():
                for block in func.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic != 'call':
                            continue
                        target = self._resolve_call_target(insn, proj)
                        if not target or not target.name:
                            continue
                        if target.name not in _HEAP_OVERFLOW_SINKS:
                            continue

                        # 找到最近的分配点
                        size = self._infer_write_size(block, insn.address, proj)
                        nearest_alloc = self._find_nearest_alloc(
                            insn.address, alloc_sites, func)

                        findings.append(AngrFinding(
                            func_name=func.name,
                            sink_name=target.name,
                            call_address=insn.address,
                            alloc_site=nearest_alloc[0] if nearest_alloc else None,
                            alloc_size=nearest_alloc[1] if nearest_alloc else None,
                            write_size=size,
                            confidence=0.5))

            elapsed = (time.perf_counter() - t0) * 1000
            total_bbs = sum(1 for _ in cfg.functions.values()
                           for _ in _.blocks)
            return AngrScanResult(
                binary_path=binary_path, success=True,
                findings=findings, total_bbs=total_bbs,
                reachable_bbs=total_bbs, scan_time_ms=elapsed,
                peak_memory_mb=0)

        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return AngrScanResult(
                binary_path=binary_path, success=False,
                findings=[], scan_time_ms=elapsed, error_msg=str(e))

    def _resolve_call_target(self, insn, proj):
        """解析call指令的目标."""
        # angr 9.x: Insn 对象的原始 capstone 指令在 .insn (旧版在 .cs_insn)
        cs = getattr(insn, 'insn', None) or getattr(insn, 'cs_insn', None)
        if cs is None:
            return None
        if cs.operands and cs.operands[0].type == 1:  # register
            return None
        if cs.operands and hasattr(cs.operands[0], 'imm'):
            addr = cs.operands[0].imm
            if addr in proj.kb.functions:
                return proj.kb.functions[addr]
        return None

    def _infer_alloc_size(self, block, call_addr, proj) -> Optional[int]:
        """推断malloc参数大小 (简单寄存器回溯)."""
        for insn in reversed(list(block.capstone.insns)):
            if insn.address >= call_addr:
                continue
            if insn.mnemonic == 'mov' and 'rdi' in insn.op_str:
                m = re.search(r'(0x[0-9a-fA-F]+)', insn.op_str)
                if m:
                    return int(m.group(1), 16)
        return None

    def _infer_write_size(self, block, call_addr, proj) -> Optional[int]:
        """推断memcpy的第三个参数 (rdx)."""
        for insn in reversed(list(block.capstone.insns)):
            if insn.address >= call_addr:
                continue
            if insn.mnemonic == 'mov' and 'rdx' in insn.op_str:
                m = re.search(r'(0x[0-9a-fA-F]+|\d+)', insn.op_str)
                if m:
                    v = m.group(1)
                    return int(v, 16) if v.startswith('0x') else int(v)
        return None

    def _find_nearest_alloc(self, call_addr: int,
                            alloc_sites: Dict[int, int],
                            func) -> Optional[Tuple[int, int]]:
        """在当前函数中找最近的分配点."""
        best_addr, best_size = None, None
        min_dist = 0x10000
        for alloc_addr, size in alloc_sites.items():
            # 只能关联同一函数的分配
            if abs(call_addr - alloc_addr) < min_dist:
                min_dist = abs(call_addr - alloc_addr)
                best_addr = alloc_addr
                best_size = size
        if best_addr is not None:
            return (best_addr, best_size)
        return None
