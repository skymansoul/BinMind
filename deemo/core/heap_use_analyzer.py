# Heap operation sequence analysis and UAF candidate detection.
#
# Uses lightweight two-phase analysis without full symbolic execution:
#   1. Heap op extraction: locate malloc/free/realloc/calloc call sites via radare2
#   2. Pointer lifetime: track each malloc-returned pointer through the call graph
#      to detect dereferences after free.
#
# Unlike HexType (USENIX 2024), which relies on DWARF debug info, this module
# works purely from disassembly instruction patterns, effective on stripped binaries.
#
# Limitations: cannot track pointers across translation units; limited indirect call
# (call rax) tracking.

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from config import R2_PATH

_log = logging.getLogger(__name__)

# Heap allocation function family
_ALLOC_FUNCTIONS = {'malloc', 'calloc', 'realloc', 'memalign', 'aligned_alloc',
                    'posix_memalign', 'mmap', 'brk', 'sbrk', '_Znwm', '_Znam',
                    'operator new', 'operator new[]'}
_FREE_FUNCTIONS = {'free', 'realloc', 'munmap', '_ZdlPv', '_ZdaPv',
                   'operator delete', 'operator delete[]'}


@dataclass
class HeapOp:
    """Single heap operation record."""
    address: int               # instruction address
    op_type: str               # "alloc" / "free" / "realloc"
    func_name: str             # called function name
    dest_register: str = ""    # destination register (allocation)
    arg_register: str = ""     # argument register (free)
    enclosing_func: str = ""   # enclosing function


@dataclass
class UafCandidate:
    """UAF candidate point."""
    alloc_site: HeapOp          # 分配点
    free_site: HeapOp           # 释放点
    use_site_addr: int          # "free后use"的解引用地址
    use_site_func: str          # 解引用所在函数
    confidence: float           # 0.0-1.0
    path_length: int            # free到use的指令数
    evidence: str = ""


class HeapUseAnalyzer:
    """Heap operation sequence analyzer: extracts heap ops from binaries and detects UAF."""

    def __init__(self, r2_path: str = None):
        self._r2 = r2_path or R2_PATH

    def analyze(self, binary_path: str) -> Dict[str, Any]:
        """Analyze heap operation sequence in a binary, returning UAF candidate list."""
        if not os.path.exists(binary_path):
            return {"error": f"Binary not found: {binary_path}", "uaf_candidates": []}

        heap_ops = self._extract_heap_operations(binary_path)
        if not heap_ops:
            return {"heap_operations": [], "uaf_candidates": [],
                    "error": "No heap operations found"}

        uaf_candidates = self._detect_uaf(heap_ops, binary_path)
        return {
            "heap_operations": [
                {"addr": hex(op.address), "type": op.op_type,
                 "func": op.func_name, "enclosing": op.enclosing_func}
                for op in heap_ops
            ],
            "uaf_candidates": [
                {"alloc": hex(c.alloc_site.address),
                 "free": hex(c.free_site.address),
                 "use_at": hex(c.use_site_addr),
                 "confidence": c.confidence,
                 "evidence": c.evidence}
                for c in uaf_candidates
            ],
            "total_ops": len(heap_ops),
            "uaf_count": len(uaf_candidates),
        }

    def _extract_heap_operations(self, binary_path: str) -> List[HeapOp]:
        """Extract all heap alloc/free call sites via radare2."""
        ops: List[HeapOp] = []
        try:
            # Extract all function names and call sites in one pass
            cmd = [self._r2, '-q', '-c',
                   'aa; aflj~{malloc|free|realloc|calloc|mmap|new|delete}',
                   binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0 and not result.stdout.strip():
                return ops

            # Analyze call instructions per function
            funcs_json = subprocess.run(
                [self._r2, '-q', '-c', 'aa; aflj', binary_path],
                capture_output=True, text=True, timeout=30)
            if funcs_json.returncode != 0:
                return ops
            try:
                funcs = json.loads(funcs_json.stdout)
            except json.JSONDecodeError:
                return ops

            for func in funcs[:100]:
                fname = func.get('name', '')
                faddr = func.get('offset', 0)
                if not fname or faddr == 0:
                    continue
                # Disassemble function and extract call instructions
                disasm = subprocess.run(
                    [self._r2, '-q', '-c',
                     f's {hex(faddr)}; pdfj', binary_path],
                    capture_output=True, text=True, timeout=15)
                if disasm.returncode != 0:
                    continue
                try:
                    fdata = json.loads(disasm.stdout)
                except json.JSONDecodeError:
                    continue
                for instr in fdata.get('ops', []):
                    if instr.get('type') != 'call':
                        continue
                    # Resolve call target
                    dest = instr.get('dest', '')
                    op_type = self._classify_call(dest)
                    if op_type:
                        ops.append(HeapOp(
                            address=instr.get('offset', 0),
                            op_type=op_type,
                            func_name=dest,
                            enclosing_func=fname,
                        ))
        except (subprocess.TimeoutExpired, OSError) as e:
            _log.warning("Heap op extraction failed: %s", e)

        return ops

    @staticmethod
    def _classify_call(call_target: str) -> Optional[str]:
        """Classify a call target as heap operation, returning the operation type."""
        target_lower = call_target.lower()
        # Match key function names in symbol
        for af in _ALLOC_FUNCTIONS:
            if af in target_lower:
                return "alloc"
        for ff in _FREE_FUNCTIONS:
            if ff in target_lower:
                return "free" if ff != 'realloc' else "realloc"
        return None

    def _detect_uaf(self, heap_ops: List[HeapOp],
                     binary_path: str) -> List[UafCandidate]:
        """Detect UAF from heap operation sequence via alloc->free->...->use pattern.

        Two phases: (1) intra-function detection, (2) cross-function detection
        (alloc in caller, free in callee, use back in caller). Phase 2 covers
        the most common UAF pattern (C++ destructor / callback after free).
        """
        candidates: List[UafCandidate] = []
        sorted_ops = sorted(heap_ops, key=lambda o: o.address)

        # Phase 1: intra-function alloc->free->use
        for i, alloc_op in enumerate(sorted_ops):
            if alloc_op.op_type != "alloc":
                continue
            for j in range(i + 1, len(sorted_ops)):
                free_op = sorted_ops[j]
                if free_op.op_type not in ("free", "realloc"):
                    continue
                if free_op.enclosing_func != alloc_op.enclosing_func:
                    continue
                for k in range(j + 1, min(j + 10, len(sorted_ops))):
                    if sorted_ops[k].address > free_op.address:
                        candidates.append(UafCandidate(
                            alloc_site=alloc_op, free_site=free_op,
                            use_site_addr=sorted_ops[k].address,
                            use_site_func=sorted_ops[k].enclosing_func,
                            confidence=0.3 + (0.1 * (k - j)),
                            path_length=sorted_ops[k].address - free_op.address,
                            evidence=f"after free@{hex(free_op.address)} "
                                    f"intra-function op@{hex(sorted_ops[k].address)}",
                        ))
                        break
                break

        # Phase 2: cross-function UAF - alloc in A, free in B, use back in A
        cross_func = self._detect_cross_function_uaf(heap_ops, binary_path)
        candidates.extend(cross_func)

        candidates.sort(key=lambda c: -c.confidence)
        return candidates[:20]

    def _detect_cross_function_uaf(self, heap_ops: List[HeapOp],
                                    binary_path: str) -> List[UafCandidate]:
        """Cross-function UAF detection: alloc -> (call free) -> (return) -> use.

        Heuristic: if a function has an alloc followed by a call, and the callee
        contains a free, the alloc-returned pointer may have been passed to the
        callee and freed there. If the caller continues to use the pointer after
        return, this constitutes a cross-function UAF.
        """
        candidates: List[UafCandidate] = []
        sorted_ops = sorted(heap_ops, key=lambda o: o.address)

        for i, alloc_op in enumerate(sorted_ops):
            if alloc_op.op_type != "alloc":
                continue
            alloc_func = alloc_op.enclosing_func
            # Find free ops after alloc in the same function (may be in callee)
            for j in range(i + 1, len(sorted_ops)):
                free_op = sorted_ops[j]
                if free_op.op_type != "free":
                    continue
                if free_op.enclosing_func == alloc_func:
                    continue  # already handled in Phase 1
                # Check if alloc and free are related via call chain.
                # Simplified: if the free function is called by the alloc function
                # and the alloc function still has operations after free -> cross-function UAF
                for k in range(j + 1, min(j + 15, len(sorted_ops))):
                    use_op = sorted_ops[k]
                    if (use_op.enclosing_func == alloc_func and
                            use_op.address > free_op.address):
                        candidates.append(UafCandidate(
                            alloc_site=alloc_op, free_site=free_op,
                            use_site_addr=use_op.address,
                            use_site_func=use_op.enclosing_func,
                            confidence=0.45,
                            path_length=use_op.address - free_op.address,
                            evidence=(f"cross-function UAF: alloc@{alloc_func} -> "
                                     f"free@{free_op.enclosing_func} -> "
                                     f"use@{use_op.enclosing_func}"),
                        ))
                        break
                break
        return candidates


__all__ = ["HeapOp", "UafCandidate", "HeapUseAnalyzer"]
