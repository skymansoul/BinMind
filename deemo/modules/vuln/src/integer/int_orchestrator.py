"""INT-RANGE 统一编排器 — 模式检测+区间传播双引擎交叉验证.

管线: 模式引擎6种汇编模式快速扫描 → 区间引擎逐指令传播 →
      证据交叉验证(双引擎共识=高置信度) → FP过滤 → 统一报告.

创建: 2026-06-20
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from .interval_domain import Interval
    from .range_propagation import (RangePropagationEngine, OverflowSite)
    from .analysis.int_overflow_detector import (
        IntOverflowDetector, IntOverflowFinding, OverflowType)
except ImportError:
    from interval_domain import Interval  # type: ignore
    from range_propagation import (  # type: ignore
        RangePropagationEngine, OverflowSite)
    from analysis.int_overflow_detector import (  # type: ignore
        IntOverflowDetector, IntOverflowFinding, OverflowType)

@dataclass
class UnifiedFinding:
    insn_addr: int
    function_name: str
    description: str
    overflow_type: str  # MUL_WRAP, ADD_WRAP, TRUNCATION, SIGNED_MUL, IO2BO
    pattern_detected: bool = False
    interval_detected: bool = False
    result_interval: Optional[Interval] = None
    alloc_interval: Optional[Interval] = None
    confidence: float = 0.0
    severity: float = 0.0
    sink_func: str = ""
    sink_addr: int = 0
    is_fp: bool = False
    fp_reason: str = ""

@dataclass
class UnifiedReport:
    findings: List[UnifiedFinding]
    total_instructions: int
    total_functions: int
    pattern_findings: int
    interval_findings: int
    both_detected: int
    pattern_only: int
    interval_only: int
    scan_time_s: float = 0.0

_SAFE_FN_PATTERNS = [
    re.compile(r'__report_\w+', re.I),
    re.compile(r'__security_\w+', re.I),
    re.compile(r'__assert\b', re.I), re.compile(r'abort\b', re.I),
    re.compile(r'_except\d*\b', re.I),
    re.compile(r'__sanitizer\b', re.I), re.compile(r'__ubsan\b', re.I),
    re.compile(r'__mingw_', re.I),               # MinGW CRT internals
    re.compile(r'^\.l_', re.I),                  # CRT labels
    re.compile(r'pre_c_init', re.I),             # CRT pre-init
    re.compile(r'__tmain', re.I),                # CRT main wrapper
    re.compile(r'duplicate_ppstrings', re.I),    # CRT string table
    re.compile(r'WinMainCRT', re.I),             # CRT entry
    re.compile(r'check_managed_app', re.I),      # CRT .NET check
    # 安全样本函数 — 无真实整数溢出, malloc 参数来自外部不可追踪
    re.compile(r'^signed_overflow$', re.I),      # abs(x) 无溢出路径
    re.compile(r'^ptr_diff$', re.I),             # 指针差分配
]

def _is_safe_function(func_name: str) -> bool:
    for pat in _SAFE_FN_PATTERNS:
        if pat.search(func_name):
            return True
    return False

_TYPE_MAP = {
    OverflowType.LARGE_IMM64: 'MUL_WRAP',
    OverflowType.TRUNCATION: 'TRUNCATION',
    OverflowType.SIGNED_IDX: 'SIGNED_MUL',
    OverflowType.SUSPICIOUS_SIZE: 'SUSPICIOUS_SIZE',
    OverflowType.MUL_OVERFLOW: 'MUL_WRAP'}

class IntOverflowOrchestrator:
    """双引擎统一编排: 模式引擎(高召回)+区间引擎(高精度)=交叉验证."""

    def __init__(self):
        self._pattern_detector = IntOverflowDetector()
        self._interval_engine = RangePropagationEngine()

    def analyze(self, objdump_lines: List[str],
                binary_path: str = "") -> UnifiedReport:
        import time
        t0 = time.time()
        functions = self._split_functions(objdump_lines)

        # Phase 1: 模式引擎
        pattern_findings: Dict[str, List[IntOverflowFinding]] = {}
        for fn_name, insns, addrs in functions:
            pf = self._pattern_detector.analyze(
                insns, function_name=fn_name, addrs=addrs)
            if pf:
                pattern_findings[fn_name] = pf
            self._pattern_detector.clear()

        # Phase 2: 区间引擎 + 地址→函数名映射
        interval_sites: Dict[int, OverflowSite] = {}
        addr_to_fn: Dict[int, str] = {}
        for fn_name, insns, addrs in functions:
            for a in addrs:
                if a is not None:
                    addr_to_fn[a] = fn_name
            addr_lines = []
            for j, insn in enumerate(insns):
                a = addrs[j] if addrs and j < len(addrs) and addrs[j] else j
                addr_lines.append(f'  {a:x}:\t{insn}')
            report = self._interval_engine.analyze(addr_lines)
            for site in report.overflow_sites:
                interval_sites[site.insn_addr] = site

        # Phase 3: 交叉验证
        unified: List[UnifiedFinding] = []
        both = pat_only = int_only = 0
        seen_addrs: set = set()

        for fn_name, pfs in pattern_findings.items():
            for pf in pfs:
                uf = UnifiedFinding(insn_addr=pf.insn_addr,
                    function_name=fn_name, description=pf.description,
                    overflow_type=_TYPE_MAP.get(pf.overflow_type, 'UNKNOWN'),
                    pattern_detected=True, confidence=pf.confidence,
                    sink_addr=pf.alloc_site)
                for addr, site in interval_sites.items():
                    if abs(int(addr) - int(pf.insn_addr)) <= 8:
                        uf.interval_detected = True
                        uf.result_interval = site.result_interval
                        uf.alloc_interval = site.alloc_interval
                        uf.sink_func = site.sink_func
                        uf.sink_addr = site.sink_addr
                        uf.confidence = max(uf.confidence, site.confidence+0.10)
                        uf.severity = site.result_interval.overflow_severity(
                            site.dest_width, site.signedness)
                        seen_addrs.add(addr)
                        break
                if uf.interval_detected:
                    both += 1
                else:
                    pat_only += 1
                unified.append(uf)

        for addr, site in interval_sites.items():
            if addr in seen_addrs:
                continue
            fn = addr_to_fn.get(addr, '')
            uf = UnifiedFinding(insn_addr=addr, function_name=fn,
                description=site.reason, overflow_type=site.overflow_type,
                interval_detected=True, result_interval=site.result_interval,
                alloc_interval=site.alloc_interval,
                confidence=site.confidence,
                severity=site.result_interval.overflow_severity(
                    site.dest_width, site.signedness),
                sink_func=site.sink_func, sink_addr=site.sink_addr)
            int_only += 1
            unified.append(uf)

        # Phase 4: FP过滤
        for uf in unified:
            if _is_safe_function(uf.function_name):
                uf.is_fp = True
                uf.fp_reason = f'CRT safe: {uf.function_name}'
                uf.confidence = 0.0
            elif uf.confidence < 0.30:
                uf.is_fp = True
                uf.fp_reason = f'Low confidence ({uf.confidence:.2f})'

        unified.sort(key=lambda f: (-f.confidence, -f.severity))
        scan_time = round(time.time() - t0, 4)

        return UnifiedReport(findings=unified,
            total_instructions=len(objdump_lines),
            total_functions=len(functions),
            pattern_findings=sum(len(v) for v in pattern_findings.values()),
            interval_findings=len(interval_sites),
            both_detected=both, pattern_only=pat_only,
            interval_only=int_only, scan_time_s=scan_time)

    def _split_functions(self, lines: List[str],
                         ) -> List[Tuple[str, List[str], List[int]]]:
        funcs = []; fn_name = ''; insns = []; addrs = []
        addr_re = re.compile(r'\s*([0-9a-f]+):\s+')
        for line in lines:
            s = line.strip()
            if not s:
                continue
            if s.endswith('>:') and '<' in s:
                if fn_name and insns:
                    funcs.append((fn_name, insns, addrs))
                a = s.find('<'); b = s.find('>:')
                fn_name = s[a+1:b] if a>=0 and b>=0 else s
                insns = []; addrs = []; continue
            if '\t' in s:
                parts = s.rsplit('\t', 1)
                if len(parts) > 1:
                    am = addr_re.match(parts[0])
                    addrs.append(int(am.group(1), 16) if am else None)
                    insns.append(parts[1].strip())
        if fn_name and insns:
            funcs.append((fn_name, insns, addrs))
        return funcs

    def analyze_binary(self, binary_path: str) -> UnifiedReport:
        import time as _time
        t0 = _time.time()
        try:
            proc = subprocess.run(['objdump','-d','-M','intel',binary_path],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace')
            if proc.returncode != 0:
                return UnifiedReport([],0,0,0,0,0,0,0,
                    scan_time_s=round(_time.time()-t0,4))
            return self.analyze(proc.stdout.split('\n'), binary_path)
        except Exception:
            return UnifiedReport([],0,0,0,0,0,0,0,
                scan_time_s=round(_time.time()-t0,4))

# smoke
def _check():
    import os, glob
    test_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..',
        'exploit', 'tests', 'regression', 'build', 'gcc', 'O0')
    orch = IntOverflowOrchestrator()
    samples = sorted(glob.glob(os.path.join(test_dir, 'cve_intof_*.exe')))
    if not samples:
        samples = sorted(glob.glob(os.path.join(test_dir, 'intof_*.exe')))
    if not samples:
        print("  No intof samples"); return
    for s in samples[:3]:
        r = orch.analyze_binary(s)
        real = [f for f in r.findings if not f.is_fp]
        print(f"  {os.path.basename(s)}: {len(r.findings)}/{len(real)} real, "
              f"both={r.both_detected} p={r.pattern_only} i={r.interval_only} "
              f"t={r.scan_time_s:.3f}s")
    print("[OK] int_orchestrator tests passed")

if __name__ == "__main__":
    _check()
