"""FMT-SPEC 编排器 — 统一管线: rdata提取 + 污点追踪 + FP过滤 + 风险评分.

管线:
  1. objdump反汇编
  2. rdata_extractor: LEA→.rdata格式串提取 + 说明符解析
  3. fmt_taint_tracker: 寄存器逆向追踪 → 格式串来源分类
  4. 交叉验证: .rdata证据 vs 污点证据
  5. FP过滤器: CRT错误处理器模式
  6. 置信度评分 + 最终裁决

创建: 2025-04-17
"""
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .rdata_extractor import extract_fmt_calls, FmtCallSite
from .fmt_taint_tracker import FmtTaintTracker, TaintResult, TaintReport
from .fmt_spec_parser import FmtSpecifier, parse_format_specs, detect_format_danger

# FP过滤器

# CRT错误处理器: vfprintf在地址 0x140001b3a-0x140001baa 区间
# 这些是GCC/MinGW运行时错误报告, 格式串来自系统代码而非用户输入
_CRT_VFPRINTF_RANGE = (0x140001b00, 0x140001c00)
_CRT_VFPRINTF_PATTERN = re.compile(
    r'__report_error|__raise_security|__security_error|'
    r'invalid_parameter|abort_handler|_invalid_parameter', re.I)

def _is_crt_error_handler(call_addr: int, func: str,
                          containing_func: str = "") -> bool:
    """判断printf调用是否在CRT错误处理器中."""
    if func == 'vfprintf':
        lo, hi = _CRT_VFPRINTF_RANGE
        if lo <= call_addr <= hi:
            return True
    if containing_func and _CRT_VFPRINTF_PATTERN.search(containing_func):
        return True
    return False

# 数据类

@dataclass
class FmtCallVerdict:
    """单个printf调用点的综合裁决."""
    call_addr: int
    func: str
    fmt_reg: str = ""
    fmt_string: str = ""          # .rdata提取的格式串 (可能为空)
    specs: List[FmtSpecifier] = field(default_factory=list)
    args_expected: int = 0
    risk: str = "SAFE"
    confidence: float = 0.0
    reason: str = ""
    # 证据来源
    from_rdata: bool = False       # 格式串来自.rdata
    from_param: bool = False       # 格式串来自函数参数 (可能用户可控)
    is_fp_filtered: bool = False   # 被FP过滤器移除
    taint_chain: str = ""

@dataclass
class FmtReport:
    """完整FMT-SPEC分析报告."""
    binary_path: str
    total_printf_calls: int
    verdicts: List[FmtCallVerdict]
    vulnerable: List[FmtCallVerdict]
    safe: List[FmtCallVerdict]
    filtered_fps: List[FmtCallVerdict]
    has_vulnerability: bool = False
    max_confidence: float = 0.0
    analysis_time_ms: float = 0.0

# 编排器

class FmtOrchestrator:
    """FMT-SPEC统一编排器.

    三步管线:
      Step A: rdata提取 → 格式串内容 + 说明符解析
      Step B: 污点追踪 → 格式串来源分类 (参数 vs .rdata vs 未知)
      Step C: 交叉验证 + FP过滤 + 置信度评分

    置信度模型:
      0.90 — 格式串来自函数参数, 且二进制包含已知输入源 (argv/recv/...)
      0.75 — 格式串来自函数参数, 但未检测到输入源 (可能间接传递)
      0.50 — 格式串来自.rdata但含危险说明符 (%n/%s)
      0.00 — 格式串来自.rdata且无非平凡说明符
    """

    def analyze(self, binary_path: str,
                objdump_lines: Optional[List[str]] = None) -> FmtReport:
        """完整分析单个二进制文件."""
        import time
        t0 = time.time()

        # objdump
        if objdump_lines is None:
            proc = subprocess.run(
                ['objdump', '-d', '-M', 'intel', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace')
            if proc.returncode != 0:
                return FmtReport(
                    binary_path=binary_path, total_printf_calls=0,
                    verdicts=[], vulnerable=[], safe=[], filtered_fps=[])
            objdump_lines = proc.stdout.split('\n')

# rdata提取 (格式串内容)
        rdata_calls = extract_fmt_calls(objdump_lines, binary_path)
        rdata_map: Dict[int, FmtCallSite] = {
            c.call_addr: c for c in rdata_calls}

# 污点追踪 (格式串来源)
        tracker = FmtTaintTracker()
        taint_report = tracker.analyze(objdump_lines)
        taint_map: Dict[int, TaintResult] = {
            t.call_addr: t for t in (
                taint_report.tainted +
                taint_report.safe_rdata +
                taint_report.unknown)}

# 交叉验证
        all_addrs = sorted(set(list(rdata_map.keys()) +
                               list(taint_map.keys())))
        verdicts: List[FmtCallVerdict] = []

        for addr in all_addrs:
            rdata = rdata_map.get(addr)
            taint = taint_map.get(addr)
            func = (rdata.func if rdata else
                    taint.func if taint else 'unknown')

# CRT FP过滤器
            if _is_crt_error_handler(addr, func):
                v = FmtCallVerdict(
                    call_addr=addr, func=func,
                    fmt_reg=rdata.fmt_reg if rdata else '',
                    fmt_string=rdata.fmt_string if rdata else '',
                    specs=rdata.specs if rdata else [],
                    args_expected=rdata.args_expected if rdata else 0,
                    risk='SAFE', confidence=0.0,
                    reason='CRT error handler (FP filtered)',
                    from_rdata=bool(rdata and rdata.fmt_from_rdata),
                    from_param=bool(taint and taint.tainted),
                    is_fp_filtered=True,
                    taint_chain=(taint.source if taint and taint.tainted
                                else ''))
                verdicts.append(v)
                continue

# 证据合并
            fmt_str = rdata.fmt_string if rdata else ""
            # 若rdata声称有映射但实际提取为空 → 可能是stale reg_to_rdata误判
            fmt_from_rdata = bool(
                rdata and rdata.fmt_from_rdata and fmt_str)
            fmt_from_param = bool(taint and taint.tainted)
            # 跨函数冲突仲裁: 参数来源比 .rdata 更危险,优先采信 taint 证据
            if fmt_from_rdata and fmt_from_param:
                fmt_from_rdata = False
            specs = rdata.specs if rdata else []
            args_expected = rdata.args_expected if rdata else 0
            fmt_reg = (rdata.fmt_reg if rdata else
                       taint.fmt_reg if taint else 'rcx')
            taint_chain = taint.source if taint else ""

            # 置信度评分
            conf = _compute_confidence(
                fmt_from_rdata, fmt_from_param, specs,
                taint_report.input_sources_found, taint_chain)

            # 风险等级
            if conf >= 0.70:
                risk = 'HIGH'
            elif conf >= 0.50:
                risk = 'MEDIUM'
            elif conf >= 0.25:
                risk = 'LOW'
            else:
                risk = 'SAFE'

            reason = _build_reason(
                func, addr, fmt_from_rdata, fmt_from_param,
                fmt_str, taint_chain, taint_report.input_sources_found)

            verdicts.append(FmtCallVerdict(
                call_addr=addr, func=func, fmt_reg=fmt_reg,
                fmt_string=fmt_str, specs=specs,
                args_expected=args_expected,
                risk=risk, confidence=conf, reason=reason,
                from_rdata=fmt_from_rdata, from_param=fmt_from_param,
                is_fp_filtered=False, taint_chain=taint_chain))

        # 分类
        vulnerable = [v for v in verdicts if v.risk in ('HIGH', 'MEDIUM')]
        safe = [v for v in verdicts
                if v.risk in ('LOW', 'SAFE') and not v.is_fp_filtered]
        filtered = [v for v in verdicts if v.is_fp_filtered]
        has_vuln = len(vulnerable) > 0
        max_conf = max((v.confidence for v in verdicts), default=0.0)

        return FmtReport(
            binary_path=binary_path,
            total_printf_calls=len(verdicts),
            verdicts=verdicts,
            vulnerable=vulnerable,
            safe=safe,
            filtered_fps=filtered,
            has_vulnerability=has_vuln,
            max_confidence=max_conf,
            analysis_time_ms=(time.time() - t0) * 1000,
        )

def _compute_confidence(from_rdata: bool, from_param: bool,
                        specs: List[FmtSpecifier],
                        input_sources: List[str],
                        taint_chain: str) -> float:
    """置信度评分: .rdata→0.0, param+input→0.85, param-only→0.70."""
    # .rdata是客观证据 (我们从二进制中读取了实际字符串)
    if from_rdata:
        has_danger = any(s.is_dangerous() for s in specs)
        has_leak = any(s.is_leak() for s in specs)
        # %n 是写原语,.rdata 中的 %n 格式串本身仍是危险模式
        has_write = any(
            hasattr(s, 'spec_char') and 'n' in getattr(s, 'spec_char', '')
            for s in specs)
        if has_danger:
            return 0.65 if has_write else 0.45  # 格式串自身危险, 但来源安全
        if has_leak and len(specs) > 3:
            return 0.35  # 多个信息泄露spec
        return 0.0  # 安全常量

    # 参数来源: 可能用户可控
    if from_param:
        base = 0.70
        # 检测到输入源 → 提升置信度
        if input_sources:
            base = 0.85
        # taint_chain越短越可信 (直接传递 vs 多层间接)
        if taint_chain and taint_chain.count('<=') <= 2:
            base = min(base + 0.05, 0.95)
        return base

    return 0.25  # 未知来源

def _build_reason(func: str, addr: int,
                  from_rdata: bool, from_param: bool,
                  fmt_str: str, taint_chain: str,
                  input_sources: List[str]) -> str:
    """生成裁决理由."""
    if from_rdata:
        preview = fmt_str[:60] if fmt_str else '?'
        return f'{func}@{addr:x}: .rdata "{preview}" — safe'
    if from_param:
        src = ", ".join(input_sources) if input_sources else 'none'
        chain = taint_chain[:80] if taint_chain else 'direct'
        return f'{func}@{addr:x}: param-derived [{chain}], inputs=[{src}]'
    return f'{func}@{addr:x}: unresolved'

# 便捷函数

def analyze_binary(binary_path: str) -> FmtReport:
    """一站式二进制格式串分析."""
    orch = FmtOrchestrator()
    return orch.analyze(binary_path)

# smoke test
def _check():
    import os, glob
    test_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..',
                            'exploit', 'tests', 'regression', 'build', 'gcc', 'O0')
    fmt_samples = sorted(glob.glob(os.path.join(test_dir, 'cve_fmt_*.exe')))
    if not fmt_samples:
        print("[SKIP] No cve_fmt samples found")
        return
    orch = FmtOrchestrator()
    ok = 0
    for s in fmt_samples:
        name = os.path.basename(s)
        r = orch.analyze(s)
        status = "VULN" if r.has_vulnerability else "SAFE"
        print(f"  {name}: {r.total_printf_calls} calls, "
              f"{len(r.vulnerable)} vuln, {len(r.safe)} safe, "
              f"{len(r.filtered_fps)} fp → {status} ({r.analysis_time_ms:.0f}ms)")
        for vv in r.vulnerable:
            print(f"    VULN: {vv.reason[:120]}")
        if r.has_vulnerability:
            ok += 1
    print(f"\nResult: {ok}/{len(fmt_samples)} vulnerable, "
          f"{sum(len(r.filtered_fps) for r in [orch.analyze(s) for s in fmt_samples])} FPs filtered")

if __name__ == "__main__":
    _check()
