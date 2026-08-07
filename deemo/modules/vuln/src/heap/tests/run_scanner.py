"""SHIELD 回归测试 — 扫描器.

对编译好的 .objdump 文件运行堆溢出检测器 (原始 + SHIELD 过滤),
收集所有 findings 并写入 JSON.

用法:
  python run_scanner.py                     # 扫描所有
  python run_scanner.py --opt O0             # 仅 O0
  python run_scanner.py --sample cve_2021_3156  # 单样本

创建: 2026-06-09
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

BUILD_ROOT = Path(__file__).resolve().parent / "build"
RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# 将 heap 模块路径加入 sys.path
HEAP_SRC = Path(__file__).resolve().parent.parent
if str(HEAP_SRC) not in sys.path:
    sys.path.insert(0, str(HEAP_SRC))


def load_objdump(path: Path) -> List[str]:
    """加载 objdump 文件, 返回指令行列表."""
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.rstrip() for line in f if line.strip() and ':' in line[:20]]


def parse_addrs(lines: List[str]) -> List[int]:
    """从 objdump 行提取指令地址."""
    import re
    addrs = []
    addr_pat = re.compile(r'\s*([0-9a-f]+):')
    for line in lines:
        m = addr_pat.match(line)
        if m:
            addrs.append(int(m.group(1), 16))
        else:
            addrs.append(0)
    return addrs


def scan_raw(instructions: List[str], addrs: List[int],
             function_name: str) -> List[dict]:
    """原始 ImprovedHeapOverflowDetector 扫描."""
    try:
        from analysis.heap_overflow_detector import ImprovedHeapOverflowDetector
    except ImportError:
        print("  [WARN] heap_overflow_detector not importable, skipping raw scan")
        return []

    detector = ImprovedHeapOverflowDetector()
    findings = detector.analyze(
        instructions, function_name=function_name, addrs=addrs)
    return [
        {
            'insn_addr': f.insn_addr,
            'function_name': f.function_name,
            'description': f.description,
            'alloc_site': f.alloc_site,
            'alloc_size_requested': f.alloc_size_requested,
            'alloc_size_usable': f.alloc_size_usable,
            'access_offset': f.access_offset,
            'access_size': f.access_size,
            'overflow_bytes': f.overflow_bytes,
            'semantic_score': f.semantic_score,
            'is_likely_fp': f.is_likely_fp,
            'fp_reason': f.fp_reason,
            'confidence': f.confidence,
            'size_source': f.size_source,
            'safety_verdict': f.safety_verdict,
        }
        for f in findings
    ]


def scan_shield(instructions: List[str], findings: List[dict],
                addrs: List[int]) -> dict:
    """用 SHIELD 编排器过滤原始 findings."""
    try:
        from shield_orchestrator import ShieldOrchestrator
    except ImportError:
        print("  [WARN] shield_orchestrator not importable, skipping SHIELD scan")
        return {'verdicts': [], 'filtered': 0, 'confirmed': 0,
                'filter_rate': 0.0, 'engine_stats': {}}

    orch = ShieldOrchestrator()
    report = orch.analyze(instructions, findings, addrs)
    return {
        'verdicts': [
            {
                'finding_id': v.finding_id,
                'is_safe': v.is_safe,
                'engine': v.engine,
                'confidence': v.confidence,
                'reasoning': v.reasoning,
            }
            for v in report.verdicts
        ],
        'filtered': report.filtered,
        'confirmed': report.confirmed,
        'filter_rate': report.filter_rate,
        'engine_stats': report.engine_stats,
    }


def scan_one(objdump_path: Path) -> dict:
    """扫描单个 objdump 文件."""
    sample_name = objdump_path.stem
    instructions = load_objdump(objdump_path)
    addrs = parse_addrs(instructions)

    t0 = time.perf_counter()
    raw_findings = scan_raw(instructions, addrs, f"{sample_name}!main")
    raw_time = time.perf_counter() - t0

    t1 = time.perf_counter()
    shield_result = scan_shield(instructions, raw_findings, addrs)
    shield_time = time.perf_counter() - t1

    return {
        'sample': sample_name,
        'objdump_path': str(objdump_path),
        'num_instructions': len(instructions),
        'raw_findings': raw_findings,
        'raw_count': len(raw_findings),
        'raw_time_ms': round(raw_time * 1000, 1),
        'shield': shield_result,
        'shield_time_ms': round(shield_time * 1000, 1),
        'final_count': shield_result['confirmed'],
        'filtered_count': shield_result['filtered'],
    }


def main():
    parser = argparse.ArgumentParser(description="SHIELD 回归扫描器")
    parser.add_argument("--opt", type=str, default="", help="优化级别 (O0/O2)")
    parser.add_argument("--sample", type=str, default="", help="单样本过滤")
    args = parser.parse_args()

    opts = [args.opt] if args.opt else ["O0", "O2"]
    all_results = []

    for opt in opts:
        opt_dir = BUILD_ROOT / "gcc" / opt
        if not opt_dir.exists():
            print(f"  [SKIP] no build for {opt}")
            continue

        objdumps = sorted(opt_dir.glob("*.objdump"))
        if args.sample:
            objdumps = [o for o in objdumps if args.sample in o.stem]

        for od in objdumps:
            print(f"  Scanning: {od.stem} ({opt}) ...")
            result = scan_one(od)
            all_results.append(result)

            n_raw = result['raw_count']
            n_final = result['final_count']
            n_filtered = result['filtered_count']
            print(f"    Raw: {n_raw} findings → SHIELD: {n_final} remaining "
                  f"({n_filtered} filtered, {result['shield_time_ms']}ms)")

    # 写入结果
    out_path = RESULTS_DIR / "scan_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results written to {out_path}")
    print(f"  Total samples scanned: {len(all_results)}")


if __name__ == "__main__":
    main()
