"""
多工具对比实验主脚本 — 统一基准测试框架.

合并说明 (BinMind/eval ↔ deemo/modules/eval 两个版本功能合并):
  - deemo/modules/eval 版: HFP 管线 — 遍历 samples/heap_overflow,
    运行 HFP 引擎 (hfp.hfp_scan + hfp.hfp_engine) + angr/qemu/ghidra
    外部脚本 (subprocess, 缺失标记 UNAVAILABLE), 输出
    results/benchmark_hfp.csv + results/benchmark_summary.json;
    CLI: --out.
  - BinMind/eval 版: DDSSSC 管线 — 通过 regression_heap 注册表
    运行 BinMind-DDSSC/BinMind-Baseline (scan_sample) + angr/ghidra/
    qemu (模块内加载), 输出 benchmark_results.csv +
    benchmark_summary.json (脚本目录); CLI: --output/-o, --tools/-t.
  - 新增 ToolAdapter 基类与 VULN_SAMPLES 常量, 供同目录
    angr_adapter.py / ghidra_adapter.py (import run_benchmark) 使用.
  - main() 调度: 仅给 --out → HFP 管线; 仅给 --output/-t → DDSSSC
    管线; 都不给 → 两条管线顺序执行.

  python run_benchmark.py --out results/benchmark_hfp.csv   # HFP 管线
  python run_benchmark.py --output benchmark_results.csv    # DDSSSC 管线
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
SAMPLE_ROOT = BASE / 'samples' / 'heap_overflow'
RESULTS = BASE / 'results'

sys.path.insert(0, str(BASE))

from hfp.hfp_scan import asm_to_pseudo_ir  # noqa: E402
from hfp.hfp_engine import detect_heap_overflow_hfp, suppress_and_report  # noqa: E402

_BINMIND = Path(r"C:\Users\Administrator\Desktop\BinMind")
for p in (str(_BINMIND), str(_BINMIND / "deemo"), str(ROOT),
          str(_BINMIND / "deemo" / "modules" / "analysis"),
          str(_BINMIND / "deemo" / "modules" / "analysis" / "regression_heap")):
    if p not in sys.path:
        sys.path.insert(0, p)

from regression_heap.collect_results import build_registry  # noqa: E402
from regression_heap.scan_dispatch import scan_sample  # noqa: E402

SAFE_SAMPLES = {'safe_01_guard_narrow', 'safe_02_align_slack',
                'safe_03_same_source'}


class ToolAdapter:
    """工具适配器基类 (供 angr_adapter.py / ghidra_adapter.py 使用)."""

    name = "tool"

    def run(self, binary_path: str) -> List[dict]:
        raise NotImplementedError


def _vuln_sample_names() -> frozenset:
    """samples/heap_overflow 中除安全对照外的漏洞样本名."""
    try:
        return frozenset(
            d.name for d in SAMPLE_ROOT.iterdir()
            if d.is_dir() and d.name not in SAFE_SAMPLES)
    except Exception:
        return frozenset()


VULN_SAMPLES = _vuln_sample_names()


# ---------------------------------------------------------------------------
# deemo/modules/eval 版: HFP 管线
# ---------------------------------------------------------------------------

def run_hfp(binary: str, asm: str) -> Dict:
    """[deemo 版] HFP 引擎扫描, 统计检出与耗时."""
    t0 = time.perf_counter()
    text = Path(asm).read_text(encoding='utf-8', errors='replace')
    ir = asm_to_pseudo_ir(text)
    findings = detect_heap_overflow_hfp(ir)
    kept, stats = suppress_and_report(findings)
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        'detected': len(kept),
        'overflow': stats['overflow'],
        'potential': stats['potential'],
        'elapsed_ms': round(elapsed, 2),
    }


def run_external(tool: str, binary: str, sample: str) -> Dict:
    """[deemo 版] 调用外部工具脚本, 容错降级."""
    script = {
        'angr': 'angr_explorer.py',
        'qemu': 'qemu_tracer.py',
        'ghidra': 'ghidra_headless.py',
    }[tool]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).parent / script), binary],
            capture_output=True, text=True, timeout=600)
        elapsed = (time.perf_counter() - t0) * 1000
        if proc.returncode != 0:
            return {'tool': tool, 'sample': sample, 'available': False,
                    'error': 'exit %d' % proc.returncode,
                    'detected': 0, 'elapsed_ms': round(elapsed, 2)}
        data = json.loads(proc.stdout)
        return {
            'tool': tool, 'sample': sample,
            'available': bool(data.get('success')),
            'detected': int(data.get('findings', 0)),
            'error': data.get('error', ''),
            'elapsed_ms': round(elapsed, 2),
        }
    except Exception as e:
        return {'tool': tool, 'sample': sample, 'available': False,
                'error': str(e)[:120], 'detected': 0,
                'elapsed_ms': round((time.perf_counter() - t0) * 1000, 2)}


def classify(sample: str, tool: str, detected: int) -> str:
    """[deemo 版] 按 ground truth 归类 TP/FP/FN/TN."""
    vuln = sample not in SAFE_SAMPLES
    has = detected > 0
    if vuln and has:
        return 'TP'
    if vuln and not has:
        return 'FN'
    if not vuln and has:
        return 'FP'
    return 'TN'


def _summarize(rows: List[Dict]) -> Dict:
    """[deemo 版] 按工具聚合召回率/误报率."""
    out = {}
    for tool in ('BinMind-HFP', 'angr', 'qemu', 'ghidra'):
        tool_rows = [r for r in rows if r['tool'] == tool]
        if not tool_rows:
            continue
        avail = [r for r in tool_rows if r['verdict'] != 'UNAVAILABLE']
        if not avail:
            out[tool] = {'status': 'unavailable'}
            continue
        vuln = [r for r in avail if r['ground_truth'] == 'VULN']
        safe = [r for r in avail if r['ground_truth'] == 'SAFE']
        tp = sum(1 for r in vuln if r['verdict'] == 'TP')
        fn = sum(1 for r in vuln if r['verdict'] == 'FN')
        fp = sum(1 for r in safe if r['verdict'] == 'FP')
        tn = sum(1 for r in safe if r['verdict'] == 'TN')
        out[tool] = {
            'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'recall': round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
            'fpr': round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            'avg_time_ms': round(
                sum(r['elapsed_ms'] for r in avail) / len(avail), 2),
        }
    return out


def _benchmark_hfp(out_path: str) -> int:
    """[deemo 版] HFP 多工具基准管线."""
    rows: List[Dict] = []
    samples = sorted(
        d for d in SAMPLE_ROOT.iterdir()
        if d.is_dir() and (d / 'vuln.exe').exists())

    for sdir in samples:
        name = sdir.name
        binary = str(sdir / 'vuln.exe')
        asm = str(sdir / 'vuln.asm')
        if not Path(asm).exists():
            proc = subprocess.run(
                ['objdump', '-d', '-M', 'intel', binary],
                capture_output=True, text=True, timeout=60)
            Path(asm).write_text(proc.stdout, encoding='utf-8',
                                 errors='replace')

        # HFP (含峰值内存)
        tracemalloc.start()
        hfp = run_hfp(binary, asm)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append({
            'tool': 'BinMind-HFP', 'sample': name,
            'ground_truth': 'VULN' if name not in SAFE_SAMPLES else 'SAFE',
            'detected': hfp['detected'],
            'fp': 1 if (name in SAFE_SAMPLES and hfp['detected'] > 0) else 0,
            'fn': 1 if (name not in SAFE_SAMPLES and hfp['detected'] == 0) else 0,
            'elapsed_ms': hfp['elapsed_ms'],
            'peak_memory_kb': round(peak / 1024, 1),
            'verdict': classify(name, 'hfp', hfp['detected']),
        })

        for tool in ('angr', 'qemu', 'ghidra'):
            ext = run_external(tool, binary, name)
            if not ext['available']:
                rows.append({
                    'tool': tool, 'sample': name,
                    'ground_truth': 'VULN' if name not in SAFE_SAMPLES else 'SAFE',
                    'detected': 0,
                    'fp': 0, 'fn': 0,
                    'elapsed_ms': ext['elapsed_ms'],
                    'peak_memory_kb': 0,
                    'verdict': 'UNAVAILABLE',
                })
                continue
            verdict = classify(name, tool, ext['detected'])
            rows.append({
                'tool': tool, 'sample': name,
                'ground_truth': 'VULN' if name not in SAFE_SAMPLES else 'SAFE',
                'detected': ext['detected'],
                'fp': 1 if verdict == 'FP' else 0,
                'fn': 1 if verdict == 'FN' else 0,
                'elapsed_ms': ext['elapsed_ms'],
                'peak_memory_kb': 0,
                'verdict': verdict,
            })

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # 汇总
    summary = _summarize(rows)
    Path(RESULTS / 'benchmark_summary.json').write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# BinMind/eval 版: DDSSSC 管线
# ---------------------------------------------------------------------------

def _load_module(name: str, path: Path):
    """[eval 版] 按路径加载模块."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_binmind(binary, enhanced: bool):
    """[eval 版] 通过 regression_heap 引擎扫描."""
    return scan_sample(binary, enable_bwr=enhanced, enable_pcst=enhanced)


def run_angr(binary):
    """[eval 版] 模块内调用 angr_explorer.explore."""
    mod = _load_module("angr_explorer", ROOT / "angr_explorer.py")
    return mod.explore(binary)


def run_ghidra(binary):
    """[eval 版] 模块内调用 ghidra_headless.audit."""
    mod = _load_module("ghidra_headless", ROOT / "ghidra_headless.py")
    return mod.audit(binary)


def run_qemu(binary):
    """[eval 版] 模块内调用 qemu_tracer.trace."""
    mod = _load_module("qemu_tracer", ROOT / "qemu_tracer.py")
    return mod.trace(binary)


def verdict_of(is_vuln: bool, count: int):
    """[eval 版] 判定 TP/FP/FN/TN."""
    if is_vuln and count > 0:
        return "TP"
    if is_vuln and count == 0:
        return "FN"
    if not is_vuln and count > 0:
        return "FP"
    return "TN"


def measure(fn):
    """[eval 版] 计时 + 峰值内存测量."""
    tracemalloc.start()
    t0 = time.perf_counter()
    try:
        r = fn()
        err = None
    except Exception as e:
        r = {"findings": 0}
        err = f"{type(e).__name__}: {e}"
    elapsed = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return r, elapsed, peak / 1024 / 1024, err


def _benchmark_ddssc(output_path: str, tool_names: List[str]) -> int:
    """[eval 版] DDSSSC 多工具基准管线."""
    registry = build_registry()
    print(f"[benchmark] {len(registry)} samples, tools={tool_names}")

    rows = []
    tools = {
        "binmind": ("BinMind-DDSSC", lambda b: run_binmind(b, True)),
        "baseline": ("BinMind-Baseline", lambda b: run_binmind(b, False)),
        "angr": ("angr", run_angr),
        "ghidra": ("Ghidra", run_ghidra),
        "qemu": ("QEMU/Unicorn", run_qemu),
    }

    for name, path, is_vuln in registry:
        for t in tool_names:
            if t not in tools:
                continue
            label, fn = tools[t]
            r, elapsed, peak, err = measure(lambda: fn(path))
            count = r.get("count", r.get("findings", 0))
            v = verdict_of(is_vuln, count)
            rows.append({
                "tool": label, "sample": name,
                "truth": "vuln" if is_vuln else "safe",
                "verdict": v, "findings": count,
                "tp": 1 if v == "TP" else 0, "fp": 1 if v == "FP" else 0,
                "fn": 1 if v == "FN" else 0, "tn": 1 if v == "TN" else 0,
                "time_ms": round(elapsed, 2),
                "peak_mem_mb": round(peak, 2),
                "error": err or "",
            })
        print(f"  {name}: done")

    out = Path(output_path)
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"[csv] {out}")

    summary = {}
    for t in tool_names:
        if t not in tools:
            continue
        label, _ = tools[t]
        tr = [r for r in rows if r["tool"] == label]
        tp = sum(r["tp"] for r in tr)
        fp = sum(r["fp"] for r in tr)
        fn = sum(r["fn"] for r in tr)
        tn = sum(r["tn"] for r in tr)
        recall = tp / max(tp + fn, 1) * 100
        precision = tp / max(tp + fp, 1) * 100
        fpr = fp / max(fp + tn, 1) * 100
        f1 = 2 * tp / max(2 * tp + fp + fn, 1)
        summary[label] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
                          "Recall": round(recall, 2),
                          "Precision": round(precision, 2),
                          "FPR": round(fpr, 2), "F1": round(f1, 4),
                          "avg_time_ms": round(sum(r["time_ms"] for r in tr)
                                               / max(len(tr), 1), 2)}
    with open(ROOT / "benchmark_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    for label, s in summary.items():
        print(f"  {label}: {json.dumps(s)}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description='multi-tool benchmark')
    ap.add_argument('--out', default=None,
                    help='HFP 管线输出 CSV (默认 results/benchmark_hfp.csv)')
    ap.add_argument('--output', '-o', default=None,
                    help='DDSSSC 管线输出 CSV (默认 benchmark_results.csv)')
    ap.add_argument('--tools', '-t', nargs='*', default=None,
                    help='DDSSSC 管线工具列表')
    args = ap.parse_args(argv)

    hfp_out = args.out or str(RESULTS / 'benchmark_hfp.csv')
    ddssc_out = args.output or str(ROOT / 'benchmark_results.csv')

    want_hfp = args.out is not None and args.output is None and args.tools is None
    want_ddssc = (args.output is not None or args.tools is not None) \
        and args.out is None
    want_both = args.out is None and args.output is None and args.tools is None

    code = 0
    if want_hfp or want_both:
        print('=== HFP pipeline ===')
        code |= _benchmark_hfp(hfp_out)
    if want_ddssc or want_both:
        print('=== DDSSSC pipeline ===')
        code |= _benchmark_ddssc(ddssc_out, args.tools or [
            "binmind", "baseline", "angr", "ghidra", "qemu"])
    return code


if __name__ == '__main__':
    sys.exit(main())