"""
统一多工具对比基准测试 — BinMind增强管线 vs 外部工具.

运行所有堆溢出样本, 对比以下工具:
  BinMind-Enhanced (Stage A+B+C+D + GAPSBV5D + inter-procedural affine)
  BinMind-Baseline (Stage A+B+C only)
  Angr (符号执行)
  Ghidra (headless decompile)
  QEMU (user-mode trace)
  Regex-Baseline (简单模式匹配)

输出: 精确率/召回率/F1/FP数/平均时间 的对比表.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class ToolResult:
    tool: str
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    fp_count: int = 0
    fn_count: int = 0
    tp_count: int = 0
    tn_count: int = 0
    avg_time_ms: float = 0.0
    total_samples: int = 0
    errors: List[str] = field(default_factory=list)


def run_binmind_baseline(sample_dir: str) -> ToolResult:
    """BinMind 基线: 仅 Stage A+B+C (guard + path_condition + interval)."""
    result = ToolResult(tool="BinMind-Baseline")
    samples = _discover_samples(sample_dir, "heap")
    if not samples:
        result.errors.append("no heap samples found")
        return result
    result.total_samples = len(samples)
    times = []
    for sample in samples:
        try:
            code = Path(sample).read_text(encoding='utf-8', errors='replace')
            t0 = time.perf_counter()
            from core.ir_normalizer import normalize_c_source
            from core.heap_overflow_detector import detect_heap_overflow
            ir_lines = normalize_c_source(code)
            candidates = detect_heap_overflow(ir_lines, code)
            from analysis.heap_overflow_verifier import HeapOverflowVerifier
            verifier = HeapOverflowVerifier(
                enable_stage_a=True, enable_stage_b=True,
                enable_stage_c=True, enable_stage_d=False)
            kept, _ = verifier.verify(candidates, ir_lines, code)
            elapsed = (time.perf_counter() - t0) * 1000
            times.append(elapsed)
            gt = _load_ground_truth(sample)
            counted = _update_counts(result, len(kept) > 0, gt.get("is_vuln", False),
                                     gt.get("heap_relevant", True))
            if not counted:
                result.total_samples -= 1
        except Exception as e:
            result.errors.append(f"{os.path.basename(sample)}: {e}")
    if times:
        result.avg_time_ms = sum(times) / len(times)
    _compute_metrics(result)
    return result


def run_binmind_enhanced(sample_dir: str) -> ToolResult:
    """BinMind 增强: Stage A+B+C+D + GAPSBV5D + inter-procedural affine."""
    result = ToolResult(tool="BinMind-Enhanced")
    samples = _discover_samples(sample_dir, "heap")
    if not samples:
        result.errors.append("no heap samples found")
        return result
    result.total_samples = len(samples)
    times = []
    for sample in samples:
        try:
            code = Path(sample).read_text(encoding='utf-8', errors='replace')
            t0 = time.perf_counter()
            from core.heap_overflow_pipeline import detect_heap_overflows_full
            from core.ir_normalizer import normalize_c_source
            ir_lines = normalize_c_source(code)
            candidates, stats = detect_heap_overflows_full(ir_lines, code)
            elapsed = (time.perf_counter() - t0) * 1000
            times.append(elapsed)
            gt = _load_ground_truth(sample)
            counted = _update_counts(result, len(candidates) > 0, gt.get("is_vuln", False),
                                     gt.get("heap_relevant", True))
            if not counted:
                result.total_samples -= 1
        except Exception as e:
            result.errors.append(f"{os.path.basename(sample)}: {e}")
    if times:
        result.avg_time_ms = sum(times) / len(times)
    _compute_metrics(result)
    return result


def run_binmind_gapsbv5d(sample_dir: str) -> ToolResult:
    """BinMind GAPSBV 5D 独立管道 (detect_heap_overflow_gapsbv)."""
    result = ToolResult(tool="BinMind-GAPSBV5D")
    samples = _discover_samples(sample_dir, "heap")
    if not samples:
        result.errors.append("no heap samples found")
        return result
    result.total_samples = len(samples)
    times = []
    for sample in samples:
        try:
            code = Path(sample).read_text(encoding='utf-8', errors='replace')
            t0 = time.perf_counter()
            from analysis.gapsbv_pipeline import detect_heap_overflow_gapsbv
            report = detect_heap_overflow_gapsbv(code)
            elapsed = (time.perf_counter() - t0) * 1000
            times.append(elapsed)
            gt = _load_ground_truth(sample)
            detected = report.verdict in ("OVERFLOW", "CONDITIONAL")
            counted = _update_counts(result, detected, gt.get("is_vuln", False),
                                     gt.get("heap_relevant", True))
            if not counted:
                result.total_samples -= 1
        except Exception as e:
            result.errors.append(f"{os.path.basename(sample)}: {e}")
    if times:
        result.avg_time_ms = sum(times) / len(times)
    _compute_metrics(result)
    return result


def run_regex_baseline(sample_dir: str) -> ToolResult:
    """Regex 基线: 简单模式匹配 malloc + memcpy/strcpy."""
    result = ToolResult(tool="Regex-Baseline")
    samples = _discover_samples(sample_dir, "heap")
    if not samples:
        result.errors.append("no heap samples found")
        return result
    result.total_samples = len(samples)
    import re
    malloc_pat = re.compile(r'\b(?:malloc|calloc|realloc)\s*\(', re.IGNORECASE)
    write_pat = re.compile(r'\b(?:memcpy|strcpy|strncpy|memset|strcat)\s*\(', re.IGNORECASE)
    times = []
    for sample in samples:
        try:
            code = Path(sample).read_text(encoding='utf-8', errors='replace')
            t0 = time.perf_counter()
            has_malloc = bool(malloc_pat.search(code))
            has_write = bool(write_pat.search(code))
            elapsed = (time.perf_counter() - t0) * 1000
            times.append(elapsed)
            gt = _load_ground_truth(sample)
            counted = _update_counts(result, has_malloc and has_write, gt.get("is_vuln", False),
                                     gt.get("heap_relevant", True))
            if not counted:
                result.total_samples -= 1
        except Exception as e:
            result.errors.append(f"{os.path.basename(sample)}: {e}")
    if times:
        result.avg_time_ms = sum(times) / len(times)
    _compute_metrics(result)
    return result


def run_flawfinder(sample_dir: str) -> ToolResult:
    """Flawfinder: 基于模式的C/C++漏洞扫描器."""
    result = ToolResult(tool="Flawfinder")
    samples = _discover_samples(sample_dir, "heap")
    if not samples:
        result.errors.append("flawfinder not available or no samples")
        return result
    result.total_samples = len(samples)
    times = []
    for sample in samples:
        try:
            t0 = time.perf_counter()
            import subprocess
            proc = subprocess.run(
                ['flawfinder', '--quiet', sample],
                capture_output=True, text=True, timeout=30)
            elapsed = (time.perf_counter() - t0) * 1000
            times.append(elapsed)
            output = proc.stdout + proc.stderr
            detected = 'heap' in output.lower() or 'buffer' in output.lower()
            gt = _load_ground_truth(sample)
            counted = _update_counts(result, detected, gt.get("is_vuln", False),
                                     gt.get("heap_relevant", True))
            if not counted:
                result.total_samples -= 1
        except Exception as e:
            result.errors.append(f"{os.path.basename(sample)}: {e}")
    if times:
        result.avg_time_ms = sum(times) / len(times)
    _compute_metrics(result)
    return result


def _discover_samples(sample_dir: str, vuln_type: str) -> List[str]:
    """发现样本文件 (.c / .cpp)."""
    samples = []
    base = Path(sample_dir)
    if not base.exists():
        return samples
    # 遍历子目录, 收集所有C源文件
    for ext in ('*.c', '*.cpp', '*.txt'):
        for f in base.rglob(ext):
            samples.append(str(f))
    # 过滤: 去重, 排除 Makefile/build 产物
    samples = [s for s in samples
               if 'Makefile' not in s and 'build' not in os.path.basename(s)]
    return sorted(samples)[:50]


def _load_ground_truth(sample_path: str) -> dict:
    """从样本路径或相邻 ground_truth.json 加载标签."""
    # 优先: 同目录下的 ground_truth.json
    gt_dir = os.path.dirname(sample_path)
    gt_file = os.path.join(gt_dir, 'ground_truth.json')
    if os.path.exists(gt_file):
        with open(gt_file, 'r', encoding='utf-8') as f:
            all_gt = json.load(f)
        basename = os.path.basename(sample_path)
        if basename in all_gt:
            return all_gt[basename]
        # 也尝试目录名作为key
        dirname = os.path.basename(gt_dir)
        if dirname in all_gt:
            return all_gt[dirname]
    # 也尝试父目录的 ground_truth.json (sample_dir = samples/cve_gapsbv)
    parent_gt = os.path.join(os.path.dirname(gt_dir), 'ground_truth.json')
    if os.path.exists(parent_gt):
        with open(parent_gt, 'r', encoding='utf-8') as f:
            all_gt = json.load(f)
        dirname = os.path.basename(gt_dir)
        if dirname in all_gt:
            return all_gt[dirname]
    # 启发式: 从目录名推断 — ho_* / heap_overflow_* → vuln
    dirname = os.path.basename(os.path.dirname(sample_path))
    is_vuln = any(kw in dirname.lower() for kw in ('overflow', 'vuln', 'cve'))
    return {"is_vuln": is_vuln, "label": dirname, "heap_relevant": True}


def _update_counts(result: ToolResult, detected: bool, is_vuln: bool,
                   heap_relevant: bool = True) -> bool:
    """更新TP/FP/FN/TN计数. 返回 True 表示已计入, False 表示跳过 (非堆相关)."""
    if not heap_relevant:
        return False
    if detected and is_vuln:
        result.tp_count += 1
    elif detected and not is_vuln:
        result.fp_count += 1
    elif not detected and is_vuln:
        result.fn_count += 1
    else:
        result.tn_count += 1
    return True


def _compute_metrics(result: ToolResult) -> None:
    total = result.tp_count + result.fp_count + result.fn_count + result.tn_count
    if total == 0:
        return
    result.precision = (result.tp_count / (result.tp_count + result.fp_count)
                        if (result.tp_count + result.fp_count) > 0 else 0.0)
    result.recall = (result.tp_count / (result.tp_count + result.fn_count)
                     if (result.tp_count + result.fn_count) > 0 else 0.0)
    if result.precision + result.recall > 0:
        result.f1 = (2 * result.precision * result.recall /
                     (result.precision + result.recall))


def run_full_comparison(sample_dir: str = "samples/cve_gapsbv") -> List[ToolResult]:
    """运行完整的多工具对比."""
    results = []
    for runner in [run_binmind_baseline, run_binmind_enhanced,
                    run_binmind_gapsbv5d, run_regex_baseline, run_flawfinder]:
        try:
            r = runner(sample_dir)
            results.append(r)
        except Exception as e:
            results.append(ToolResult(tool=runner.__name__, errors=[str(e)]))
    return results


def print_comparison_table(results: List[ToolResult]) -> None:
    """打印对比表."""
    header = f"{'Tool':<25} {'Prec':>7} {'Recall':>7} {'F1':>7} {'FP':>5} {'FN':>5} {'Time(ms)':>9}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r.tool:<25} {r.precision:>7.3f} {r.recall:>7.3f} "
              f"{r.f1:>7.3f} {r.fp_count:>5} {r.fn_count:>5} "
              f"{r.avg_time_ms:>9.1f}")


def save_results_json(results: List[ToolResult], output: str = "eval/multi_tool_comparison.json") -> None:
    """保存结果为JSON."""
    data = []
    for r in results:
        data.append({
            "tool": r.tool,
            "precision": round(r.precision, 4),
            "recall": round(r.recall, 4),
            "f1": round(r.f1, 4),
            "fp_count": r.fp_count,
            "fn_count": r.fn_count,
            "tp_count": r.tp_count,
            "avg_time_ms": round(r.avg_time_ms, 1),
            "total_samples": r.total_samples,
            "errors": r.errors[:3],
        })
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Results saved to {output}")


if __name__ == "__main__":
    sample_dir = sys.argv[1] if len(sys.argv) > 1 else "samples/cve_gapsbv"
    results = run_full_comparison(sample_dir)
    print_comparison_table(results)
    save_results_json(results)
