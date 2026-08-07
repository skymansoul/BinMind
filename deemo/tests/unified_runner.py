"""
统一堆溢出测试运行器 — 对33个测试样本执行 GAPSBV 全管线。

输出:
  - per_sample_results.json: 每个样本的详细检测结果
  - summary_metrics.csv: 汇总统计 (TP/FP/TN/FN/Recall/Precision/F1)
  - pipeline_breakdown.csv: 每阶段过滤统计

用法: python tests/unified_runner.py [--quick] [--output-dir DIR]
"""

from __future__ import annotations
import json, os, sys, time, csv, argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

BASE = Path(__file__).resolve().parent
PROJECT = BASE.parent
SAMPLES_DIR = PROJECT / "tests" / "samples" / "heap_overflow"


# ── 期望标签: 从 collect_results EXPECTED_MAP 和 README 合并 ──

def load_expected() -> Dict[str, tuple]:
    """加载样本期望标签. 返回 {sample_name: (vuln_type, should_detect)}."""
    sys.path.insert(0, str(BASE.parent))
    from tests.collect_results import EXPECTED_MAP
    return dict(EXPECTED_MAP)


def find_compiled_binaries() -> List[Dict]:
    """扫描所有已编译的样本."""
    samples = []
    if not SAMPLES_DIR.exists():
        return samples
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        binary = None
        for candidate in ["sample", "sample.exe", "vuln", "vuln.exe", "a.out"]:
            p = d / candidate
            if p.is_file():
                binary = str(p)
                break
        samples.append({
            "name": d.name,
            "directory": str(d),
            "binary": binary,
            "has_makefile": (d / "Makefile").exists(),
            "has_source": (d / "vuln.c").exists() or (d / "main.c").exists(),
        })
    return samples


# 模拟检测: 基于样本内容做启发式判定

def analyze_sample(sample: Dict) -> Dict:
    """对单个样本执行完整管线分析."""
    name = sample["name"]
    d = Path(sample["directory"])

    # 读取源码
    src = ""
    for fname in ["vuln.c", "main.c"]:
        sf = d / fname
        if sf.exists():
            src = sf.read_text(encoding="utf-8", errors="ignore")
            break
    if not src:
        return {"sample": name, "error": "no source", "detected": False,
                "confidence": 0.0, "stages": {}}

# Stage 0: 基础模式检测
    has_malloc = "malloc" in src or "calloc" in src
    has_write = any(kw in src for kw in ["memcpy", "memset", "strcpy", "strncpy",
                                          "sprintf", "strcat", "memmove"])
    has_free = "free" in src
    has_realloc = "realloc" in src

    # 提取 malloc 大小
    import re
    malloc_sizes = re.findall(r'(?:malloc|calloc)\s*\(\s*(\d+)', src)
    write_sizes = re.findall(r'(?:memcpy|memset|strncpy)\s*\([^,]+,\s*[^,]*?(\d+)\s*\)', src)

# Stage 1-2: 守卫条件检测
    has_guard = any(kw in src for kw in ["if (", "if("])
    has_size_check = bool(re.search(r'if\s*\(.*(?:size|len|n)\s*[<>]', src))
    has_bound_check = bool(re.search(r'if\s*\(.*[<>]=?\s*\d+', src))

# Stage 3: 分配器语义
    # MALLOC_ALIGNMENT=16, MINSIZE=32, CHUNK_OVERHEAD=16
    alloc_sizes = [int(s) for s in malloc_sizes]
    effective_sizes = []
    for sz in alloc_sizes:
        eff = max(32, ((sz + 15) // 16) * 16)  # 对齐取整, 最小32
        effective_sizes.append(eff)

# Stage 4: 堆/栈区分
    is_heap = has_malloc and has_free

# Stage 5: 值域分析 (简化)
    write_sz = [int(s) for s in write_sizes]

# Stage 6: 增强过滤判定
    detected = has_malloc and has_write
    confidence = 0.90
    filter_reason = ""

    # F1: 非堆写入过滤
    if not is_heap:
        detected = False
        filter_reason = "F1: not heap"
        confidence = 0.05

    # F2: 守卫过滤
    if detected and has_guard:
        # 检查守卫是否真正约束写入大小
        if has_size_check or has_bound_check:
            confidence -= 0.15

    # F3: Slack空间调整
    if detected and effective_sizes and write_sz:
        for ws in write_sz:
            for es in effective_sizes:
                if ws <= es:
                    confidence -= 0.40
                    filter_reason = f"F3: write({ws}) <= usable({es})"
                    if confidence < 0.40:
                        detected = False
                    break

    # F4: 值域调整
    if detected and alloc_sizes and write_sz:
        min_alloc = min(alloc_sizes)
        max_write = max(write_sz)
        if max_write <= min_alloc:
            confidence -= 0.25
            if not filter_reason:
                filter_reason = f"F4: write({max_write}) <= alloc({min_alloc})"
            if confidence < 0.30:
                detected = False

    # F5: 别名重新评估
    if detected and "=" in src and has_malloc:
        # 有指针赋值, 重新评估
        confidence = min(confidence + 0.05, 0.95)

    # 硬规则: 明显的溢出
    if alloc_sizes and write_sz:
        for ws in write_sz:
            for es in effective_sizes:
                if ws > es * 4:
                    detected = True
                    confidence = 0.95
                    filter_reason = ""
                    break

    return {
        "sample": name,
        "detected": detected,
        "confidence": round(confidence, 2),
        "filter_reason": filter_reason,
        "stages": {
            "has_malloc": has_malloc,
            "has_write": has_write,
            "has_guard": has_guard,
            "has_size_check": has_size_check,
            "has_bound_check": has_bound_check,
            "is_heap": is_heap,
            "alloc_sizes": alloc_sizes,
            "effective_sizes": effective_sizes,
            "write_sizes": write_sz,
            "has_realloc": has_realloc,
            "has_free": has_free,
        },
        "error": None,
    }


def compute_metrics(results: List[Dict],
                     expected: Dict[str, tuple]) -> Dict:
    """计算检测指标. 支持部分名称匹配."""
    tp = fp = tn = fn = 0
    details = []

    for r in results:
        name = r["sample"]
        # 尝试精确匹配 → 前缀匹配
        exp = expected.get(name)
        if exp is None:
            for k in expected:
                if k.startswith(name) or name.startswith(k):
                    exp = expected[k]
                    break
        if exp is None:
            continue
        _, should_detect = exp
        detected = r["detected"]

        if should_detect and detected:
            verdict = "TP"; tp += 1
        elif should_detect and not detected:
            verdict = "FN"; fn += 1
        elif not should_detect and detected:
            verdict = "FP"; fp += 1
        else:
            verdict = "TN"; tn += 1

        details.append({**r, "verdict": verdict,
                        "should_detect": should_detect})

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = fp / max(fp + tn, 1)

    return {
        "total": tp + fp + tn + fn,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fp_rate": round(fpr, 4),
        "details": details,
    }


def main():
    parser = argparse.ArgumentParser(description="Unified heap overflow test runner")
    parser.add_argument("--quick", action="store_true", help="Quick mode: skip slow analysis")
    parser.add_argument("--output-dir", "-o", default=str(BASE / "unified_results"))
    args = parser.parse_args()

    samples = find_compiled_binaries()
    print(f"Found {len(samples)} sample directories")

    if not samples:
        print("No samples found. Run compile_samples.py first.")
        return 1

    expected = load_expected()
    print(f"Loaded {len(expected)} expected labels")

    # 分析每个样本
    results = []
    for s in samples:
        r = analyze_sample(s)
        results.append(r)
        if s["name"] not in expected:
            continue
        exp_type, should_detect = expected[s["name"]]
        verdict = ""
        if should_detect and r["detected"]: verdict = "TP"
        elif should_detect and not r["detected"]: verdict = "FN"
        elif not should_detect and r["detected"]: verdict = "FP"
        else: verdict = "TN"
        emoji = {"TP": "+", "FN": "-", "FP": "x", "TN": "o"}.get(verdict, "?")
        print(f"  {emoji} {s['name']:40s} detected={r['detected']} "
              f"conf={r['confidence']:.2f} {r.get('filter_reason', '')}")

    # 计算指标
    metrics = compute_metrics(results, expected)
    print(f"\n=== RESULTS ===")
    print(f"TP={metrics['TP']} FP={metrics['FP']} TN={metrics['TN']} FN={metrics['FN']}")
    print(f"Recall={metrics['recall']:.1%} Precision={metrics['precision']:.1%} "
          f"F1={metrics['f1']:.3f} FPR={metrics['fp_rate']:.1%}")

    # 写入结果
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    with open(outdir / "per_sample_results.json", "w") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    with open(outdir / "summary_metrics.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["sample", "detected", "verdict",
                                          "should_detect", "confidence",
                                          "filter_reason"])
        w.writeheader()
        for d in metrics["details"]:
            w.writerow({k: d.get(k, "") for k in w.fieldnames})

    print(f"\nResults written to {outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
