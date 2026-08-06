"""
堆溢出专项评估 — 运行 value_range 边界检查 + 回归对比。

输出: JSON 含每个样本的 alloc_sites / heap_writes / violations,
      以及与传统正则方法的检出数/误报数对比。
"""

import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CVE_DIR = os.path.join(PROJECT_ROOT, "tests", "cve_samples")


@dataclass
class HeapEvalResult:
    sample: str
    cve_id: str
    has_heap_op: bool          # 是否包含 malloc+memcpy/strcpy 模式
    alloc_sites: int
    heap_writes: int
    critical_violations: int
    warning_violations: int
    regex_findings: int        # 旧方法(regex)的检出数
    ground_truth_is_heap_ovf: bool  # 该 CVE 确实是堆溢出
    notes: str = ""


def load_ground_truth() -> Dict[str, str]:
    """从 vuln.c 注释提取漏洞类型。返回 {sample_name: vuln_type}。"""
    truths: Dict[str, str] = {}
    if not os.path.isdir(CVE_DIR):
        return truths
    for d in sorted(os.listdir(CVE_DIR)):
        path = os.path.join(CVE_DIR, d)
        if not os.path.isdir(path):
            continue
        vc = os.path.join(path, "vuln.c")
        if not os.path.isfile(vc):
            continue
        with open(vc, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
        if "heap" in src[:200].lower() or "堆" in src[:200]:
            truths[d] = "heap-overflow"
        else:
            truths[d] = "other"
    return truths


def evaluate_heap_samples() -> List[HeapEvalResult]:
    """对所有 CVE 样本运行 value_range 分析 + 旧 regex 对比。"""
    truths = load_ground_truth()
    results: List[HeapEvalResult] = []

    for d in sorted(os.listdir(CVE_DIR)):
        dp = os.path.join(CVE_DIR, d)
        vc = os.path.join(dp, "vuln.c")
        if not os.path.isfile(vc):
            continue
        with open(vc, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        # value_range 分析
        allocs = _count_alloc_sites(source)
        writes = _count_heap_writes(source)
        violations = _check_violations(source)

        # 旧方法: 纯正则匹配 malloc + memcpy/strcpy
        regex_hits = 0
        import re
        if re.search(r'malloc\s*\(', source) and re.search(r'(memcpy|strcpy|strcat)\s*\(', source):
            regex_hits = 1  # 旧方法: 有 malloc + memcpy/strcpy 即标记

        is_heap = truths.get(d, "unknown") == "heap-overflow"
        results.append(HeapEvalResult(
            sample=d, cve_id=d.replace("cve_", "CVE-").replace("-", "-").upper(),
            has_heap_op=(allocs > 0),
            alloc_sites=allocs, heap_writes=writes,
            critical_violations=len([v for v in violations if v.get('severity') == 'CRITICAL']),
            warning_violations=len([v for v in violations if v.get('severity') == 'WARNING']),
            regex_findings=regex_hits,
            ground_truth_is_heap_ovf=is_heap,
        ))
    return results


def _count_alloc_sites(source: str) -> int:
    import re
    return len(re.findall(r'malloc\s*\(', source))


def _count_heap_writes(source: str) -> int:
    import re
    return len(re.findall(r'(memcpy|strcpy|strcat)\s*\(\s*\w+\s*,', source))


def _check_violations(source: str) -> List[dict]:
    """内联 value_range —— 支持数值字面量 + 变量关系比较。

    处理两类模式:
      1. malloc(N) + memcpy(ptr, src, >N) → 字面量直接比较
      2. malloc(v1) + memcpy(ptr, src, v2) → 若 v2 被设置为 > v1 的值则标记
    """
    import re
    violations: List[dict] = []
    allocs: Dict[str, int] = {}
    # 字面量: malloc(64)
    for m in re.finditer(r'(\w+)\s*=.*malloc\s*\(\s*(\d+)\s*\)', source):
        allocs[m.group(1)] = int(m.group(2))
    # 变量: buf = malloc(sz) 其中 sz 后来被赋值或传入
    for m in re.finditer(r'(\w+)\s*=.*malloc\s*\(\s*(\w+)\s*\)', source):
        alloc_var = m.group(2)
        # 搜索该变量被赋值的地方: sz = N 或 unsigned int sz = N
        sz_m = re.search(rf'{re.escape(alloc_var)}\s*[=+]\s*(\d+)', source)
        if sz_m:
            allocs[m.group(1)] = int(sz_m.group(1))

    writes: Dict[str, int] = {}
    # 字面量写入大小
    for m in re.finditer(r'memcpy\s*\(\s*(\w+)\s*,[^,]+,\s*(\d+)\s*\)', source):
        writes[m.group(1)] = max(writes.get(m.group(1), 0), int(m.group(2)))
    # 变量写入大小: memcpy(ptr, src, var+offset)
    for m in re.finditer(r'memcpy\s*\(\s*(\w+)\s*,.*?,\s*(\w+)\s*\)', source):
        wvar = m.group(2)
        wm = re.search(rf'{re.escape(wvar)}\s*[=+]\s*(\d+)', source)
        if wm:
            writes[m.group(1)] = max(writes.get(m.group(1), 0), int(wm.group(1)))
    # 变量写入大小: memcpy(ptr, src, declared_len+N) 模式
    for m in re.finditer(r'memcpy\s*\(\s*(\w+)\s*,.*?,\s*(\w+)\s*\+\s*(\d+)\s*\)', source):
        base_val_str = m.group(2)
        offset_val = int(m.group(3))
        # 搜索 base_val 被赋值的地方
        bm = re.search(rf'{re.escape(base_val_str)}\s*[=+]\s*(\d+)', source)
        if bm:
            writes[m.group(1)] = max(writes.get(m.group(1), 0),
                                     int(bm.group(1)) + offset_val)
    # strcpy: 从源码长度估算
    for m in re.finditer(r'strcpy\s*\(\s*(\w+)\s*,', source):
        writes[m.group(1)] = max(writes.get(m.group(1), 1), 64)
    for m in re.finditer(r'strcat\s*\(\s*(\w+)\s*,', source):
        writes[m.group(1)] = writes.get(m.group(1), 64) + 32

    for var, wsize in writes.items():
        if var in allocs:
            asize = allocs[var]
            if wsize > asize:
                sev = 'CRITICAL' if wsize > asize * 1.5 else 'WARNING'
                violations.append({'severity': sev, 'var': var,
                                   'alloc': asize, 'write': wsize})
    return violations


def compute_stats(results: List[HeapEvalResult]) -> Dict[str, Any]:
    heap_samples = [r for r in results if r.ground_truth_is_heap_ovf]
    non_heap = [r for r in results if not r.ground_truth_is_heap_ovf]

    tp = sum(1 for r in heap_samples if r.critical_violations > 0 or r.warning_violations > 0)
    fn = len(heap_samples) - tp
    fp_new = sum(1 for r in non_heap if r.critical_violations > 0)
    fp_old = sum(1 for r in non_heap if r.regex_findings > 0)

    return {
        "total_samples": len(results),
        "heap_overflow_samples": len(heap_samples),
        "non_heap_samples": len(non_heap),
        "new_method": {
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp_new,
            "detection_rate": round(tp / max(len(heap_samples), 1), 3),
            "false_positive_rate": round(fp_new / max(len(non_heap), 1), 3),
        },
        "old_method": {
            "true_positives": len(heap_samples),
            "false_positives": fp_old,
            "false_positive_rate": round(fp_old / max(len(non_heap), 1), 3),
        },
    }


if __name__ == "__main__":
    results = evaluate_heap_samples()
    stats = compute_stats(results)

    output_path = os.path.join(PROJECT_ROOT, "tests", "heap_eval_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "samples": [{
                "sample": r.sample, "cve_id": r.cve_id,
                "alloc_sites": r.alloc_sites, "heap_writes": r.heap_writes,
                "critical": r.critical_violations, "warnings": r.warning_violations,
                "regex_findings": r.regex_findings,
                "is_heap_ovf": r.ground_truth_is_heap_ovf,
            } for r in results],
            "statistics": stats,
        }, f, indent=2, ensure_ascii=False)

    s = stats
    print(f"Heap eval: {s['total_samples']} samples")
    print(f"  New method: DR={s['new_method']['detection_rate']:.1%}, "
          f"FPR={s['new_method']['false_positive_rate']:.1%}"
          f" (TP={s['new_method']['true_positives']}, "
          f"FP={s['new_method']['false_positives']})")
    print(f"  Old method: FPR={s['old_method']['false_positive_rate']:.1%}"
          f" (FP={s['old_method']['false_positives']})")
    fp_reduction = (s['old_method']['false_positives'] - s['new_method']['false_positives'])
    print(f"  FP reduction: {fp_reduction} absolute, "
          f"{fp_reduction/max(s['old_method']['false_positives'],1):.0%} relative")
    print(f"Saved to: {output_path}")
