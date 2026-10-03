"""
统一回归测试调度器 v2 — 一键运行全部四种检测类型的回归测试.
  Heap Overflow (仿射边界验证) | UAF (时序-别名-可达-路径验证+RAP) | Format String (FSCS) | Integer Overflow (I-GUARD)

用法:
  python tests/regression/run/unified_regression_runner.py
  python tests/regression/run/unified_regression_runner.py --types heap,uaf
  python tests/regression/run/unified_regression_runner.py --output results/

v2变更:
  - Ground truth: 硬编码EXPECTED字典 (提取至 ground_truth.py)
  - 检测器: tests/ 下的C源码检测器 (提取至 detectors.py)
"""

import argparse, json, os, sys, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from tests.regression.run.ground_truth import GOLD, CAT_TYPE, SAMPLE_ROOTS
from tests.regression.run.detectors import DETECTOR_MAP


# 数据结构

@dataclass
class SampleMeta:
    """样本元数据 (来自EXPECTED字典 + 文件系统)."""
    name: str = ""
    path: str = ""
    vuln_type: str = ""
    is_vulnerable: bool = False
    category: str = ""


@dataclass
class DetectionResult:
    """单个样本的检测结果."""
    sample: SampleMeta
    detected: bool = False
    scan_time_ms: float = 0.0
    details: str = ""


@dataclass
class MetricSet:
    """一组指标 (Precision/Recall/F1/FP Rate)."""
    tp: int = 0; fp: int = 0; tn: int = 0; fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d > 0 else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d > 0 else 0.0

    def to_dict(self) -> Dict:
        return {"TP": self.tp, "FP": self.fp, "TN": self.tn, "FN": self.fn,
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1": round(self.f1, 4),
                "fp_rate": round(self.fp_rate, 4)}


# 样本发现 + Ground Truth

# 未标注样本名单: 被排除出指标分母, 由调用方如实报告
EXCLUDED_UNLABELLED: List[str] = []


def _expect(name: str, category: str) -> Optional[bool]:
    """查询 gold.jsonl 正式标签; 未标注返回 None, 不得默认判为漏洞."""
    if name in GOLD:
        return bool(GOLD[name])
    return None  # legacy 逻辑曾对未标注默认 return True, 已废弃


def find_samples(vuln_types: Optional[List[str]] = None) -> List[SampleMeta]:
    """遍历样本目录, 收集所有C样本并关联 ground truth."""
    samples: List[SampleMeta] = []
    EXCLUDED_UNLABELLED.clear()
    base = _PROJECT_ROOT

    for root_rel, cat in SAMPLE_ROOTS:
        root = base / root_rel
        if not root.is_dir():
            continue
        vt = CAT_TYPE.get(cat, 'heap_overflow')
        if vuln_types and vt not in vuln_types:
            continue
        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            src = d / 'vuln.c'
            if not src.exists():
                continue
            is_vuln = _expect(d.name, cat)
            if is_vuln is None:
                # 未标注样本不得进入指标分母, legacy 曾默认判漏洞
                EXCLUDED_UNLABELLED.append(d.name)
                continue
            samples.append(SampleMeta(
                name=d.name, path=str(src),
                vuln_type=vt, is_vulnerable=is_vuln, category=cat,
            ))
    return samples


# 扫描与评估

def scan_sample(meta: SampleMeta) -> DetectionResult:
    """对单个样本运行对应类型的检测器."""
    t0 = time.time()
    try:
        with open(meta.path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()
    except Exception:
        source = ""

    detector = DETECTOR_MAP.get(meta.vuln_type, DETECTOR_MAP['heap_overflow'])
    try:
        detected, detail = detector(source)
    except Exception as e:
        detected, detail = False, f'error: {e}'

    dt = (time.time() - t0) * 1000
    return DetectionResult(sample=meta, detected=detected,
                           scan_time_ms=round(dt, 1), details=detail)


def scan_all(samples: List[SampleMeta]) -> List[DetectionResult]:
    """扫描全部样本."""
    return [scan_sample(meta) for meta in samples]


def compute_metrics(results: List[DetectionResult]):
    """从检测结果计算聚合指标和按类型指标."""
    aggregate = MetricSet()
    by_type: Dict[str, MetricSet] = {}

    for r in results:
        vt = r.sample.vuln_type
        if vt not in by_type:
            by_type[vt] = MetricSet()
        exp, det = r.sample.is_vulnerable, r.detected
        if exp and det:
            aggregate.tp += 1; by_type[vt].tp += 1
        elif exp and not det:
            aggregate.fn += 1; by_type[vt].fn += 1
        elif not exp and det:
            aggregate.fp += 1; by_type[vt].fp += 1
        else:
            aggregate.tn += 1; by_type[vt].tn += 1

    return aggregate, by_type


# 报告输出

def print_report(results: List[DetectionResult], aggregate: MetricSet,
                 by_type: Dict[str, MetricSet], total_time_s: float):
    """打印综合报告 (Markdown-friendly)."""
    print(f"\n{'='*70}")
    print(f"  BinMind Unified Regression Test Report (v2)")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total Samples: {len(results)}  |  Total Time: {total_time_s:.1f}s")
    print(f"{'='*70}")

    type_order = ['heap_overflow', 'uaf', 'format_string', 'integer_overflow']
    print(f"\n{'Type':<22} {'Samples':>7} {'P':>7} {'R':>7} {'F1':>7} {'FP Rate':>7}")
    print(f"{'-'*57}")
    for vt in type_order:
        if vt in by_type:
            m = by_type[vt]
            n = m.tp + m.fp + m.tn + m.fn
            print(f"  {vt:<20} {n:>7} {m.precision:>6.1%} {m.recall:>6.1%} {m.f1:>6.3f} {m.fp_rate:>6.1%}")

    print(f"  {'─'*55}")
    n = aggregate.tp + aggregate.fp + aggregate.tn + aggregate.fn
    print(f"  {'AGGREGATE':<20} {n:>7} {aggregate.precision:>6.1%} {aggregate.recall:>6.1%} {aggregate.f1:>6.3f} {aggregate.fp_rate:>6.1%}")
    print(f"\n  Confusion: TP={aggregate.tp} FP={aggregate.fp} TN={aggregate.tn} FN={aggregate.fn}")

    # 逐样本详情 (仅异常: FN和FP)
    anomalies = [r for r in results
                 if (r.sample.is_vulnerable and not r.detected)
                 or (not r.sample.is_vulnerable and r.detected)]
    if anomalies:
        print(f"\n  Anomalies ({len(anomalies)}):")
        print(f"  {'Sample':<35} {'Expected':>8} {'Detected':>8} {'Type'}")
        print(f"  {'-'*65}")
        for r in anomalies:
            exp = 'VULN' if r.sample.is_vulnerable else 'SAFE'
            det = 'YES' if r.detected else 'NO'
            print(f"  {r.sample.name:<33} {exp:>8} {det:>8}  {r.sample.vuln_type}")

    # 性能统计
    times = [r.scan_time_ms for r in results if r.scan_time_ms > 0]
    if times:
        avg_ms = sum(times) / len(times)
        print(f"\n  Per-sample latency: avg={avg_ms:.1f}ms min={min(times):.1f}ms max={max(times):.1f}ms")

    print(f"{'='*70}\n")


def write_results_json(results: List[DetectionResult], aggregate: MetricSet,
                       by_type: Dict[str, MetricSet], output_path: str):
    """写入JSON结果到文件."""
    per_sample = []
    for r in results:
        verdict = 'TP'
        if r.sample.is_vulnerable and not r.detected: verdict = 'FN'
        elif not r.sample.is_vulnerable and r.detected: verdict = 'FP'
        elif not r.sample.is_vulnerable and not r.detected: verdict = 'TN'
        per_sample.append({
            "name": r.sample.name, "path": r.sample.path,
            "type": r.sample.vuln_type, "category": r.sample.category,
            "is_vulnerable": r.sample.is_vulnerable,
            "detected": r.detected, "verdict": verdict,
            "scan_time_ms": r.scan_time_ms, "details": r.details,
        })

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": "v3 (gold.jsonl labels, unlabelled excluded, source-regex baseline)",
        "summary": {"total_samples": len(results),
                    "unlabelled_excluded": list(EXCLUDED_UNLABELLED),
                    "aggregate": aggregate.to_dict()},
        "by_type": {vt: m.to_dict() for vt, m in by_type.items()},
        "per_sample": per_sample,
    }
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"  JSON report -> {output_path}")


# CLI 入口

def main():
    parser = argparse.ArgumentParser(description="BinMind Unified Regression Test Runner v2")
    parser.add_argument("--types", default="", help="Comma-separated: heap,uaf,fmt,int (default: all)")
    parser.add_argument("--output", default="", help="Output JSON path")
    args = parser.parse_args()

    type_map = {'heap': 'heap_overflow', 'uaf': 'uaf', 'fmt': 'format_string', 'int': 'integer_overflow'}
    vuln_types = None
    if args.types:
        vuln_types = [type_map.get(t.strip(), t.strip()) for t in args.types.split(',')]

    samples = find_samples(vuln_types)
    if not samples:
        print("No samples found.")
        return 1

    print(f"\n  Total samples: {len(samples)} (excluded unlabelled: {len(EXCLUDED_UNLABELLED)})")
    if EXCLUDED_UNLABELLED:
        print(f"    excluded: {EXCLUDED_UNLABELLED}")
    for vt in sorted(set(s.vuln_type for s in samples)):
        count = sum(1 for s in samples if s.vuln_type == vt)
        vuln_count = sum(1 for s in samples if s.vuln_type == vt and s.is_vulnerable)
        print(f"    {vt}: {count} ({vuln_count} vulnerable, {count - vuln_count} safe)")

    t0 = time.time()
    results = scan_all(samples)
    dt = time.time() - t0

    aggregate, by_type = compute_metrics(results)
    print_report(results, aggregate, by_type, dt)

    default_output = str(_PROJECT_ROOT / 'tests' / 'regression' / 'results' / 'unified_regression.json')
    write_results_json(results, aggregate, by_type, args.output or default_output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
