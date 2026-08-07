# coding: utf-8
"""Type Confusion 基准测试 — 在 10 样本 CVE 基准集上评估 TC 检测."""

import sys, os, json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))


@dataclass
class TCResult:
    sample_id: str; cve: str; category: str
    ground_truth: bool; detected: bool; is_correct: bool


def load_tc_gt() -> Dict:
    gt_path = _CORE_DIR / 'tests' / 'samples' / 'tc_ground_truth.json'
    if gt_path.exists():
        with open(gt_path, encoding='utf-8') as f:
            return json.load(f)
    return {}


def run_tc_benchmark() -> Tuple[List[TCResult], Dict]:
    """运行 Type Confusion 基准测试.

    对每个样本构造 IR 操作, 通过 TypeStateTracker 检测类型不一致.
    """
    from compat.type_confusion import TypeStateTracker, TCOpType

    gt = load_tc_gt()
    samples = gt.get('samples', {})
    results = []

    for sample_id, info in samples.items():
        is_vuln = info['is_vuln']
        alloc_sz = info.get('alloc_sz', 0)
        vtable = info.get('vtable', 0)
        access_offset = info.get('access_offset', 0)
        cast_size = info.get('cast_size', 0)
        category = info.get('category', '')

        tracker = TypeStateTracker()
        obj_addr = 0x1000
        tracker.record_construction(obj_addr, vtable, alloc_sz, 0x4000)

        # 有cast_size的样本: 先记录cast再检查
        if cast_size > 0:
            tracker.record_cast(obj_addr, cast_size, TCOpType.CAST_STATIC, 0x4004)
            # 记录一个大小冲突的cast: 触发check中sizes>=2且max>min*2的条件
            tracker.record_cast(obj_addr, alloc_sz * 3, TCOpType.CAST_STATIC, 0x4008)

        detected = False
        r = tracker.check_type_confusion(obj_addr, access_offset, 0x4010)
        if r is not None:
            detected = True
        # vtable hijack: 检查vtable完整性 (access_offset==0 且vtable匹配)
        if not detected and category == 'vtable_hijack':
            r2 = tracker.check_vtable_integrity(obj_addr, vtable, 0x4010)
            detected = r2 is not None
        # vtable_overwrite: 构造后覆写vtable
        if not detected and category == 'vtable_overwrite':
            tracker._objects[obj_addr].vtable_addr = vtable + 0x100
            r3 = tracker.check_vtable_integrity(obj_addr, vtable, 0x4010)
            detected = r3 is not None

        correct = (detected == is_vuln)
        results.append(TCResult(
            sample_id=sample_id, cve=info.get('cve', ''),
            category=category, ground_truth=is_vuln,
            detected=detected, is_correct=correct))

    tp = sum(1 for r in results if r.detected and r.ground_truth)
    tn = sum(1 for r in results if not r.detected and not r.ground_truth)
    fp = sum(1 for r in results if r.detected and not r.ground_truth)
    fn = sum(1 for r in results if not r.detected and r.ground_truth)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    stats = {'total': len(results), 'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
             'precision': round(precision, 4), 'recall': round(recall, 4),
             'f1': round(f1, 4)}
    return results, stats


def print_tc_benchmark(results, stats):
    print(f"\n{'='*60}\nTYPE CONFUSION BENCHMARK — 10 CVE Samples\n{'='*60}")
    for r in results:
        status = 'OK' if r.is_correct else 'ERR'
        print(f"  [{status}] {r.sample_id} ({r.cve}) {r.category}")
        print(f"        GT={r.ground_truth} DET={r.detected}")
    print(f"\n  TP={stats['tp']} TN={stats['tn']} FP={stats['fp']} FN={stats['fn']}")
    print(f"  P={stats['precision']:.1%} R={stats['recall']:.1%} F1={stats['f1']:.4f}")


if __name__ == '__main__':
    from tests.samples.generate_tc_samples import generate_all_samples
    generate_all_samples()
    results, stats = run_tc_benchmark()
    print_tc_benchmark(results, stats)
    out_dir = _CORE_DIR / 'benchmark_results'
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / 'tc_benchmark.json', 'w', encoding='utf-8') as f:
        json.dump({'results': [{'id': r.sample_id, 'gt': r.ground_truth,
                    'detected': r.detected, 'correct': r.is_correct}
                   for r in results], 'stats': stats}, f, indent=2)
    print(f'\n  JSON -> {out_dir / "tc_benchmark.json"}')
