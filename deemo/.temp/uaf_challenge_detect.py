"""UAF挑战样本检测 — 跑TemporalPathVerifier和HOIG Pipeline对15个新样本."""

from __future__ import annotations
import json
import os
import sys
import re

# 项目路径
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from analysis.uaf_temporal_path_verifier import TemporalPathVerifier
from analysis.uaf_hoig_pipeline import UafHoigPipeline

SAMPLE_DIR = os.path.join(ROOT, 'tests', 'cve_samples', 'uaf')

# 15个挑战样本定义
CHALLENGE_SAMPLES = {
    'uaf_16': {'file': 'uaf_16_factory_return_freed.c', 'expected': 'TP',
               'category': 'factory_return_freed'},
    'uaf_17': {'file': 'uaf_17_deep_alias_chain.c', 'expected': 'TP',
               'category': 'deep_alias_chain'},
    'uaf_18': {'file': 'uaf_18_cond_free_guard_use.c', 'expected': 'TN',
               'category': 'cond_free_guard_use'},
    'uaf_19': {'file': 'uaf_19_cross_cond_free.c', 'expected': 'TP',
               'category': 'cross_cond_free'},
    'uaf_20': {'file': 'uaf_20_switch_case.c', 'expected': 'TP',
               'category': 'switch_case'},
    'uaf_21': {'file': 'uaf_21_goto_cleanup.c', 'expected': 'TP',
               'category': 'goto_cleanup'},
    'uaf_22': {'file': 'uaf_22_struct_field_alias.c', 'expected': 'TP',
               'category': 'struct_field_alias'},
    'uaf_23': {'file': 'uaf_23_realloc_null_oldptr.c', 'expected': 'TP',
               'category': 'realloc_null_oldptr'},
    'uaf_24': {'file': 'uaf_24_double_free_alias.c', 'expected': 'TP',
               'category': 'double_free_alias'},
    'uaf_25': {'file': 'uaf_25_reassign_safe.c', 'expected': 'TN',
               'category': 'reassign_safe'},
    'uaf_26': {'file': 'uaf_26_deep_call_chain.c', 'expected': 'TP',
               'category': 'deep_call_chain'},
    'uaf_27': {'file': 'uaf_27_same_name_diff_obj.c', 'expected': 'TN',
               'category': 'same_name_diff_obj'},
    'uaf_28': {'file': 'uaf_28_nested_cond_free.c', 'expected': 'TP',
               'category': 'nested_cond_free'},
    'uaf_29': {'file': 'uaf_29_dead_branch_safe.c', 'expected': 'TN',
               'category': 'dead_branch_safe'},
    'uaf_30': {'file': 'uaf_30_callback_dtor.c', 'expected': 'TP',
               'category': 'callback_dtor'},
}


def load_source(sample_dir: str, filename: str) -> str:
    path = os.path.join(SAMPLE_DIR, sample_dir, filename)
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def verdict_to_str(results):
    """将TemporalPathVerifier结果转为判定字符串."""
    if not results:
        return 'SAFE'
    for r in results:
        v = r.verdict.value if hasattr(r.verdict, 'value') else str(r.verdict)
        if v in ('UAF', 'DOUBLE_FREE'):
            return 'UAF'
    has_uncertain = any(
        (r.verdict.value if hasattr(r.verdict, 'value') else str(r.verdict)) == 'UNCERTAIN'
        for r in results)
    if has_uncertain:
        return 'UNCERTAIN'
    return 'SAFE'


def extract_func_bodies(source: str):
    """从C源码提取所有函数体和调用关系(HOIG管线用)."""
    # 简单提取: 匹配 void/char*/int func_name(...) { ... }
    func_pattern = re.compile(
        r'(?:void|char\s*\*|int|struct\s+\w+\s*\*)\s*(\w+)\s*\([^)]*\)\s*\{',
        re.MULTILINE)
    bodies = {}
    calls = []
    for m in func_pattern.finditer(source):
        fname = m.group(1)
        start = m.end()
        # 找匹配的花括号
        depth = 1
        pos = start
        while pos < len(source) and depth > 0:
            if source[pos] == '{':
                depth += 1
            elif source[pos] == '}':
                depth -= 1
            pos += 1
        bodies[fname] = source[m.start():pos]
    # 推断调用关系: 简单正则
    for fname, body in bodies.items():
        for other in bodies:
            if other != fname:
                if re.search(rf'\b{other}\s*\(', body):
                    calls.append((fname, other))
    return bodies, calls


def main():
    tpv = TemporalPathVerifier()
    tp, fp, tn, fn = 0, 0, 0, 0
    results_list = []

    for name, info in CHALLENGE_SAMPLES.items():
        source = load_source(name, info['file'])
        expected = info['expected']
        category = info['category']

        # Temporal Path Verifier
        tpv_results = tpv.verify(source)
        tpv_verdict = verdict_to_str(tpv_results)
        tpv_detected = tpv_verdict in ('UAF', 'DOUBLE_FREE')

        # HOIG Pipeline (每次创建新实例避免状态累积)
        hoig = UafHoigPipeline()
        func_bodies, calls = extract_func_bodies(source)
        main_func = list(func_bodies.keys())
        hoig_code = '\n'.join(func_bodies.values())
        hoig_result = hoig.analyze(
            hoig_code,
            func_name=main_func[0] if main_func else 'main',
            func_bodies=func_bodies if len(func_bodies) > 1 else None,
            calls=calls if calls else None,
        )
        hoig_verdict = hoig_result['verdict']
        hoig_detected = hoig_verdict == 'CONFIRMED'

        # 综合: 任一检测到UAF则判为UAF
        detected = tpv_detected or hoig_detected
        is_tp = expected == 'TP'
        if is_tp and detected:
            outcome = 'TP'
            tp += 1
        elif is_tp and not detected:
            outcome = 'FN'
            fn += 1
        elif not is_tp and detected:
            outcome = 'FP'
            fp += 1
        else:
            outcome = 'TN'
            tn += 1

        results_list.append({
            'sample': name,
            'category': category,
            'expected': expected,
            'tpv_verdict': tpv_verdict,
            'hoig_verdict': hoig_verdict,
            'outcome': outcome,
        })

    # 输出
    total = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("=" * 70)
    print("UAF挑战样本检测结果 (15个新样本)")
    print("=" * 70)
    for r in results_list:
        mark = "OK" if r['outcome'] in ('TP', 'TN') else r['outcome']
        print(f"  {r['sample']:10s} | exp={r['expected']:2s} | "
              f"TPV={r['tpv_verdict']:10s} | HOIG={r['hoig_verdict']:10s} | "
              f"{mark}")
    print("-" * 70)
    print(f"TP={tp} FP={fp} TN={tn} FN={fn} | "
          f"P={prec:.3f} R={recall:.3f} F1={f1:.3f} FPR={fpr:.3f}")
    print("=" * 70)

    # 标记FN/FP样本
    fn_samples = [r for r in results_list if r['outcome'] == 'FN']
    fp_samples = [r for r in results_list if r['outcome'] == 'FP']
    if fn_samples:
        print("\n漏报(FN)样本:")
        for r in fn_samples:
            print(f"  - {r['sample']} ({r['category']})")
    if fp_samples:
        print("\n误报(FP)样本:")
        for r in fp_samples:
            print(f"  - {r['sample']} ({r['category']})")

    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': prec, 'recall': recall, 'f1': f1, 'fpr': fpr}


if __name__ == '__main__':
    main()
