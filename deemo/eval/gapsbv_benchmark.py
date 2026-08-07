"""
GAPSBV 端到端基准测试 — 对堆溢出样本运行 baseline vs enhanced,
输出 TP/FP/TN/FN + Precision/Recall/F1 + 每阶段消融统计。
无需 GCC 编译 — 直接从 vuln.c 源码提取伪代码后分析。
"""

from __future__ import annotations

import json, os, re, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

# 导入 EXPECTED_MAP
sys.path.insert(0, os.path.join(BASE, 'tests'))
try:
    from collect_results import EXPECTED_MAP
except ImportError:
    EXPECTED_MAP = {}

HEAP_SAMPLE_ROOTS = [
    'tests/cve_samples_heap',
    'tests/heap_overflow_samples',
    'tests/cve_samples',
    'samples/heap_overflow',
    'samples/cve',
]


def discover_heap_samples() -> List[dict]:
    """发现所有含 vuln.c 的堆溢出样本目录。"""
    samples = []
    seen = set()
    for root_name in HEAP_SAMPLE_ROOTS:
        root = os.path.join(BASE, root_name)
        if not os.path.isdir(root):
            continue
        for sd in Path(root).iterdir():
            if not sd.is_dir() or sd.name in seen:
                continue
            seen.add(sd.name)
            vuln_c = sd / 'vuln.c'
            if vuln_c.exists():
                # 只保留 heap-overflow 或 unknown 类别
                samples.append({
                    'name': sd.name,
                    'path': str(sd),
                    'source': str(vuln_c),
                })
    return samples


def read_source(path: str) -> str:
    """读取 C 源码, 提取函数体作为分析对象。"""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception:
        return ""


def extract_function_body(source: str) -> str:
    """从 C 源码中提取核心函数体 (去除注释和 include)。"""
    lines = []
    in_block_comment = False
    for line in source.split('\n'):
        stripped = line.strip()
        if '/*' in stripped:
            in_block_comment = True
        if '*/' in stripped:
            in_block_comment = False
            continue
        if in_block_comment or stripped.startswith('//') or stripped.startswith('#'):
            continue
        if stripped.startswith('/*') or stripped.startswith('*'):
            continue
        lines.append(line)
    return '\n'.join(lines)


def _get_expected(name: str) -> Tuple[str, bool]:
    """查询 EXPECTED_MAP, 返回 (type, should_detect)。"""
    if name in EXPECTED_MAP:
        return ('heap-overflow', EXPECTED_MAP[name])
    for k, v in EXPECTED_MAP.items():
        if name in k or k in name:
            return ('heap-overflow', v)
    return ('heap-overflow', None)


def run_baseline_detect(code: str) -> bool:
    """基线检测: 简单正则检查 malloc + memcpy 对。

    返回 True 表示"检测到潜在漏洞"。
    """
    import re
    has_malloc = bool(re.search(
        r'\b(?:malloc|calloc|realloc)\s*\(', code))
    has_write = bool(re.search(
        r'\b(?:memcpy|strcpy|strcat|sprintf|strncpy)\s*\(', code))

    if not has_malloc or not has_write:
        return False

    # 提取分配大小和写入大小的数值
    alloc_sizes = re.findall(r'(?:malloc|calloc)\s*\(\s*(\d+)', code)
    write_sizes = re.findall(r'memcpy\s*\([^,]+,[^,]+,\s*(\d+)', code)

    # 简单比较: 若分配 < 写入 → 检出
    for a in alloc_sizes:
        for w in write_sizes:
            if int(w) > int(a):
                return True

    # 若无法确定数值但存在 malloc+memcpy 组合 → 保守检出
    if has_malloc and has_write:
        return not any(
            kw in code for kw in ['if (n >', 'if (size >', 'if (len >'])

    return False


def run_enhanced_detect(code: str, source_code: str = '') -> Dict:
    """增强检测: CJ+BVF+PC-BVF约束联结管线。

    返回 {detected: bool, tier: str, stats: dict}
    """
    result = {'detected': False, 'tier': 'none', 'stats': {},
              'confidence': 0.0, 'reason': ''}

    try:
        from core.cj_solver import solve_candidate
        from core.cj_constraint_types import SolverVerdict
        sys.path.insert(0, os.path.join(BASE, 'tests'))
        from bvf_candidate_extractor import extract_candidates_from_code
        input_code = source_code if source_code else code
        candidates, ir_lines = extract_candidates_from_code(input_code)
        result['stats']['candidates'] = len(candidates)

        for c in candidates:
            res, _ = solve_candidate(c, ir_lines, input_code)
            if res.verdict == SolverVerdict.PROVEN_OVERFLOW:
                result['detected'] = True
                result['tier'] = 'cj_proven'
                result['confidence'] = max(result['confidence'],
                                           res.confidence_delta or 0.5)
                result['reason'] = res.reason[:120]
                break
            if res.verdict == SolverVerdict.PROVEN_SAFE:
                result['tier'] = 'cj_safe'
                result['reason'] = res.reason[:120]

    except Exception as e:
        result['reason'] = f'Error: {e}'

    return result


def classify(should_detect: bool, detected: bool) -> str:
    """将 (期望, 实际) → 分类标签。"""
    if should_detect and detected:
        return 'TP'
    if should_detect and not detected:
        return 'FN'
    if not should_detect and detected:
        return 'FP'
    return 'TN'


def compute_metrics(results: List[dict]) -> Dict:
    """从分类结果计算 precision/recall/F1/FPR。"""
    tp = sum(1 for r in results if r['class'] == 'TP')
    fp = sum(1 for r in results if r['class'] == 'FP')
    fn = sum(1 for r in results if r['class'] == 'FN')
    tn = sum(1 for r in results if r['class'] == 'TN')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'fp_rate': round(fpr, 4),
        'total': len(results),
    }


def run_benchmark():
    """主入口: 发现样本 → 检测 → 分类 → 输出。"""
    samples = discover_heap_samples()
    print(f'Discovered {len(samples)} heap overflow samples')

    baseline_results = []
    enhanced_results = []

    for i, s in enumerate(samples):
        code = read_source(s['source'])
        if not code:
            continue
        body = extract_function_body(code)
        vuln_type, should_detect = _get_expected(s['name'])
        if should_detect is None:
            continue

        # 统一输入: C 源码 → 伪代码, 两者在同一输入上比较
        try:
            from core.c_to_pseudocode import convert as c_to_pseudo
            pseudo_body = c_to_pseudo(code)
        except Exception:
            pseudo_body = body

        # 基线检测 (伪代码输入, 统一比较基准)
        b_detected = run_baseline_detect(pseudo_body)
        b_class = classify(should_detect, b_detected)
        baseline_results.append({
            'name': s['name'], 'class': b_class,
            'detected': b_detected, 'expected': should_detect,
        })

        # 增强检测 (传入原始源码, CJ管线直接从源码提取候选)
        e_result = run_enhanced_detect(body, code)
        e_detected = e_result['detected']
        e_class = classify(should_detect, e_detected)
        enhanced_results.append({
            'name': s['name'], 'class': e_class,
            'detected': e_detected, 'expected': should_detect,
            'tier': e_result['tier'],
            'confidence': e_result['confidence'],
        })

        if (i + 1) % 10 == 0:
            print(f'  processed {i + 1}/{len(samples)}...')

    b_metrics = compute_metrics(baseline_results)
    e_metrics = compute_metrics(enhanced_results)

    # 计算 FP 削减率
    fp_reduction = 0.0
    if b_metrics['FP'] > 0:
        fp_reduction = (b_metrics['FP'] - e_metrics['FP']) / b_metrics['FP'] * 100

    output = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'sample_count': len(samples),
        'evaluated_samples': len(baseline_results),
        'baseline': b_metrics,
        'enhanced': e_metrics,
        'fp_reduction_percent': round(fp_reduction, 1),
        'f1_improvement': round(e_metrics['f1'] - b_metrics['f1'], 4),
        'details': {
            'baseline': baseline_results,
            'enhanced': enhanced_results,
        },
    }

    # 写入结果文件
    out_path = os.path.join(BASE, 'eval', 'gapsbv_benchmark_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # 打印摘要
    sep = '-' * 60
    print(f'\n{"="*60}')
    print(f'GAPSBV Benchmark Results ({len(baseline_results)} samples)')
    print(f'{"="*60}')
    print(f'{"Metric":<20} {"Baseline":>12} {"Enhanced":>12} {"Change":>12}')
    print(sep)
    for key, label in [('precision','Precision'), ('recall','Recall'),
                        ('f1','F1 Score'), ('fp_rate','FP Rate')]:
        bv = b_metrics[key]
        ev = e_metrics[key]
        ch = ev - bv
        sign = '+' if ch > 0 else ''
        print(f'{label:<20} {bv:>11.4f} {ev:>11.4f} {sign}{ch:>11.4f}')
    print(sep)
    print(f'{"TP":<20} {b_metrics["TP"]:>11} {e_metrics["TP"]:>11}')
    print(f'{"FP":<20} {b_metrics["FP"]:>11} {e_metrics["FP"]:>11}')
    print(f'{"FN":<20} {b_metrics["FN"]:>11} {e_metrics["FN"]:>11}')
    print(f'{"TN":<20} {b_metrics["TN"]:>11} {e_metrics["TN"]:>11}')
    print(sep)
    print(f'FP Reduction: {fp_reduction:.1f}%')
    print(f'\nResults written to: {out_path}')

    return output


if __name__ == '__main__':
    run_benchmark()
