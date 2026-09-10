# 消融评估 — 基线 vs 写侧区间创新 的召回/误报对比
"""测量写侧双向区间交汇+循环写检测相对基线的指标变化。

输出:
  tests/scan_results/ablation_heap.json
  tests/scan_results/ablation_heap.csv

指标定义:
  recall       = 检出TP样本数 / 堆溢出TP样本总数
  fp_rate      = FP告警数 / 总告警数
  precision    = TP告警 / (TP告警 + FP告警)
  fn_count     = 未检出的TP样本数

用法: python tests/run_ablation.py [--out DIR]
"""

import os, sys, json, argparse, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

# 堆溢出正样本(ground truth): TP001-TP016 + 含真实malloc结构的CVE堆溢出
# 排除无malloc的样本(heartbleed栈读, dirty_pipe/tcp_sack内核结构, wget/tcp_mss)
HEAP_TP_SAMPLES = [
    'CVE-2025-TP001_tainted_heap_overflow',
    'CVE-2025-TP002_unbounded_heap_overflow',
    'CVE-2025-TP003_loop_bound',
    'CVE-2025-TP004_off_by_one',
    'CVE-2025-TP005_calc_error',
    'CVE-2025-TP006_direct_taint',
    'CVE-2025-TP007_cross_func_alloc',
    'CVE-2025-TP008_mul_size',
    'CVE-2025-TP009_indirect_taint',
    'CVE-2025-TP010_loop_write',
    'CVE-2025-TP011_call_ret_size',
    'CVE-2025-TP012_realloc_expand',
    'CVE-2025-TP013_struct_field',
    'CVE-2025-TP014_array_idx',
    'CVE-2025-TP015_chained_arith',
    'CVE-2025-TP016_strlen_offby',
    'CVE-2015-0235_ghost_heap_overflow',
    'CVE-2016-10191_heap_overflow',
    'CVE-2018-1000001_glibc_realpath_heap_overflow',
    'CVE-2021-3156_sudo_heap_overflow',
    'CVE-2023-27997_fortigate_heap_overflow',
    'CVE-2024-21626_runc_heap_overflow',
]

# 安全样本(ground truth): 不应被报为漏洞
HEAP_FP_SAMPLES = [
    'CVE-2025-FP001_constant_malloc_safe',
    'CVE-2025-FP002_guarded_malloc_safe',
    'CVE-2025-FP003_alignment_safe',
    'CVE-2025-FP004_and_mask_guard',
    'CVE-2025-FP005_loop_bound_safe',
    'CVE-2025-FP006_minsize_guard',
    'CVE-2025-FP007_cross_call_valid',
    'CVE-2025-FP008_cmova_capped',
]


def scan_one(binary_path: str, sample_name: str,
             enable_write_side: bool) -> dict:
    """对单个binary运行detector, 返回结构化结果。"""
    import subprocess
    from src.heap_overflow_detector import HeapOverflowDetector
    from src.asm_normalize import normalize_asm_lines

    t0 = time.time()
    result = {'sample': sample_name, 'detected': False,
              'tp': 0, 'fp': 0, 'filtered': 0, 'time': 0.0, 'error': None}
    try:
        r = subprocess.run(['objdump', '-d', '-M', 'intel', binary_path],
                           capture_output=True, text=True, timeout=30)
        lines = normalize_asm_lines(r.stdout.split('\n'))
        det = HeapOverflowDetector(enable_write_side=enable_write_side)
        rep = det.detect(lines, sample_name)
        result['detected'] = rep.true_positives > 0
        result['tp'] = rep.true_positives
        result['filtered'] = rep.false_positives
        # fp: 安全样本被误报为漏洞 → 1
        result['fp'] = 1 if (result['detected']
                             and sample_name not in HEAP_TP_SAMPLES) else 0
        result['uncertain'] = rep.uncertain
    except Exception as e:
        result['error'] = str(e)[:120]
    result['time'] = round(time.time() - t0, 2)
    return result


def find_binary(sample_dir: str):
    for name in ('vuln_debug', 'vuln_debug.exe', 'vuln_release'):
        p = os.path.join(sample_dir, name)
        if os.path.isfile(p):
            return p
    return None


def run(sample_root: str) -> dict:
    """运行基线与创新两组扫描, 计算指标。"""
    baseline = {'detected_samples': 0, 'tp_alerts': 0, 'fp_alerts': 0,
                'fn_samples': 0, 'fp_samples_alarm': 0,
                'filtered_alerts': 0}
    enhanced = {'detected_samples': 0, 'tp_alerts': 0, 'fp_alerts': 0,
                'fn_samples': 0, 'fp_samples_alarm': 0,
                'filtered_alerts': 0}
    details = {'baseline': [], 'enhanced': []}

    tp_expected = HEAP_TP_SAMPLES
    fp_expected = HEAP_FP_SAMPLES

    for name in tp_expected:
        d = os.path.join(sample_root, name)
        if not os.path.isdir(d):
            continue
        b = find_binary(d)
        if not b:
            continue
        for tag, enable, agg, dets in [
                ('baseline', False, baseline, details['baseline']),
                ('enhanced', True, enhanced, details['enhanced'])]:
            r = scan_one(b, name, enable)
            rec = {'sample': name, 'detected': r['detected'],
                   'tp': r['tp'], 'fp': r['fp'], 'time': r['time']}
            dets.append(rec)
            if r['detected']:
                agg['detected_samples'] += 1
                agg['tp_alerts'] += r['tp']
            else:
                agg['fn_samples'] += 1
            # filtered = detector内部过滤数(非误报), 作辅助指标
            agg['filtered_alerts'] += r.get('filtered', 0)

    for name in fp_expected:
        d = os.path.join(sample_root, name)
        if not os.path.isdir(d):
            continue
        b = find_binary(d)
        if not b:
            continue
        for tag, enable, agg, dets in [
                ('baseline', False, baseline, details['baseline']),
                ('enhanced', True, enhanced, details['enhanced'])]:
            r = scan_one(b, name, enable)
            dets.append({'sample': name, 'detected': r['detected'],
                         'tp': r['tp'], 'fp': r['fp'], 'time': r['time']})
            if r['detected']:
                agg['fp_samples_alarm'] += 1
                agg['fp_alerts'] += 1

    total_tp = sum(1 for n in tp_expected
                   if os.path.isdir(os.path.join(sample_root, n))
                   and find_binary(os.path.join(sample_root, n)))
    total_fp = sum(1 for n in fp_expected
                   if os.path.isdir(os.path.join(sample_root, n))
                   and find_binary(os.path.join(sample_root, n)))

    def metrics(agg, n_tp, n_fp):
        recall = agg['detected_samples'] / n_tp * 100 if n_tp else 0
        # 误报率 = 安全样本被误报为漏洞的比例
        fp_rate = agg['fp_alerts'] / n_fp * 100 if n_fp else 0
        precision = (agg['tp_alerts'] / (agg['tp_alerts'] + agg['fp_alerts'])
                     * 100 if (agg['tp_alerts'] + agg['fp_alerts']) else 0)
        fp_sample_rate = agg['fp_samples_alarm'] / n_fp * 100 if n_fp else 0
        return {
            'recall_pct': round(recall, 1),
            'fp_rate_pct': round(fp_rate, 1),
            'precision_pct': round(precision, 1),
            'fp_sample_rate_pct': round(fp_sample_rate, 1),
            'detected_samples': agg['detected_samples'],
            'tp_alerts': agg['tp_alerts'],
            'fp_alerts': agg['fp_alerts'],
            'fn_samples': agg['fn_samples'],
            'filtered_alerts': agg['filtered_alerts'],
        }

    return {
        'total_tp_expected': total_tp,
        'total_fp_expected': total_fp,
        'baseline': metrics(baseline, total_tp, total_fp),
        'enhanced': metrics(enhanced, total_tp, total_fp),
        'details': details,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', default='tests/scan_results')
    args = p.parse_args()

    sample_root = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'cve_samples')
    result = run(sample_root)
    os.makedirs(args.out, exist_ok=True)

    json_path = os.path.join(args.out, 'ablation_heap.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    csv_path = os.path.join(args.out, 'ablation_heap.csv')
    with open(csv_path, 'w', encoding='utf-8', newline='') as f:
        import csv
        w = csv.writer(f)
        w.writerow(['sample', 'variant', 'detected', 'tp', 'fp', 'time'])
        for variant in ('baseline', 'enhanced'):
            for r in result['details'][variant]:
                w.writerow([r['sample'], variant, r['detected'],
                            r['tp'], r['fp'], r['time']])

    b, e = result['baseline'], result['enhanced']
    print(f"总TP样本: {result['total_tp_expected']}, 总FP样本: {result['total_fp_expected']}")
    print(f"基线  召回={b['recall_pct']}% 安全样本误报={b['fp_rate_pct']}% "
          f"精度={b['precision_pct']}% 内部过滤={b['filtered_alerts']}")
    print(f"增强  召回={e['recall_pct']}% 安全样本误报={e['fp_rate_pct']}% "
          f"精度={e['precision_pct']}% 内部过滤={e['filtered_alerts']}")
    recall_delta = e['recall_pct'] - b['recall_pct']
    filtered_delta = b['filtered_alerts'] - e['filtered_alerts']
    print(f"召回提升 {recall_delta:+.1f}pt, "
          f"消除不健全过滤 {filtered_delta} 个告警 "
          f"(未知写大小→cannot_overflow缺陷)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
