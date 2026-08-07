# DCG消融实验——对比DCG启用/禁用时的FP压制效果
# 对全部heap样本运行两次: 一次enable_dcg=True, 一次enable_dcg=False
# 输出DCG贡献的FP压制数量和具体样本
import json, csv, sys, subprocess, time
from pathlib import Path
from typing import List, Dict, Tuple

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

from src.disasm.objdump_parser import ObjdumpParser
from src.detect.pipeline_bridge import DetectionPipeline, CombinedVerdict
from analysis.heap_fp_filter import HeapFalsePositiveFilter, FilterDecision

BUILD = BASE / "tests" / "regression" / "build"
EVAL = Path(__file__).parent

# 堆溢出样本ground truth
_HEAP_GT = {
    'CVE-2002-0639':True,'CVE-2004-0816':True,'CVE-2006-2451':True,
    'CVE-2007-4268':True,'CVE-2008-1720':True,'CVE-2009-1385':True,
    'CVE-2010-2950':True,'CVE-2011-1577':True,'CVE-2012-2136':True,
    'CVE-2013-2147':True,'CVE-2014-0160':True,'CVE-2014-2523':True,
    'CVE-2014-9471':True,'CVE-2015-1805':True,'CVE-2015-7547':True,
    'CVE-2016-10191':True,'CVE-2016-3841':True,'CVE-2016-6187':True,
    'CVE-2017-1000112':True,'CVE-2017-13089':True,'CVE-2018-1000001':True,
    'CVE-2018-1160':True,'CVE-2018-14634':True,'CVE-2018-6789':True,
    'CVE-2019-17558':True,'CVE-2020-10713':True,'CVE-2020-12026':True,
    'CVE-2020-25656':True,'CVE-2021-3156':True,'CVE-2022-0185':True,
    'CVE-2022-23270':True,'CVE-2022-3602':True,'CVE-2023-38545':True,
    'CVE-2023-6817':True,
    'HEAP-FP-001':True,'HEAP-FP-003':True,'HEAP-FP-004':True,
    'HEAP-FP-005':True,'HEAP-FP-006':True,'HEAP-FP-007':True,
    'HEAP-FP-002':False,'HEAP-FP-008':False,
}


def run_dcg_ablation(exe_path: Path) -> Dict:
    """对单个二进制运行DCG启用/禁用对比"""
    sid = _sample_id(exe_path)
    if sid not in _HEAP_GT:
        return {}

    proc = subprocess.run(['objdump','-d',str(exe_path)], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        return {}
    funcs = ObjdumpParser()._parse_output(proc.stdout)
    if not funcs:
        return {}

    is_vuln = _HEAP_GT[sid]
    results = {'sample': sid, 'is_vuln': is_vuln}

    for dcg_enabled, label in [(True, 'with_dcg'), (False, 'without_dcg')]:
        pipeline = DetectionPipeline()
        # 替换内部filter的DCG设置
        pipeline._new_filter._dcg = (
            __import__('analysis.dcg_post_filter', fromlist=['DCGPostFilter'])
            .DCGPostFilter(safety_margin=16) if dcg_enabled else None)

        all_reports = []
        t0 = time.perf_counter()
        for func in funcs:
            if len(func.instructions) < 3:
                continue
            try:
                all_reports.extend(pipeline.scan_function(
                    func.instructions, func.bb_boundaries, func.cfg_edges, func.name))
            except Exception:
                continue
        elapsed = (time.perf_counter() - t0) * 1000

        _POS = (CombinedVerdict.CONFIRMED, CombinedVerdict.LIKELY, CombinedVerdict.NEW_FINDING)
        typed = [r for r in all_reports
                 if r.combined_verdict in (CombinedVerdict.CONFIRMED, CombinedVerdict.LIKELY,
                     CombinedVerdict.NEW_FINDING, CombinedVerdict.FILTERED, CombinedVerdict.UNCERTAIN)]
        pos_reports = [r for r in typed if r.combined_verdict in _POS]
        detected = len(pos_reports) > 0

        results[f'{label}_detected'] = detected
        results[f'{label}_verdict'] = pos_reports[0].combined_verdict.value if pos_reports else (
            typed[0].combined_verdict.value if typed else 'none')
        results[f'{label}_confidence'] = round(pos_reports[0].confidence if pos_reports else 0, 3)
        results[f'{label}_time_ms'] = round(elapsed, 1)
        results[f'{label}_report_count'] = len(all_reports)
        # 记录DCG是否参与过滤
        results[f'{label}_dcg_safe'] = any(
            'DCG' in r.reason for r in all_reports)

    # 判定DCG贡献
    w = results.get('with_dcg_detected')
    wo = results.get('without_dcg_detected')
    if is_vuln:
        results['dcg_effect'] = 'correct_retained' if w else 'ERROR_FN'
    else:
        if wo and not w:
            results['dcg_effect'] = 'FP_SUPPRESSED'  # DCG压制了FP
        elif not wo and not w:
            results['dcg_effect'] = 'correct_filtered_both'
        elif wo and w:
            results['dcg_effect'] = 'FP_both_failed'
        else:
            results['dcg_effect'] = 'unknown'

    return results


def _sample_id(exe_path: Path):
    parts = exe_path.stem.split('_')
    for i in range(len(parts)):
        candidate = '_'.join(parts[:i+1])
        if candidate in _HEAP_GT:
            return candidate
    return parts[0] if parts else None


def main():
    exes = sorted(BUILD.glob('*.exe'))
    heap_exes = [e for e in exes if _sample_id(e) in _HEAP_GT and not e.name.endswith('_dbg.exe')]
    # 去重: 每个sample只取第一个编译版本(O0优先)
    seen = set(); unique = []
    for e in heap_exes:
        sid = _sample_id(e)
        if sid not in seen:
            seen.add(sid); unique.append(e)

    print(f"DCG Ablation: {len(unique)} unique heap samples\n{'='*70}")
    rows = []
    for exe in unique:
        r = run_dcg_ablation(exe)
        if r:
            rows.append(r)
            flag = {'FP_SUPPRESSED': '+DCG', 'correct_filtered_both': '.', 'FP_both_failed': 'X',
                    'correct_retained': 'OK', 'ERROR_FN': '!!FN'}.get(r.get('dcg_effect',''), '?')
            print(f"  {flag:5s} {r['sample']:<25s} vuln={r['is_vuln']} "
                  f"with_dcg={r.get('with_dcg_detected','?')} "
                  f"without_dcg={r.get('without_dcg_detected','?')} "
                  f"dcg_safe={r.get('with_dcg_dcg_safe','?')}")

    suppressed = [r for r in rows if r.get('dcg_effect') == 'FP_SUPPRESSED']
    vuln_samples = [r for r in rows if r['is_vuln']]
    fp_samples = [r for r in rows if not r['is_vuln']]
    fp_without = sum(1 for r in fp_samples if r.get('without_dcg_detected'))
    fp_with = sum(1 for r in fp_samples if r.get('with_dcg_detected'))
    recall_without = sum(1 for r in vuln_samples if r.get('without_dcg_detected')) / max(1, len(vuln_samples))
    recall_with = sum(1 for r in vuln_samples if r.get('with_dcg_detected')) / max(1, len(vuln_samples))

    print(f"\n{'='*70}\nDCG ABLATION RESULTS")
    print(f"  Samples: {len(rows)} ({len(vuln_samples)} VULN + {len(fp_samples)} SAFE)")
    print(f"  Without DCG: recall={recall_without:.1%}, FP={fp_without}/{len(fp_samples)}")
    print(f"  With DCG:    recall={recall_with:.1%}, FP={fp_with}/{len(fp_samples)}")
    print(f"  DCG FP suppressed: {len(suppressed)}")
    if suppressed:
        for r in suppressed:
            print(f"    - {r['sample']}: {r.get('without_dcg_verdict','?')}→{r.get('with_dcg_verdict','?')}")

    csv_path = EVAL / 'dcg_ablation_results.csv'
    with open(csv_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else ['sample'])
        w.writeheader(); w.writerows(rows)
    print(f"\nCSV → {csv_path}")

    json_path = EVAL / 'dcg_ablation_results.json'
    with open(json_path, 'w') as f:
        json.dump({'summary': {
            'n': len(rows), 'n_vuln': len(vuln_samples), 'n_safe': len(fp_samples),
            'fp_without_dcg': fp_without, 'fp_with_dcg': fp_with,
            'fp_suppressed': len(suppressed),
            'recall_without_dcg': round(recall_without, 3),
            'recall_with_dcg': round(recall_with, 3),
            'suppressed_samples': [r['sample'] for r in suppressed]
        }, 'rows': rows}, f, indent=2)
    print(f"JSON → {json_path}")


if __name__ == '__main__':
    main()
