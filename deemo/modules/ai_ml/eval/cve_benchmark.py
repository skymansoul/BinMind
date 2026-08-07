# CVE真二进制基准测试——对回归样本编译产物运行全管线+消融实验
# 与deep_benchmark.py互补: 该文件用合成objdump, 本文件用真实编译的CVE二进制
import json, csv, time, sys, subprocess, logging
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger(__name__)
BASE = Path(__file__).parent.parent
if str(BASE) not in sys.path: sys.path.insert(0, str(BASE))

BUILD_DIR = BASE / "tests" / "regression" / "build"
EVAL_DIR = Path(__file__).parent

def _load_ground_truth() -> Dict[str, Tuple[str, bool]]:
    gt = {}
    for c in ['CVE-2002-0639','CVE-2004-0816','CVE-2006-2451','CVE-2007-4268','CVE-2008-1720',
        'CVE-2009-1385','CVE-2010-2950','CVE-2011-1577','CVE-2012-2136','CVE-2013-2147',
        'CVE-2014-0160','CVE-2014-2523','CVE-2014-9471','CVE-2015-1805','CVE-2015-7547',
        'CVE-2016-10191','CVE-2016-3841','CVE-2016-6187','CVE-2017-1000112','CVE-2017-13089',
        'CVE-2018-1000001','CVE-2018-1160','CVE-2018-14634','CVE-2018-6789','CVE-2019-17558',
        'CVE-2020-10713','CVE-2020-12026','CVE-2020-25656','CVE-2021-3156','CVE-2022-0185',
        'CVE-2022-23270','CVE-2022-3602','CVE-2023-38545','CVE-2023-6817']:
        gt[c] = ('buffer_overflow', True)
    uaf_true = {'CVE-2016-6309','CVE-2019-12900','CVE-2024-6387'}
    for c in ['CVE-2011-0065','CVE-2012-0767','CVE-2013-0912','CVE-2014-1767','CVE-2015-0313',
        'CVE-2016-1665','CVE-2016-6309','CVE-2017-5123','CVE-2018-8174','CVE-2019-12900',
        'CVE-2019-3568','CVE-2020-16040','CVE-2021-38003','CVE-2022-22620','CVE-2024-6387']:
        gt[c] = ('use_after_free', c in uaf_true)
    for c in ['CVE-2000-0573','CVE-2001-0013','CVE-2002-1343','CVE-2003-0358','CVE-2004-0557',
        'CVE-2005-2793','CVE-2006-3074','CVE-2007-5191','CVE-2008-1686','CVE-2009-1384',
        'CVE-2010-2948','CVE-2011-0411','CVE-2012-0809','CVE-2013-2178','CVE-2014-2851']:
        gt[c] = ('format_string', True)
    gt['HEAP-FP-002'] = gt['HEAP-FP-008'] = ('buffer_overflow', False)
    for fp in ['HEAP-FP-001','HEAP-FP-003','HEAP-FP-004','HEAP-FP-005','HEAP-FP-006','HEAP-FP-007']:
        gt[fp] = ('buffer_overflow', True)
    return gt

GROUND_TRUTH = _load_ground_truth()

_KNOWN_FN = {'CVE-2020-25656': 'cross-function free', 'HEAP-FP-002': 'cross-func bounds check'}
_KNOWN_FP = {'HEAP-FP-002': 'cross-function bounds check'}

@dataclass
class CveSampleResult:
    sample_id: str; vuln_type: str; is_true_vuln: bool; opt_level: str = "O0"
    detected: bool = False; verdict: str = ""; confidence: float = 0.0
    time_ms: float = 0.0; func_count: int = 0; report_count: int = 0
    error: str = ""; known_issue: str = ""

def _discover_binaries() -> List[Path]:
    if not BUILD_DIR.exists(): return []
    return [e for e in sorted(BUILD_DIR.glob("*.exe")) if not e.name.endswith('_dbg.exe')]

def _sample_id_from_path(exe_path: Path) -> Optional[str]:
    parts = exe_path.stem.split('_')
    if parts and (parts[0].startswith('CVE-') or parts[0].startswith('HEAP-')):
        return parts[0]
    return None


def run_single_binary(exe_path: Path) -> List[CveSampleResult]:
    from src.disasm.objdump_parser import ObjdumpParser
    from src.detect.pipeline_bridge import DetectionPipeline, CombinedVerdict

    sample_id = _sample_id_from_path(exe_path)
    if sample_id is None: return []
    stem = exe_path.stem; opt_level = "O0"
    for o in ('O3','O2','O1','O0'):
        if stem.endswith(f'_{o}'): opt_level = o; break
    gt = GROUND_TRUTH.get(sample_id)
    if gt is None: return []
    vuln_type, is_vuln = gt
    known = _KNOWN_FN.get(sample_id, '') if is_vuln else _KNOWN_FP.get(sample_id, '')
    results = []
    try:
        proc = subprocess.run(['objdump', '-d', str(exe_path)], capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            results.append(CveSampleResult(sample_id=sample_id, vuln_type=vuln_type,
                is_true_vuln=is_vuln, opt_level=opt_level, error='objdump_failed'))
            return results
        funcs = ObjdumpParser()._parse_output(proc.stdout)
        if not funcs:
            results.append(CveSampleResult(sample_id=sample_id, vuln_type=vuln_type,
                is_true_vuln=is_vuln, opt_level=opt_level, error='parse_failed'))
            return results
        pipeline = DetectionPipeline(); all_combined = []; t0 = time.perf_counter()
        for func in funcs:
            if len(func.instructions) < 3: continue
            try: all_combined.extend(pipeline.scan_function(
                func.instructions, func.bb_boundaries, func.cfg_edges, func.name))
            except Exception: continue
        elapsed = (time.perf_counter() - t0) * 1000
        _TYPE_MAP = {'buffer_overflow': (CombinedVerdict.CONFIRMED, CombinedVerdict.LIKELY,
            CombinedVerdict.NEW_FINDING, CombinedVerdict.FILTERED, CombinedVerdict.UNCERTAIN),
            'use_after_free': (CombinedVerdict.UAF_CONFIRMED, CombinedVerdict.UAF_LIKELY),
            'format_string': (CombinedVerdict.FMT_CONFIRMED, CombinedVerdict.FMT_LIKELY),
            'integer_overflow': (CombinedVerdict.INTOVF_CONFIRMED, CombinedVerdict.INTOVF_LIKELY)}
        typed = [c for c in all_combined if c.combined_verdict in _TYPE_MAP.get(vuln_type, ())]
        _POS = (CombinedVerdict.CONFIRMED, CombinedVerdict.LIKELY, CombinedVerdict.NEW_FINDING,
            CombinedVerdict.UAF_CONFIRMED, CombinedVerdict.UAF_LIKELY,
            CombinedVerdict.FMT_CONFIRMED, CombinedVerdict.FMT_LIKELY,
            CombinedVerdict.INTOVF_CONFIRMED, CombinedVerdict.INTOVF_LIKELY)
        r = CveSampleResult(sample_id=sample_id, vuln_type=vuln_type, is_true_vuln=is_vuln,
            opt_level=opt_level, time_ms=elapsed, func_count=len(funcs),
            report_count=len(all_combined), known_issue=known)
        if typed:
            best = max(typed, key=lambda c: c.confidence)
            r.detected = best.combined_verdict in _POS
            r.verdict = best.combined_verdict.value; r.confidence = best.confidence
        else: r.verdict = 'no_matching_type'
        results.append(r)
    except Exception as e:
        results.append(CveSampleResult(sample_id=sample_id, vuln_type=vuln_type,
            is_true_vuln=is_vuln, opt_level=opt_level, error=str(e)[:80]))
    return results


def compute_metrics(results: List[CveSampleResult], vuln_type: Optional[str] = None) -> Dict:
    f = [r for r in results if vuln_type is None or r.vuln_type == vuln_type]
    tp = sum(1 for r in f if r.detected and r.is_true_vuln)
    fp = sum(1 for r in f if r.detected and not r.is_true_vuln)
    fn = sum(1 for r in f if not r.detected and r.is_true_vuln)
    tn = sum(1 for r in f if not r.detected and not r.is_true_vuln)
    n = len(f); recall = tp / max(1, tp + fn); fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    return {'n': n, 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'errors': sum(1 for r in f if r.error),
            'recall': round(recall, 4), 'fpr': round(fpr, 4),
            'precision': round(precision, 4), 'f1': round(f1, 4),
            'accuracy': round((tp + tn) / max(1, n), 4)}


def main():
    bins = _discover_binaries()
    if not bins:
        print("[cve_benchmark] 未找到编译好的二进制文件——请先运行 tests/regression/compile_samples.py")
        print(f"[cve_benchmark] 预期位置: {BUILD_DIR}")
        return None, None
    print(f"[cve_benchmark] {len(bins)} 个编译好的二进制文件")
    hc = fc = uc = 0
    for exe in bins:
        sid = _sample_id_from_path(exe)
        if sid and sid in GROUND_TRUTH:
            vt, _ = GROUND_TRUTH[sid]
            if vt == 'buffer_overflow': hc += 1
            elif vt == 'format_string': fc += 1
            elif vt == 'use_after_free': uc += 1
    print(f"  heap_overflow={hc}  format_string={fc}  uaf={uc}")
    known_gt = [e for e in bins if _sample_id_from_path(e) in GROUND_TRUTH]
    print(f"  有真值映射: {len(known_gt)} 个")

    print(f"\n{'='*80}\nREAL CVE BINARY BENCHMARK ({len(known_gt)} samples)\n{'='*80}")
    print(f"{'Sample':<24} {'Type':<16} {'Truth':>5} {'Detected':>9} {'Verdict':<18} {'Conf':>5} {'Time':>8}")
    print(f"{'-'*90}")

    all_results = []; errs = 0
    for exe in known_gt:
        for r in run_single_binary(exe):
            all_results.append(r)
            truth = 'VULN' if r.is_true_vuln else 'SAFE'
            if r.error:
                print(f"ERR {r.sample_id:<21} {r.vuln_type:<16} {truth:>5} {'---':>9} {r.error:<18}"); errs += 1
            else:
                st = 'OK' if r.detected == r.is_true_vuln else 'MIS'
                kf = ' [KNOWN]' if r.known_issue else ''
                print(f"{st} {r.sample_id:<21} {r.vuln_type:<16} {truth:>5} {str(r.detected):>9} "
                      f"{r.verdict:<18} {r.confidence:>5.2f} {r.time_ms:>7.0f}ms{kf}")

    m = compute_metrics(all_results)
    avg_t = sum(r.time_ms for r in all_results) / max(1, len(all_results))
    print(f"\n{'='*80}\nOVERALL METRICS (n={m['n']}, errors={m['errors']})")
    print(f"  Accuracy:{m['accuracy']:.1%}  Recall:{m['recall']:.1%}(TP={m['tp']},FN={m['fn']})")
    print(f"  Precision:{m['precision']:.1%}(FP={m['fp']})  FPR:{m['fpr']:.1%}(TN={m['tn']})")
    print(f"  F1:{m['f1']:.3f}  Avg time:{avg_t:.1f}ms/sample\n{'='*80}")

    for vt, lb in [('buffer_overflow','堆溢出'),('use_after_free','UAF'),('format_string','格式串')]:
        mt = compute_metrics(all_results, vt)
        if mt['n']: print(f"  {lb:6s} n={mt['n']:3d} recall={mt['recall']:.1%} fpr={mt['fpr']:.1%} f1={mt['f1']:.3f}")

    kfn = [r for r in all_results if r.known_issue and r.is_true_vuln and not r.detected]
    kfp = [r for r in all_results if r.known_issue and not r.is_true_vuln and r.detected]
    if kfn:
        print(f"\n[KNOWN FN] ({len(kfn)}):")
        for r in kfn: print(f"  {r.sample_id}: {r.known_issue}")
    if kfp:
        print(f"\n[KNOWN FP] ({len(kfp)}):")
        for r in kfp: print(f"  {r.sample_id}: {r.known_issue}")

    csv_path = EVAL_DIR / 'cve_benchmark_results.csv'
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['sample_id','vuln_type','is_vuln','detected','verdict','confidence','time_ms','correct','error','known_issue','opt'])
        for r in all_results:
            w.writerow([r.sample_id, r.vuln_type, r.is_true_vuln, r.detected, r.verdict, r.confidence,
                        round(r.time_ms, 1), r.detected == r.is_true_vuln, r.error, r.known_issue, r.opt_level])
    print(f"\nCSV → {csv_path}")

    json_path = EVAL_DIR / 'cve_benchmark_results.json'
    clean = [{'sample_id':r.sample_id,'vuln_type':r.vuln_type,'is_vuln':r.is_true_vuln,
        'detected':r.detected,'verdict':r.verdict,'confidence':r.confidence,
        'time_ms':round(r.time_ms,1),'error':r.error,'known_issue':r.known_issue,
        'opt':r.opt_level,'correct':r.detected==r.is_true_vuln} for r in all_results]
    with open(json_path, 'w') as f:
        json.dump({'overall': m, 'per_type': {vt: compute_metrics(all_results, vt)
            for vt in ['buffer_overflow','use_after_free','format_string']},
            'results': clean, 'data_quality': 'REAL COMPILED BINARIES — objdump→pipeline direct'
        }, f, indent=2)
    print(f"JSON → {json_path}")
    return all_results, m

if __name__ == '__main__':
    main()
