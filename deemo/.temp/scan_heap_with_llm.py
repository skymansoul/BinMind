#!/usr/bin/env python3
"""堆样本扫描 + LLM 增强分析 — 接入 ollama qwen2.5:7b 执行真实 LLM 分析。"""
import json, os, sys, time, glob

DEMO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEMO)
os.chdir(DEMO)

from core.unified_heap_pipeline import analyze_heap_safety
from modules.llm_client import call_llm_simple, is_ai_configured

HEAP_OVERFLOW_DIR = os.path.join(DEMO, 'samples', 'cve_unified', 'synthetic_heap_overflow')
HEAP_SAFE_DIR = os.path.join(DEMO, 'samples', 'cve_unified', 'synthetic_heap_safe')
HEAP_EDGE_DIR = os.path.join(DEMO, 'samples', 'cve_unified', 'synthetic_heap_edge')


def llm_analyze_code(code, sample_name):
    """调用 ollama LLM 分析代码中的堆漏洞。"""
    system_prompt = (
        "你是二进制漏洞分析专家。分析给定C代码中的堆溢出漏洞。"
        "输出JSON格式: {\"vulnerabilities\":[{\"type\":\"\",\"cwe\":\"\",\"severity\":\"\",\"description\":\"\"}]}"
    )
    user_prompt = f"分析以下C代码({sample_name})中的堆溢出/堆安全漏洞:\n\n```c\n{code[:3000]}\n```"
    t0 = time.perf_counter()
    try:
        result = call_llm_simple(user_prompt, system_prompt=system_prompt, use_cache=False)
        elapsed = time.perf_counter() - t0
        return {
            'response': result,
            'elapsed_sec': round(elapsed, 2),
            'status': 'ok',
        }
    except Exception as e:
        elapsed = time.perf_counter() - t0
        return {
            'error': str(e)[:300],
            'elapsed_sec': round(elapsed, 2),
            'status': 'error',
        }


def scan_one(c_path, label, do_llm=True):
    """扫描单个 .c 样本。"""
    t0 = time.perf_counter()
    with open(c_path, 'r', encoding='utf-8', errors='replace') as f:
        code = f.read()

    findings, stats = analyze_heap_safety(code, 'main', c_path)
    elapsed = time.perf_counter() - t0

    confirmed = [f for f in findings if f.get('severity') == 'DEFINITE' or f.get('verdict') == 'DEFINITE']
    possible = [f for f in findings if f.get('severity') == 'POSSIBLE' or f.get('verdict') == 'POSSIBLE']

    result = {
        'sample': os.path.basename(os.path.dirname(c_path)),
        'label': label,
        'c_file': c_path,
        'elapsed_sec': round(elapsed, 2),
        'total_findings': len(findings),
        'confirmed': len(confirmed),
        'possible': len(possible),
        'filtered': stats.get('filtered', 0),
        'uaf_findings': stats.get('uaf_findings', 0),
        'double_free': stats.get('double_free_findings', 0),
        'alloc_sites': stats.get('alloc_sites', 0),
        'write_sites': stats.get('write_sites', 0),
        'allocator': stats.get('allocator', 'unknown'),
        'errors': stats.get('errors', []),
        'findings_detail': findings[:5],
    }

    if do_llm:
        llm_result = llm_analyze_code(code, result['sample'])
        result['llm'] = llm_result

    return result


def scan_dir(dir_path, label, do_llm=True):
    """扫描目录下所有 vuln.c 文件。"""
    results = []
    c_files = sorted(glob.glob(os.path.join(dir_path, '*/vuln.c')))
    for cf in c_files:
        sname = os.path.basename(os.path.dirname(cf))
        print(f"  scanning {sname} ...", flush=True)
        r = scan_one(cf, label, do_llm=do_llm)
        results.append(r)
        llm_stat = ''
        if 'llm' in r:
            llm_stat = f", llm={r['llm']['status']}({r['llm']['elapsed_sec']}s)"
        print(f"    -> findings={r['total_findings']}, confirmed={r['confirmed']}, "
              f"possible={r['possible']}, elapsed={r['elapsed_sec']}s{llm_stat}", flush=True)
    return results


if __name__ == '__main__':
    OUTPUT_DIR = os.path.join(DEMO, '.temp', 'results_heap')
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    ai_ok = is_ai_configured()
    print(f"AI configured: {ai_ok}", flush=True)
    print(f"AI_PROVIDER: {os.environ.get('AI_PROVIDER', 'from config')}", flush=True)

    all_results = []

    # 堆溢出样本 — 全部 LLM 分析
    print("\n=== 堆溢出样本扫描 (预期: 检出) ===", flush=True)
    ho_results = scan_dir(HEAP_OVERFLOW_DIR, 'heap_overflow', do_llm=True)
    all_results.extend(ho_results)

    # 堆安全样本 — 全部 LLM 分析
    print("\n=== 堆安全样本扫描 (预期: 不检出) ===", flush=True)
    hs_results = scan_dir(HEAP_SAFE_DIR, 'heap_safe', do_llm=True)
    all_results.extend(hs_results)

    # 堆边界样本 — 全部 LLM 分析
    print("\n=== 堆边界样本扫描 ===", flush=True)
    he_results = scan_dir(HEAP_EDGE_DIR, 'heap_edge', do_llm=True)
    all_results.extend(he_results)

    # 统计
    ho_tp = sum(1 for r in ho_results if r['total_findings'] > 0)
    hs_tn = sum(1 for r in hs_results if r['total_findings'] == 0)
    llm_ok = sum(1 for r in all_results if 'llm' in r and r['llm']['status'] == 'ok')
    llm_err = sum(1 for r in all_results if 'llm' in r and r['llm']['status'] == 'error')

    summary = {
        'heap_overflow_samples': len(ho_results),
        'heap_overflow_detected': ho_tp,
        'heap_overflow_recall': round(ho_tp / len(ho_results) * 100, 1) if ho_results else 0,
        'heap_safe_samples': len(hs_results),
        'heap_safe_correctly_filtered': hs_tn,
        'heap_safe_specificity': round(hs_tn / len(hs_results) * 100, 1) if hs_results else 0,
        'heap_edge_samples': len(he_results),
        'heap_edge_detected': sum(1 for r in he_results if r['total_findings'] > 0),
        'total_samples': len(all_results),
        'rule_engine_elapsed': round(sum(r['elapsed_sec'] for r in all_results), 2),
        'llm_calls_ok': llm_ok,
        'llm_calls_error': llm_err,
        'llm_total_elapsed': round(sum(r.get('llm', {}).get('elapsed_sec', 0) for r in all_results), 2),
        'ai_configured': ai_ok,
    }

    output = {
        'summary': summary,
        'results': all_results,
    }

    out_file = os.path.join(OUTPUT_DIR, 'heap_scan_with_llm.json')
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n=== 扫描完成 ===", flush=True)
    print(f"堆溢出: {ho_tp}/{len(ho_results)} 检出 (recall={summary['heap_overflow_recall']}%)", flush=True)
    print(f"堆安全: {hs_tn}/{len(hs_results)} 正确过滤 (specificity={summary['heap_safe_specificity']}%)", flush=True)
    print(f"堆边界: {summary['heap_edge_detected']}/{len(he_results)} 检出", flush=True)
    print(f"规则引擎总耗时: {summary['rule_engine_elapsed']}s", flush=True)
    print(f"LLM调用: ok={llm_ok}, error={llm_err}, 总耗时={summary['llm_total_elapsed']}s", flush=True)
    print(f"结果保存至: {out_file}", flush=True)
