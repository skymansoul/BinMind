#!/usr/bin/env python3
"""堆样本真实扫描脚本 — 通过 analyze_heap_safety + LLM 分析执行真实检测。"""
import json, os, sys, time, glob

DEMO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEMO)
os.chdir(DEMO)

from core.unified_heap_pipeline import analyze_heap_safety

# 堆溢出样本（预期检出）
HEAP_OVERFLOW_DIR = os.path.join(DEMO, 'samples', 'cve_unified', 'synthetic_heap_overflow')
# 堆安全样本（预期不检出）
HEAP_SAFE_DIR = os.path.join(DEMO, 'samples', 'cve_unified', 'synthetic_heap_safe')
# 堆边界样本
HEAP_EDGE_DIR = os.path.join(DEMO, 'samples', 'cve_unified', 'synthetic_heap_edge')

# LLM 分析
try:
    from analysis.c_source_analyzer import analyze_c_source
    HAS_LLM = True
except Exception:
    HAS_LLM = False

# LLM 适配层
try:
    from adapters.llm_adapter import LLMAdapter
    llm = LLMAdapter()
    HAS_LLM_ADAPTER = True
except Exception:
    HAS_LLM_ADAPTER = False

def scan_one(c_path, label):
    """扫描单个 .c 样本。"""
    t0 = time.perf_counter()
    with open(c_path, 'r', encoding='utf-8', errors='replace') as f:
        code = f.read()

    # 分析主函数（若没有 main 就用空字符串，管线会提取所有函数）
    findings, stats = analyze_heap_safety(code, 'main', c_path)

    elapsed = time.perf_counter() - t0

    # 提取关键信息
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
        'findings_detail': findings[:5],  # 前5条详情
    }

    # 尝试 LLM 增强
    if HAS_LLM_ADAPTER:
        try:
            from adapters.llm_adapter import LLMAdapter
            llm = LLMAdapter()
            # 提取函数代码片段发给 LLM
            prompt = f"分析以下C代码中的堆溢出漏洞，给出漏洞类型和CWE编号:\n\n{code[:2000]}"
            resp = llm.analyze(prompt)
            result['llm_response'] = resp[:500] if resp else None
            result['llm_enabled'] = True
        except Exception as e:
            result['llm_enabled'] = False
            result['llm_error'] = str(e)[:200]
    else:
        result['llm_enabled'] = False

    return result


def scan_dir(dir_path, label):
    """扫描目录下所有 vuln.c 文件。"""
    results = []
    c_files = sorted(glob.glob(os.path.join(dir_path, '*/vuln.c')))
    for cf in c_files:
        print(f"  scanning {os.path.basename(os.path.dirname(cf))} ...", flush=True)
        r = scan_one(cf, label)
        results.append(r)
        print(f"    -> findings={r['total_findings']}, confirmed={r['confirmed']}, "
              f"possible={r['possible']}, elapsed={r['elapsed_sec']}s", flush=True)
    return results


if __name__ == '__main__':
    OUTPUT_DIR = os.path.join(DEMO, '.temp', 'results_heap')
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_results = []

    print("=== 堆溢出样本扫描 (预期: 检出) ===", flush=True)
    ho_results = scan_dir(HEAP_OVERFLOW_DIR, 'heap_overflow')
    all_results.extend(ho_results)

    print("\n=== 堆安全样本扫描 (预期: 不检出) ===", flush=True)
    hs_results = scan_dir(HEAP_SAFE_DIR, 'heap_safe')
    all_results.extend(hs_results)

    print("\n=== 堆边界样本扫描 ===", flush=True)
    he_results = scan_dir(HEAP_EDGE_DIR, 'heap_edge')
    all_results.extend(he_results)

    # 统计
    ho_tp = sum(1 for r in ho_results if r['total_findings'] > 0)
    hs_tn = sum(1 for r in hs_results if r['total_findings'] == 0)

    summary = {
        'heap_overflow_samples': len(ho_results),
        'heap_overflow_detected': ho_tp,
        'heap_overflow_recall': round(ho_tp / len(ho_results) * 100, 1) if ho_results else 0,
        'heap_safe_samples': len(hs_results),
        'heap_safe_correctly_filtered': hs_tn,
        'heap_safe_precision': round(hs_tn / len(hs_results) * 100, 1) if hs_results else 0,
        'heap_edge_samples': len(he_results),
        'heap_edge_detected': sum(1 for r in he_results if r['total_findings'] > 0),
        'total_elapsed': round(sum(r['elapsed_sec'] for r in all_results), 2),
        'llm_adapter_available': HAS_LLM_ADAPTER,
    }

    output = {
        'summary': summary,
        'results': all_results,
    }

    out_file = os.path.join(OUTPUT_DIR, 'heap_scan_results.json')
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n=== 扫描完成 ===", flush=True)
    print(f"堆溢出: {ho_tp}/{len(ho_results)} 检出 (recall={summary['heap_overflow_recall']}%)", flush=True)
    print(f"堆安全: {hs_tn}/{len(hs_results)} 正确过滤 (specificity={summary['heap_safe_precision']}%)", flush=True)
    print(f"堆边界: {summary['heap_edge_detected']}/{len(he_results)} 检出", flush=True)
    print(f"总耗时: {summary['total_elapsed']}s", flush=True)
    print(f"结果保存至: {out_file}", flush=True)
