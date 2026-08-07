"""
多工具对比基准测试 — BinMind GAPSBV vs objdump vs nm vs 纯正则。
在全部33个堆溢出样本上运行, 生成对比指标和图表。

工具:
  BinMind-GAPSBV — 源码扫描 + 守卫推断 + 分配器语义
  Objdump-Naive  — objdump反汇编 + call指令计数启发式
  Nm-Symbol      — nm符号表: 存在malloc+memcpy → 盲报
  Regex-Baseline — 纯正则匹配 (无分配器模型/守卫推断), Flawfinder类比

依赖 benchmark_runners.py 提供各工具运行器。
"""
import os, sys, json, time, csv
from pathlib import Path
from typing import List

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
SAMPLE_DIR = os.path.join(BASE, 'tests', 'samples', 'heap_overflow')
OUT_DIR = os.path.join(BASE, 'eval')

# 预期映射
EXPECTED = {
    'CVE-2014-0160': True, 'CVE-2016-6301': True, 'CVE-2017-11176': True,
    'CVE-2018-6552': True, 'CVE-2019-1010298': True, 'CVE-2020-10711': True,
    'CVE-2021-3156': True, 'CVE-2022-0185': True, 'CVE-2022-23222': True,
    'CVE-2023-0461': True, 'CVE-2024-21894': True,
    'HEAP-OVERFLOW-BASIC-01': True, 'HEAP-OVERFLOW-LOOP-02': True,
    'HEAP-OVERFLOW-COND-03': True, 'HEAP-OVERFLOW-MULTI-06': True,
    'HEAP-OVERFLOW-REALLOC-07': True,
    'heap_aliased_ptr': True, 'heap_dynamic_index': True,
    'heap_int_overflow_to_heap': True, 'heap_loop_overflow': True,
    'heap_no_guard_check': True, 'heap_off_by_one': True,
    'heap_realloc_misuse': True, 'heap_simple_overflow': True,
    'heap_strcpy_overflow': True, 'heap_struct_write': True,
    'HEAP-OVERFLOW-FP-04': True, 'HEAP-OVERFLOW-ALIGN-05': True,
    'heap_slack_space': True,
    'cve_2021_3156_sudoedit': True, 'cve_2022_0185_kernel_heap': True,
    'cve_2023_23001_custom': True,
    'heap_guard_protected': False,
}

TOOLS = ['BinMind-GAPSBV', 'Objdump-Naive', 'Nm-Symbol', 'Regex-Baseline']


# 指标计算

def compute_metrics(results: List[dict]) -> dict:
    """对一组结果计算 TP/FP/TN/FN/Precision/Recall/F1。"""
    tp = fp = tn = fn = total_ms = 0
    for r in results:
        exp = EXPECTED.get(r['sample'], True)
        detected = r.get('detected', False)
        if exp and detected:
            tp += 1
        elif exp and not detected:
            fn += 1
        elif not exp and detected:
            fp += 1
        else:
            tn += 1
        total_ms += r.get('duration_ms', 0)

    total = tp + fp + tn + fn
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)
    fp_rate = fp / max(fp + tn, 1)

    return {
        'total': total, 'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'precision': round(precision, 4), 'recall': round(recall, 4),
        'f1': round(f1, 4), 'fp_rate': round(fp_rate, 4),
        'total_ms': total_ms, 'avg_ms': total_ms // max(total, 1),
    }


# 主流程

def main():
    from eval.benchmark_runners import (
        run_binmind, run_objdump, run_nm, run_regex_baseline,
    )

    print('=' * 72)
    print('BinMind GAPSBV — 多工具对比基准测试')
    print('=' * 72)

    # 发现样本
    samples = []
    for d in sorted(Path(SAMPLE_DIR).iterdir()):
        if not d.is_dir():
            continue
        src = d / 'vuln.c'
        if not src.exists():
            continue
        exe = d / 'vuln.exe'
        samples.append({
            'name': d.name,
            'src_path': str(src),
            'binary_path': str(exe) if exe.exists() else '',
        })

    print(f'\n发现 {len(samples)} 个样本')
    print(f'工具: {", ".join(TOOLS)}')

    # 运行所有工具
    all_results = {tool: [] for tool in TOOLS}
    runners = {
        'BinMind-GAPSBV': run_binmind,
        'Objdump-Naive': run_objdump,
        'Nm-Symbol': run_nm,
        'Regex-Baseline': run_regex_baseline,
    }

    for tool in TOOLS:
        runner = runners[tool]
        print(f'\n{"─" * 60}')
        print(f'[{tool}]')
        for i, s in enumerate(samples):
            r = runner(s['name'], s['src_path'], s['binary_path'])
            all_results[tool].append(r)
            marker = '!' if r.get('detected') else ' '
            dur = r.get('duration_ms', 0)
            if i % 8 == 0 or i == len(samples) - 1:
                print(f'  [{i+1:2d}/{len(samples)}] {marker} {s["name"]:<35s} {dur}ms')

    # 计算指标
    print(f'\n{"=" * 72}')
    print('对比结果')
    print(f'{"=" * 72}')

    header = f'{"Tool":<20s} {"TP":>4s} {"FP":>4s} {"TN":>4s} {"FN":>4s} {"Prec":>7s} {"Recall":>7s} {"F1":>7s} {"FPR":>7s} {"Avg ms":>7s}'
    print(header)
    print('-' * len(header))

    all_metrics = {}
    for tool in TOOLS:
        m = compute_metrics(all_results[tool])
        all_metrics[tool] = m
        print(f'{tool:<20s} {m["TP"]:>4d} {m["FP"]:>4d} {m["TN"]:>4d} {m["FN"]:>4d} '
              f'{m["precision"]:>6.1%} {m["recall"]:>6.1%} {m["f1"]:>7.4f} '
              f'{m["fp_rate"]:>6.1%} {m["avg_ms"]:>6d}')

    # 逐样本明细
    print(f'\n{"─" * 60}')
    print('逐样本明细 (前10个异常)')
    print(f'{"─" * 60}')

    for s in samples:
        name = s['name']
        exp = EXPECTED.get(name, True)
        detections = []
        for tool in TOOLS:
            for r in all_results[tool]:
                if r['sample'] == name:
                    detections.append('+' if r.get('detected') else '-')
                    break
        status = 'TP' if exp and '+' in detections else \
                 ('TN' if not exp and '-' in detections[0] else
                  ('FP' if not exp and '+' in detections[0] else 'FN'))
        if status in ('FP', 'FN') or (exp is False):
            print(f'  [{status}] {name:<35s} exp={exp} '
                  f'BinMind={detections[0]} Objdump={detections[1]} '
                  f'Nm={detections[2]} Regex={detections[3]}')

# 保存结果
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    _save_outputs(all_metrics, all_results, timestamp)
    return all_metrics


def _save_outputs(all_metrics, all_results, timestamp):
    """保存 JSON / CSV / LaTeX 输出。"""
    json_path = os.path.join(OUT_DIR, f'multi_tool_benchmark_{timestamp}.json')
    with open(json_path, 'w') as f:
        json.dump({
            'metrics': all_metrics,
            'results': all_results,
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }, f, indent=2, ensure_ascii=False)

    csv_path = os.path.join(OUT_DIR, f'multi_tool_benchmark_{timestamp}.csv')
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Tool', 'TP', 'FP', 'TN', 'FN', 'Precision',
                         'Recall', 'F1', 'FPR', 'AvgMs'])
        for tool in TOOLS:
            m = all_metrics[tool]
            writer.writerow([tool, m['TP'], m['FP'], m['TN'], m['FN'],
                            f"{m['precision']:.4f}", f"{m['recall']:.4f}",
                            f"{m['f1']:.4f}", f"{m['fp_rate']:.4f}",
                            m['avg_ms']])

    tex_path = os.path.join(OUT_DIR, f'multi_tool_table_{timestamp}.tex')
    with open(tex_path, 'w') as f:
        f.write(r'\begin{table}[htbp]' + '\n')
        f.write(r'\centering' + '\n')
        f.write(r'\caption{Multi-Tool Heap Overflow Detection Comparison}' + '\n')
        f.write(r'\label{tab:multi-tool}' + '\n')
        f.write(r'\begin{tabular}{lrrrrrrr}' + '\n')
        f.write(r'\toprule' + '\n')
        f.write(r'Tool & TP & FP & TN & FN & Precision & Recall & F1 \\' + '\n')
        f.write(r'\midrule' + '\n')
        for tool in TOOLS:
            m = all_metrics[tool]
            f.write(f'{tool} & {m["TP"]} & {m["FP"]} & {m["TN"]} & {m["FN"]} & '
                    f'{m["precision"]:.1%} & {m["recall"]:.1%} & {m["f1"]:.4f} \\\\\n')
        f.write(r'\bottomrule' + '\n')
        f.write(r'\end{tabular}' + '\n')
        f.write(r'\end{table}' + '\n')

    print(f'\n报告已保存:')
    print(f'  JSON: {json_path}')
    print(f'  CSV:  {csv_path}')
    print(f'  LaTeX: {tex_path}')


if __name__ == '__main__':
    main()
