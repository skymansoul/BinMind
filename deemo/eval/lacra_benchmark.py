"""
LACRA 仿射约束分析端到端测试 — 在16个CVE样本上验证FP削减效果.

测试目标: 测量LACRA (lpvra_affine + lpvra_lacra_integrator + lpvra_stride_filter)
在 c_semantic_analyzer 输出上的后处理过滤效果.

预期:
  - 所有原有 OVERFLOW/SAFE 判定不被改变 (功能只增不减)
  - 至少40%的 UNCERTAIN 被转换为 SAFE (仿射证明)
  - 零 UNCERTAIN→OVERFLOW 强制转换 (除非可证伪)
  - 单样本分析时间 < 5ms (轻量级)
"""

import json
import os
import sys
import time

# 路径设置
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(BASE_DIR, 'samples', 'cve_heap_overflow')
sys.path.insert(0, BASE_DIR)

from analysis.c_semantic_analyzer import CSemanticAnalyzer
from analysis.lpvra_lacra_integrator import LACRAIntegrator
from analysis.lpvra_stride_filter import enhance_heap_verdict_with_stride
from analysis.interval_domain import Interval


def find_c_files(directory: str):
    """查找目录下所有 .c 文件 (非 Makefile)."""
    c_files = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            if f.endswith('.c') and not f.startswith('Make') and not f.startswith('test_'):
                c_files.append(os.path.join(root, f))
    return sorted(c_files)


def extract_relevant_function(source: str) -> str:
    """提取C源码中与堆操作最相关的函数 (包含 malloc 的函数).

    支持多行函数声明: 返回类型/名称/参数/开括号可分布在不同行.
    """
    lines = source.splitlines()
    functions = []
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if not s or s.startswith('#') or s.startswith('//') or s.startswith('/*'):
            i += 1; continue
        if s.startswith('if') or s.startswith('while') or s.startswith('for'):
            i += 1; continue
        if s.startswith('switch') or s.startswith('typedef') or s.startswith('struct'):
            i += 1; continue

        # 检测函数定义: 收集声明行直到遇到 {
        if '(' in s and not s.startswith('return'):
            decl_start = i
            # 向前搜索: 跨越多行直到找到 {
            brace_line = -1
            for j in range(i, min(i + 5, len(lines))):
                if '{' in lines[j]:
                    brace_line = j
                    break
            if brace_line < 0:
                i += 1; continue

            # 从 decl_start 到 brace_line 是函数声明
            func_start = decl_start
            brace_depth = 1
            for ch in lines[brace_line]:
                if ch == '{': brace_depth += 1
            brace_depth -= 1  # 补偿初始的+1

            k = brace_line + 1
            while k < len(lines) and brace_depth > 0:
                for ch in lines[k]:
                    if ch == '{': brace_depth += 1
                    elif ch == '}': brace_depth -= 1
                k += 1
            functions.append((func_start, k))
            i = k
        else:
            i += 1

    if not functions:
        return source
    for start, end in functions:
        body = '\n'.join(lines[start:end])
        if 'malloc' in body or 'calloc' in body or 'realloc' in body:
            return body
    return source


def run_benchmark():
    """在CVE样本上运行LACRA基准测试."""
    c_files = find_c_files(SAMPLE_DIR)
    if not c_files:
        print("ERROR: No CVE .c files found in", SAMPLE_DIR)
        return

    analyzer = CSemanticAnalyzer()
    integrator = LACRAIntegrator()

    results = []
    summary = {
        'total_samples': len(c_files),
        'total_verdicts': 0,
        'before': {'OVERFLOW': 0, 'SAFE': 0, 'UNCERTAIN': 0},
        'after': {'OVERFLOW': 0, 'SAFE': 0, 'UNCERTAIN': 0},
        'lacra_safe_conversions': 0,
        'stride_conversions': 0,
        'total_time_ms': 0.0,
    }

    print(f"{'='*70}")
    print(f"LACRA Affine Constraint Analysis Benchmark")
    print(f"{'='*70}")
    print(f"  Samples: {len(c_files)}")
    print(f"  Method: CSemanticAnalyzer → LACRA affine filter → Stride filter")
    print()

    for c_path in c_files:
        sample_name = os.path.basename(os.path.dirname(c_path))
        try:
            with open(c_path, 'r', encoding='utf-8', errors='replace') as fh:
                source = fh.read()
        except Exception as e:
            print(f"  SKIP {sample_name}: read error {e}")
            continue

        func_source = extract_relevant_function(source)
        t0 = time.time()

        # 阶段1: C语义分析
        verdicts = analyzer.analyze(func_source)
        before_counts = {'OVERFLOW': 0, 'SAFE': 0, 'UNCERTAIN': 0}
        for v in verdicts:
            before_counts[v.verdict] = before_counts.get(v.verdict, 0) + 1

        # 阶段2: LACRA仿射过滤
        filtered = integrator.filter_uncertain(func_source, verdicts)
        after_counts = {'OVERFLOW': 0, 'SAFE': 0, 'UNCERTAIN': 0}
        for v in filtered:
            after_counts[v.verdict] = after_counts.get(v.verdict, 0) + 1

        lacra_safe = after_counts['SAFE'] - before_counts['SAFE']

        # 阶段3: 步长精化 (只对仍为 UNCERTAIN 的做附加检查)
        stride_conv = 0
        for v in filtered:
            if v.verdict != "UNCERTAIN":
                continue
            # 提取分配大小区间
            if v.alloc.size_const > 0:
                alloc_iv = Interval.const(v.alloc.size_const)
            else:
                alloc_iv = Interval.top()
            ws = v.write.size_const if v.write.size_const > 0 else 1
            result = enhance_heap_verdict_with_stride(
                v.alloc.var, alloc_iv, ws, func_source)
            if result is True:
                v.verdict = "SAFE"
                v.reason += " [stride: proved safe]"
                stride_conv += 1
            elif result is False:
                v.verdict = "OVERFLOW"
                v.reason += " [stride: proved overflow]"
                stride_conv += 1

        elapsed = (time.time() - t0) * 1000

        # 重新统计 after (含步长) — 必须在 summary 累加之前计算
        final_counts = {'OVERFLOW': 0, 'SAFE': 0, 'UNCERTAIN': 0}
        for v in filtered:
            final_counts[v.verdict] = final_counts.get(v.verdict, 0) + 1

        summary['total_time_ms'] += elapsed
        summary['before']['OVERFLOW'] += before_counts['OVERFLOW']
        summary['before']['SAFE'] += before_counts['SAFE']
        summary['before']['UNCERTAIN'] += before_counts['UNCERTAIN']
        summary['after']['OVERFLOW'] += final_counts['OVERFLOW']
        summary['after']['SAFE'] += final_counts['SAFE']
        summary['after']['UNCERTAIN'] += final_counts['UNCERTAIN']
        summary['lacra_safe_conversions'] += lacra_safe
        summary['stride_conversions'] += stride_conv
        summary['total_verdicts'] += len(filtered)

        status = f"{sample_name:<30s}"
        b_status = f"BEFORE: O={before_counts['OVERFLOW']} S={before_counts['SAFE']} U={before_counts['UNCERTAIN']}"
        a_status = f"AFTER: O={final_counts['OVERFLOW']} S={final_counts['SAFE']} U={final_counts['UNCERTAIN']}"
        delta = f"Δ: +{lacra_safe} affine +{stride_conv} stride"
        print(f"  {status} {b_status} → {a_status} ({delta}, {elapsed:.2f}ms)")

        results.append({
            'sample': sample_name,
            'before': before_counts,
            'after': final_counts,
            'lacra_conversions': lacra_safe,
            'stride_conversions': stride_conv,
            'elapsed_ms': round(elapsed, 3),
        })

    # 汇总
    fp_reduction = summary['lacra_safe_conversions'] + summary['stride_conversions']
    fp_before = summary['before']['UNCERTAIN']
    fp_rate_reduction = (fp_reduction / max(fp_before, 1)) * 100

    print()
    print(f"{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Total verdicts:           {summary['total_verdicts']}")
    print(f"  BEFORE:  O={summary['before']['OVERFLOW']}  "
          f"S={summary['before']['SAFE']}  U={summary['before']['UNCERTAIN']}")
    print(f"  AFTER:   O={summary['after']['OVERFLOW']}  "
          f"S={summary['after']['SAFE']}  U={summary['after']['UNCERTAIN']}")
    print(f"  LACRA affine conversions: {summary['lacra_safe_conversions']}")
    print(f"  Stride conversions:       {summary['stride_conversions']}")
    print(f"  Total FP reductions:      {fp_reduction}")
    print(f"  FP rate reduction:        {fp_rate_reduction:.1f}%")
    print(f"  Total time:               {summary['total_time_ms']:.2f}ms "
          f"({summary['total_time_ms']/max(len(c_files),1):.2f}ms avg)")
    print()

    # 保存结果
    output_path = os.path.join(
        BASE_DIR, 'eval', 'lacra_benchmark_results.json')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as fh:
        json.dump({
            'summary': summary,
            'details': results,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }, fh, indent=2)
    print(f"  Results saved to: {output_path}")

    return results


if __name__ == '__main__':
    run_benchmark()
