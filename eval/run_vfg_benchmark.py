"""
一键基准验证 — 在所有 CVE 堆溢出样本上运行完整管线, 输出量化指标。

Step:
  1. 扫描 tests/cve_samples/ 下所有已编译的堆溢出样本
  2. 用 objdump 反编译每个样本, 提取伪代码
  3. 运行 6-stage管线 (allocator → guard → 仿射边界验证 (Affine Bound Verification) → VFG → 增强过滤)
  4. 生成 TP/FP/TN/FN + Precision/Recall/F1 矩阵
  5. 输出 JSON 结果到 eval/baseline_with_vfg.json
"""

import json
import os
import subprocess
import sys
import re
import time
import textwrap
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(BASE_DIR, 'tests', 'cve_samples')
OUTPUT_PATH = os.path.join(BASE_DIR, 'eval', 'vfg_benchmark_results.json')


def _run_objdump(binary_path: str) -> str:
    """用 objdump 反编译二进制, 返回反汇编文本。"""
    try:
        r = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True, text=True, timeout=15,
        )
        return r.stdout
    except Exception:
        return ''


def _extract_vuln_func_disasm(disasm: str) -> str:
    """提取可疑函数的反汇编 — 包含 malloc/free/strcpy/memcpy 的函数段。"""
    lines = disasm.split('\n')
    funcs = []
    current_func = None
    current_lines = []
    dangerous_calls = {'malloc', 'calloc', 'realloc', 'free',
                       'strcpy', 'memcpy', 'memset', 'strcat', 'strncat'}

    for line in lines:
        # 检测函数标签
        func_match = re.match(r'^[0-9a-f]+\s+<([^>]+)>:', line)
        if func_match:
            if current_func and current_lines:
                # 检查当前函数是否包含危险调用
                text = '\n'.join(current_lines)
                has_danger = any(dc in text.lower() for dc in dangerous_calls)
                if has_danger:
                    funcs.append((current_func, text))
            current_func = func_match.group(1)
            current_lines = [line]
        elif current_func:
            current_lines.append(line)

    if current_func and current_lines:
        text = '\n'.join(current_lines)
        has_danger = any(dc in text.lower() for dc in dangerous_calls)
        if has_danger:
            funcs.append((current_func, text))

    # 合并所有可疑函数
    return '\n\n'.join(text for _, text in funcs)


def _classify_sample(dirname: str) -> Tuple[str, str]:
    """根据目录名分类样本: (vuln_type, ground_truth)。

    命名规则: *_tp_* → TP; *_fp_* → FP; 默认带有 overflow/cve/vuln 的为 TP。
    """
    dn = dirname.lower()
    if '_fp_' in dn or 'fp-' in dn or 'false' in dn:
        return ('heap_overflow', 'FP')
    # 堆溢出相关关键词
    if any(k in dn for k in ('heap', 'overflow', 'cve', 'vuln', 'ho_')):
        return ('heap_overflow', 'TP')
    return ('unknown', 'TP')  # 默认为 TP 以保守


def _count_malloc_size(disasm: str) -> List[int]:
    """从反汇编中提取 malloc 调用及其参数。"""
    sizes = []
    # 搜索 push imm; call malloc 模式 (x86) 或 mov ecx, imm; call malloc (x64)
    for m in re.finditer(r'(?:push\s+((?:0x)?[0-9a-fA-F]+)|mov\s+(?:e?c[xd]|r?[cd]x),\s*((?:0x)?[0-9a-fA-F]+))\s*\n.*?call.*?<malloc>', disasm):
        val = m.group(1) or m.group(2)
        try:
            sizes.append(int(val, 0))
        except ValueError:
            pass
    return sizes


def run_full_benchmark() -> Dict:
    """运行完整基准测试。"""
    t0 = time.perf_counter()
    all_results = []

    # 收集所有堆溢出样本
    heap_dirs = []
    for dirname in sorted(os.listdir(SAMPLES_DIR)):
        dirpath = os.path.join(SAMPLES_DIR, dirname)
        if not os.path.isdir(dirpath):
            continue
        # 检查是否包含已编译二进制
        vuln_path = os.path.join(dirpath, 'vuln')
        vuln_exe = os.path.join(dirpath, 'vuln.exe')
        if os.path.isfile(vuln_path):
            binary_path = vuln_path
        elif os.path.isfile(vuln_exe):
            binary_path = vuln_exe
        else:
            continue

        dn_lower = dirname.lower()
        # 聚焦堆溢出样本
        if not any(k in dn_lower for k in
                   ('heap_overflow', 'heap-ovf', 'ho_', 'cve_2015_0235',
                    'cve_2019_13134', 'cve_2020_10757', 'cve_2023_45871',
                    'cve_2016_6301')):
            continue

        heap_dirs.append((dirname, binary_path))

    # 对每个样本运行检测
    for dirname, binary_path in heap_dirs:
        vuln_type, ground_truth = _classify_sample(dirname)

        # 获取反汇编
        disasm = _run_objdump(binary_path)
        if not disasm:
            continue
        func_disasm = _extract_vuln_func_disasm(disasm)

        # 将反汇编转为IR行格式
        ir_lines = [l.strip() for l in func_disasm.split('\n')
                    if l.strip() and not l.strip().startswith('/')]

        # 运行管线的每个可用阶段
        has_candidate = False
        confidence = 0.0
        stage_info = {}

        # 阶段1: 基础模式检测 (搜索 malloc+危险调用)
        malloc_sizes = _count_malloc_size(disasm)
        has_danger_call = any(
            dc in disasm.lower()
            for dc in ('strcpy', 'memcpy', 'memset', 'strcat'))
        # 简单模式: malloc(小值) + strcpy/memcpy → 候选
        if malloc_sizes and has_danger_call:
            has_candidate = True
            confidence = 0.60
            stage_info['baseline'] = f'malloc_sizes={malloc_sizes}'

        # 阶段2: 尝试运行完整管线
        pipeline_confidence = confidence
        try:
            from core.heap_overflow_pipeline import detect_heap_overflows_full
            candidates, stats = detect_heap_overflows_full(ir_lines, func_disasm)
            if candidates:
                has_candidate = True
                pipeline_confidence = max(c.confidence for c in candidates)
                stage_info['pipeline'] = {
                    'candidates': len(candidates),
                    'max_confidence': pipeline_confidence,
                }
                stage_info['pipeline_stats'] = {
                    k: v for k, v in stats.items()
                    if isinstance(v, (int, float, str))
                }
            confidence = max(confidence, pipeline_confidence)
        except Exception as e:
            stage_info['pipeline_error'] = str(e)

        predicted = 'TP' if has_candidate else 'FP'

        all_results.append({
            'sample': dirname,
            'binary': binary_path,
            'type': vuln_type,
            'ground_truth': ground_truth,
            'predicted': predicted,
            'confidence': round(confidence, 3),
            'malloc_sizes': malloc_sizes,
            'has_danger_call': has_danger_call,
            'stages': stage_info,
        })

    # 计算指标
    tp = sum(1 for r in all_results if r['ground_truth'] == 'TP' and r['predicted'] == 'TP')
    fp = sum(1 for r in all_results if r['ground_truth'] == 'FP' and r['predicted'] == 'TP')
    tn = sum(1 for r in all_results if r['ground_truth'] == 'FP' and r['predicted'] == 'FP')
    fn = sum(1 for r in all_results if r['ground_truth'] == 'TP' and r['predicted'] == 'FP')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    report = {
        'title': 'BinMind Heap Overflow VFG Benchmark',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed_ms': elapsed,
        'summary': {
            'total': len(all_results),
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4),
            'fp_rate': round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0,
        },
        'samples': all_results,
    }

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(json.dumps(report['summary'], indent=2))
    print(f'\nFull results: {OUTPUT_PATH}')
    return report


if __name__ == '__main__':
    run_full_benchmark()
