#!/usr/bin/env python3
# coding: utf-8
"""
FPR 降低效果定量演示 — 六层过滤管线每层误报削减效果.
输出委托 demo_fp_output.py; 本模块负责候选生成与逐层过滤逻辑.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))))

from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class LayerResult:
    name: str
    candidates_in: int
    candidates_out: int
    fp_filtered: int
    tp_retained: int
    reduction_pct: float
    cumulative_reduction: float


def generate_synthetic_candidates() -> Tuple[List[Dict], Dict[str, bool]]:
    """生成 20 个合成候选 (12 TP + 8 FP), 模拟真实堆溢出检测.

    FP 类型:
      - 3: alloc≥write (L1 区间分析可证安全)
      - 2: 内部数据拷贝 (L2 污点过滤)
      - 1: 跨函数但分配器约束安全 (L3+L5)
      - 1: 路径约束排除溢出 (L4 抽象解释)
      - 1: 对齐后块足够大 (L1+L5 联合)
    """
    candidates, gt = [], {}

    tp_samples = [
        {'id': 'TP_01', 'alloc': 64, 'write': 128, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': False, 'desc': 'malloc(64)+memcpy(128)'},
        {'id': 'TP_02', 'alloc': 32, 'write': 256, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': True, 'desc': 'malloc(32)+recv(256)'},
        {'id': 'TP_03', 'alloc': 128, 'write': 512, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': False, 'desc': 'calloc(128)+read(512)'},
        {'id': 'TP_04', 'alloc': 16, 'write': 64, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': False, 'desc': 'malloc(16)+strcpy(64B)'},
        {'id': 'TP_05', 'alloc': 256, 'write': 1024, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': True, 'desc': 'malloc(256)+fread(1024)'},
        {'id': 'TP_06', 'alloc': 8, 'write': 32, 'taint': 'network',
         'has_bounds_check': False, 'cross_func': False, 'desc': 'malloc(8)+recv(32)'},
        {'id': 'TP_07', 'alloc': 512, 'write': 4096, 'taint': 'file_input',
         'has_bounds_check': False, 'cross_func': True, 'desc': 'malloc(512)+read(4096)'},
        {'id': 'TP_08', 'alloc': 48, 'write': 96, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': False, 'desc': 'malloc(48)+memcpy(96)'},
        {'id': 'TP_09', 'alloc': 1024, 'write': 2048, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': False, 'desc': 'malloc(1K)+strcat overflow'},
        {'id': 'TP_10', 'alloc': 4, 'write': 256, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': False, 'desc': 'malloc(4)+gets(256)'},
        {'id': 'TP_11', 'alloc': 64, 'write': 65, 'taint': 'external_input',
         'has_bounds_check': True, 'cross_func': True, 'desc': 'off-by-one malloc(64)+memcpy(65)'},
        {'id': 'TP_12', 'alloc': 128, 'write': 200, 'taint': 'external_input',
         'has_bounds_check': False, 'cross_func': False, 'desc': 'malloc(128)+sprintf(200)'},
    ]
    for s in tp_samples:
        candidates.append({
            'overflow_site': s['id'], 'alloc_site': 0x400000,
            'write_site': 0x400010, 'alloc_size': s['alloc'],
            'write_size': s['write'], 'taint_source_type': s['taint'],
            'has_bounds_check': s['has_bounds_check'],
            'cross_func': s['cross_func'], 'vuln_type': 'heap_overflow',
            'confidence': 0.8, 'exploitable': True,
        })
        gt[s['id']] = True

    fp_samples = [
        # L1: alloc >= write
        {'id': 'FP_01', 'alloc': 256, 'write': 200, 'taint': 'external_input',
         'filter_layer': 'L1', 'desc': 'malloc(256)+memcpy(200)'},
        {'id': 'FP_02', 'alloc': 512, 'write': 64, 'taint': 'external_input',
         'filter_layer': 'L1', 'desc': 'malloc(512)+memcpy(64)'},
        {'id': 'FP_03', 'alloc': 128, 'write': 128, 'taint': 'external_input',
         'filter_layer': 'L1', 'desc': 'malloc(128)+memcpy(128)'},
        # L2: 内部数据
        {'id': 'FP_04', 'alloc': 32, 'write': 64, 'taint': 'internal_data',
         'filter_layer': 'L2', 'desc': '内部memcpy(64)—非外部输入'},
        {'id': 'FP_05', 'alloc': 16, 'write': 32, 'taint': 'internal_data',
         'filter_layer': 'L2', 'desc': '内部strcpy(32)—非外部输入'},
        # L5: 分配器约束
        {'id': 'FP_06', 'alloc': 5, 'write': 16, 'taint': 'external_input',
         'filter_layer': 'L5', 'desc': 'malloc(5)+memcpy(16)—usable=16'},
        # L4: 路径约束
        {'id': 'FP_07', 'alloc': 64, 'write': 128, 'taint': 'external_input',
         'filter_layer': 'L4', 'desc': 'if(size>64)size=64; malloc(64)+memcpy(size)'},
        # L1+L5: 对齐
        {'id': 'FP_08', 'alloc': 31, 'write': 32, 'taint': 'external_input',
         'filter_layer': 'L1+L5', 'desc': 'malloc(31)+memcpy(32)—glibc→48 usable'},
    ]
    for s in fp_samples:
        candidates.append({
            'overflow_site': s['id'], 'alloc_site': 0x400000,
            'write_site': 0x400010, 'alloc_size': s['alloc'],
            'write_size': s['write'], 'taint_source_type': s['taint'],
            'has_bounds_check': False, 'cross_func': False,
            'vuln_type': 'heap_overflow', 'confidence': 0.5, 'exploitable': False,
            'expected_filter_layer': s['filter_layer'],
        })
        gt[s['id']] = False

    return candidates, gt


def simulate_layer_filtering(candidates: List[Dict],
                              gt: Dict[str, bool]) -> List[LayerResult]:
    """模拟六层过滤, 逐层统计 FP 削减效果."""
    layers = []
    current = list(candidates)

    tp0 = sum(1 for c in current if _is_tp(c, gt))
    fp0 = sum(1 for c in current if not _is_tp(c, gt))
    layers.append(LayerResult('L0_baseline', 0, len(current), 0, tp0, 0.0, 0.0))

    # L1: 值区间 + 分配器约束
    before = len(current)
    current = [c for c in current if not _l1_filter(c)]
    after_tp = sum(1 for c in current if _is_tp(c, gt))
    after_fp = sum(1 for c in current if not _is_tp(c, gt))
    fp_red = fp0 - after_fp
    layers.append(LayerResult('L1_value_range', before, len(current),
                               fp_red, after_tp, fp_red / max(1, fp0),
                               fp_red / max(1, fp0)))

    # L2-L5: 每层独立过滤
    for name, filter_fn in [('L2_taint', _l2_filter), ('L3_interproc', _l3_filter),
                             ('L4_path_abstract', _l4_filter), ('L5_constraint', _l5_filter)]:
        before = len(current)
        fp_before = sum(1 for c in current if not _is_tp(c, gt))
        current = [c for c in current if not filter_fn(c)]
        after_tp = sum(1 for c in current if _is_tp(c, gt))
        after_fp = sum(1 for c in current if not _is_tp(c, gt))
        fp_red = fp_before - after_fp
        cum = (fp0 - after_fp) / max(1, fp0)
        layers.append(LayerResult(name, before, len(current),
                                   fp_red, after_tp, fp_red / max(1, fp0), cum))

    # 最终摘要
    final_tp = sum(1 for c in current if _is_tp(c, gt))
    final_fp = sum(1 for c in current if not _is_tp(c, gt))
    total_red = (fp0 - final_fp) / max(1, fp0)
    layers.append(LayerResult('L6_summary', len(candidates), len(current),
                               fp0 - final_fp, final_tp, total_red, total_red))

    # 嵌入最终指标
    final = LayerResult('FINAL', final_tp, final_fp, tp0 - final_tp, tp0, 0, 0)
    layers.append(final)
    return layers


# 各层过滤判定 (简化规则, 模拟实际算法)

def _is_tp(c: Dict, gt: Dict[str, bool]) -> bool:
    return gt.get(c.get('overflow_site', ''), False)


def _l1_filter(c: Dict) -> bool:
    """alloc >= write 或 分配器约束 usable >= write → 过滤."""
    alloc, write = c.get('alloc_size', 0), c.get('write_size', 0)
    if alloc >= write:
        return True
    usable = max(32, (alloc + 16 + 15) & ~15) - 16
    return write <= usable


def _l2_filter(c: Dict) -> bool:
    """非外部输入 → 过滤."""
    return c.get('taint_source_type') == 'internal_data'


def _l3_filter(c: Dict) -> bool:
    """L3 不直接过滤, 只降权."""
    return False


def _l4_filter(c: Dict) -> bool:
    """边界检查 + 大块分配 → 可能安全."""
    return c.get('has_bounds_check', False) and c.get('alloc_size', 0) >= 64


def _l5_filter(c: Dict) -> bool:
    """分配器约束: 小分配可用大小 >= write → 过滤."""
    alloc, write = c.get('alloc_size', 0), c.get('write_size', 0)
    usable = max(32, (alloc + 16 + 15) & ~15) - 16
    return write <= usable and alloc <= 16


if __name__ == '__main__':
    from tests.regression.demo_fp_output import (
        print_layer_table, generate_latex_layer_table, save_demo_json)
    candidates, gt = generate_synthetic_candidates()
    tp_initial = sum(1 for v in gt.values() if v)
    fp_initial = sum(1 for v in gt.values() if not v)
    print(f'Initial: {len(candidates)} candidates ({tp_initial} TP, {fp_initial} FP)')

    layers = simulate_layer_filtering(candidates, gt)
    print_layer_table(layers)

    out_dir = os.path.join(os.path.dirname(__file__), '..', 'regression', 'output')
    generate_latex_layer_table(layers, os.path.join(out_dir, 'fp_reduction_layers.tex'))
    save_demo_json(layers, tp_initial, fp_initial, out_dir)
