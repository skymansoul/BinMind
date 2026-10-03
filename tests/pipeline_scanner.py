"""
管线扫描器 —— scan_binary 核心逻辑 + 守卫推断。
"""
import os, re, time
from typing import Any, Dict


def infer_guards(source: str) -> dict:
    """从源码推断守卫条件: {index_var: max_bound}。

    模式: if (idx < N) { ... buf[idx] = ... }
    或:    if (idx >= N) return; ... buf[idx] = ...
    支持 #define 宏名作为边界值。
    """
    # 先提取宏
    macros = {}
    for line in source.splitlines():
        m = re.match(r'#define\s+(\w+)\s+(\d+)\b', line.strip())
        if m:
            macros[m.group(1)] = int(m.group(2))

    guards = {}
    lines = source.splitlines()

    for line in lines:
        stripped = line.strip()
        # 模式1: if (var < N) 或 if (var <= N) — N 可以是字面量或宏名
        m = re.search(r'if\s*\(\s*(\w+)\s*(<=?)\s*(\w+)\s*\)', stripped)
        if m:
            var = m.group(1)
            op = m.group(2)
            bound_str = m.group(3)
            bound = None
            try:
                bound = int(bound_str)
            except ValueError:
                if bound_str in macros:
                    bound = macros[bound_str]
            if bound is not None:
                if op == '<=':
                    bound += 1
                if var not in guards or bound < guards[var]:
                    guards[var] = bound

        # 模式2: if (var >= N) return/exit → var < N 是安全条件的反面
        m2 = re.search(
            r'if\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)\s*(?:return|exit|goto)',
            stripped,
        )
        if m2:
            var = m2.group(1)
            bound_str = m2.group(2)
            bound = None
            try:
                bound = int(bound_str)
            except ValueError:
                if bound_str in macros:
                    bound = macros[bound_str]
            if bound is not None:
                if var not in guards or bound < guards[var]:
                    guards[var] = bound

    return guards


def scan_binary(binary_path: str, src_path: str = None) -> dict:
    """对单个样本运行 源码扫描 + 守卫推断 + 分配器过滤 管道。

    检测策略:
      1. source_scanner 提取所有堆操作候选
      2. 分配器语义: 比较 write_size vs glibc effective_size
      3. 守卫推断: 检测 if(idx<N) 模式，过滤已防护的写入
      4. 确定性写入: memcpy(buf, src, 48) 可直接比较数值
      5. 动态写入: array_store / strcpy → UNCERTAIN (保守保留)
      6. detected = 存在未被守卫过滤的 OVERFLOW/UNCERTAIN 候选
    """
    t0 = time.time()
    result = {
        'detected': False, 'findings_count': 0,
        'baseline_count': 0, 'source_scan_count': 0,
        'enhanced_count': 0, 'gapsbv_filtered': 0,
        'gapsbv_kept': 0, 'gapsbv_uncertain': 0,
        'src_overflow': 0, 'src_uncertain': 0, 'src_safe': 0,
        'guard_filtered': 0,
        'verdicts': [], 'duration_ms': 0, 'error': '',
    }
    try:
# 读取源码
        source = ''
        if src_path and os.path.isfile(src_path):
            with open(src_path, encoding='utf-8', errors='replace') as f:
                source = f.read()

        ir_lines = source.splitlines() if source else []

# 第1层: 源码扫描 + 守卫推断
        try:
            from tests.source_scanner import extract_heap_ops_c
            from tests.source_classifier import classify_finding

            source_ops = extract_heap_ops_c(source) if source else []
            result['source_scan_count'] = len(source_ops)

            guard_bounds = infer_guards(source)
            result['guard_filtered'] = 0

            for so in source_ops:
                cls = classify_finding(so)
                is_ovf = so.get('is_overflow', False)
                write_type = so.get('type', '')
                idx_var = so.get('idx_var', '')

# 守卫检查: array_store 有前置 if(idx<N) guard
                guarded = False
                guard_bound = 0
                if write_type == 'array_write' and idx_var:
                    if idx_var in guard_bounds:
                        guard_bound = guard_bounds[idx_var]
                        eff = so.get('alloc_effective', 0)
                        if guard_bound > 0 and eff > 0 and guard_bound <= eff:
                            guarded = True
                            result['guard_filtered'] += 1

                if cls == 'SAFE' or guarded:
                    verdict = 'SAFE'
                    result['src_safe'] += 1
                elif cls == 'OVERFLOW':
                    verdict = 'OVERFLOW'
                    result['src_overflow'] += 1
                else:
                    verdict = 'UNCERTAIN'
                    result['src_uncertain'] += 1

                result['verdicts'].append({
                    'type': so.get('type', 'heap-overflow'),
                    'confidence': 0.7 if (is_ovf or cls == 'UNCERTAIN') else 0.3,
                    'verdict': verdict,
                    'desc': (f"alloc={so.get('alloc_func','')}({so.get('alloc_size_expr','')}) "
                            f"write={so.get('write_func','')}(sz={so.get('write_size',0)}) "
                            f"req={so.get('alloc_requested',0)} eff={so.get('alloc_effective',0)} "
                            f"cls={cls} guarded={guarded}"),
                })
        except ImportError:
            pass

# 第2层: 仿射边界验证 HeapVerify (辅助验证)
        try:
            from core.heap_verify import HeapVerify
            verifier = HeapVerify()
            if ir_lines:
                summary = verifier.verify_function('\n'.join(ir_lines), '')
                result['enhanced_count'] = summary.total_input
                result['gapsbv_filtered'] = summary.filtered
                result['gapsbv_kept'] = summary.kept
                result['gapsbv_uncertain'] = summary.uncertain
        except ImportError:
            pass

# 汇总判定
        result['findings_count'] = len(result['verdicts'])
        result['detected'] = (result['src_overflow'] > 0
                              or result['src_uncertain'] > 0)

    except Exception as e:
        result['error'] = f'{type(e).__name__}: {str(e)[:300]}'
    result['duration_ms'] = int((time.time() - t0) * 1000)
    return result
