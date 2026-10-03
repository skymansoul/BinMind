"""
循环分析器 — 数组写入聚合 (for循环体) + off-by-one 检测。

"""
import re
from typing import Any, Dict, List


# 循环边界: for (int i = 0; i <= N; i++) / for (i = 0; i < N; i++)
_LOOP_FOR_RE = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*\d+\s*;\s*'
    r'\1\s*(<=?)\s*(\d+)\s*;\s*'
    r'\1\s*\+\+\s*\)',
)

# 循环体内数组写入: buf[i] = ...
_LOOP_ARRAY_WRITE_RE = re.compile(
    r'(\w+)\s*\[\s*(\w+)\s*\]\s*=',
)


def _aggregate_loop_writes(paired: List[Dict], source: str) -> List[Dict]:
    """检测循环内数组写入并聚合总量。

    识别 for(i=0; i<=N; i++) buf[i]=... → 总写入 = N+1 (若 N+1 >= 分配有效大小 → 溢出)
    """
    loop_bounds = {}  # idx_var → max_iterations
    # (A) 数值上界: for(i=0; i<=32; i++)
    for m in _LOOP_FOR_RE.finditer(source):
        idx_var = m.group(1)
        op = m.group(2)
        try:
            bound = int(m.group(3))
        except ValueError:
            continue
        if op == '<=':
            max_iter = bound + 1
        else:
            max_iter = bound
        if idx_var not in loop_bounds or max_iter > loop_bounds[idx_var]:
            loop_bounds[idx_var] = max_iter
    # (B) 变量上界: for(i=0; i<=n; i++) → 提取 n 的值
    _var_loop_re = re.compile(
        r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*\d+\s*;\s*'
        r'\1\s*(<=?)\s*(\w+)\s*;\s*'
        r'\1\s*\+\+\s*\)',
    )
    for m in _var_loop_re.finditer(source):
        idx_var = m.group(1)
        op = m.group(2)
        bound_var = m.group(3)
        var_val = None
        for am in re.finditer(rf'{bound_var}\s*=\s*(\d+)\s*;', source):
            try:
                var_val = int(am.group(1))
                break
            except ValueError:
                pass
        if var_val is None:
            for dm in re.finditer(rf'#define\s+{bound_var}\s+(\d+)', source):
                try:
                    var_val = int(dm.group(1))
                    break
                except ValueError:
                    pass
        if var_val is not None:
            max_iter = var_val + 1 if op == '<=' else var_val
            if idx_var not in loop_bounds or max_iter > loop_bounds[idx_var]:
                loop_bounds[idx_var] = max_iter

    if not loop_bounds:
        return paired

    for p in paired:
        if p['type'] != 'array_write':
            continue
        idx = p.get('idx_var', '')
        if idx in loop_bounds:
            eff = p.get('alloc_effective', 0)
            req = p.get('alloc_requested', 0)
            max_writes = loop_bounds[idx]
            overflow = False
            if req > 0 and max_writes > req:
                overflow = True
            if eff > 0 and max_writes > eff:
                overflow = True
            if overflow:
                p['write_size'] = max_writes
                p['is_overflow'] = True
                p['write_func'] = 'loop_array_store'

    return paired


def _detect_off_by_one(paired: List[Dict], source: str) -> List[Dict]:
    """检测 off-by-one 循环: 分配循环 i<N 但写入循环 i<=N → 多写一次。

    模式:
      for (i = 0; i < N; i++)   buf[i] = malloc(size);  // N次分配
      for (i = 0; i <= N; i++)  memset(buf[i], ...);    // N+1次写入 ← BUG
    """
    from tests.source_matcher import extract_macros
    macros = extract_macros(source)

    def _resolve_bound(bound_str: str) -> int:
        """解析循环上界: 数字直接返回, 宏名查找, 否则 -1。"""
        if bound_str.isdigit():
            return int(bound_str)
        if bound_str in macros:
            return macros[bound_str]
        m = re.search(rf'#define\s+{bound_str}\s+(\d+)', source)
        if m:
            return int(m.group(1))
        return -1

    # 找所有分配循环: for(i=0; i<N; i++) arr[i]=malloc(...)
    alloc_loops = {}  # ptr → {count: N, op: '<'}
    _alloc_loop_re = re.compile(
        r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*\d+\s*;\s*'
        r'\1\s*(<=?)\s*(\d+|\w+)\s*;\s*'
        r'\1\s*\+\+\s*\)',
    )
    for m in _alloc_loop_re.finditer(source):
        idx_var = m.group(1)
        op = m.group(2)
        bound_str = m.group(3)
        bound_val = _resolve_bound(bound_str)
        if bound_val < 0:
            continue
        loop_start = m.end()
        brace_depth = 0
        loop_body_start = source.find('{', loop_start)
        if loop_body_start < 0:
            continue
        loop_end = loop_body_start
        for k in range(loop_body_start, len(source)):
            if source[k] == '{':
                brace_depth += 1
            elif source[k] == '}':
                brace_depth -= 1
                if brace_depth == 0:
                    loop_end = k + 1
                    break
        loop_body = source[loop_body_start:loop_end]
        arr_alloc_m = re.search(
            rf'(\w+)\s*\[\s*{idx_var}\s*\]\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc)',
            loop_body)
        if arr_alloc_m:
            alloc_loops[arr_alloc_m.group(1)] = {
                'count': bound_val,
                'op': op,
            }

    if not alloc_loops:
        return paired

    # 找写入循环: for(i=0; i<=N; i++) memcpy(arr[i], ...)
    for m in _alloc_loop_re.finditer(source):
        idx_var = m.group(1)
        op = m.group(2)
        bound_str = m.group(3)
        bound_val = _resolve_bound(bound_str)
        if bound_val < 0:
            continue
        write_count = bound_val
        if op == '<=':
            write_count += 1
        loop_start = m.end()
        brace_depth = 0
        loop_body_start = source.find('{', loop_start)
        if loop_body_start < 0:
            continue
        loop_end = loop_body_start
        for k in range(loop_body_start, len(source)):
            if source[k] == '{':
                brace_depth += 1
            elif source[k] == '}':
                brace_depth -= 1
                if brace_depth == 0:
                    loop_end = k + 1
                    break
        loop_body = source[loop_body_start:loop_end]
        arr_m = re.search(rf'(\w+)\s*\[\s*{idx_var}\s*\]', loop_body)
        if arr_m:
            arr_name = arr_m.group(1)
            if arr_name in alloc_loops:
                alloc_count = alloc_loops[arr_name]['count']
                if write_count > alloc_count:
                    for p in paired:
                        if p.get('ptr_var') == arr_name:
                            p['is_overflow'] = True
                            p['write_size'] = max(p.get('write_size', 0), 999)
                            p['write_func'] = 'off_by_one_loop'
    return paired
