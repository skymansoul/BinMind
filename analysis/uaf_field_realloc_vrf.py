"""
UAF增强VRF — 结构体字段 / Realloc别名 / 循环内double-free 检测.
与 uaf_semantic_vrf.py 互补: 基础VRF无法处理 r->name / old=realloc 模式.
"""
from __future__ import annotations
import re
from typing import Dict, List, Set, Tuple

_RE_MALLOC_RAW = re.compile(
    r'(\w[\w.\->]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(')
_RE_FREE_RAW = re.compile(r'\bfree\s*\(\s*(\w[\w.\->]*)\s*\)')
_RE_STRUCT_FIELD = re.compile(r'^(\w+)->(\w+)$')
_RE_STRUCT_FIELD_ASSIGN = re.compile(r'(\w+)->(\w+)\s*=\s*(\w[\w.\->]*)\s*;?')
_RE_FOR_LOOP = re.compile(r'\bfor\s*\([^)]*\)\s*\{?\s*(.*)', re.DOTALL)
_RE_WHILE_LOOP = re.compile(r'\bwhile\s*\([^)]*\)\s*\{?\s*(.*)', re.DOTALL)
_RE_REALLOC_OLD = re.compile(r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?realloc\s*\(\s*(\w+)\s*,')
_RE_DEREF_FIELD = re.compile(r'(\w+)->(\w+)\s*=|(\w+)->(\w+)\s*\[|->(\w+)\s*\(')

_C_KW = {'if','for','while','do','else','return','goto','break','continue',
         'case','default','switch','sizeof','typedef','struct','enum','union',
         'void','int','char','long','short','float','double','unsigned','signed',
         'const','static','extern','volatile','register','auto','NULL','nullptr'}

def _is_id(s: str) -> bool:
    return bool(s) and s not in _C_KW and re.match(r'^[a-zA-Z_]\w*$', s)

def _is_id_or_field(s: str) -> bool:
    """允许 p 或 p->field 两种形式."""
    if not s: return False
    if _is_id(s): return True
    m = _RE_STRUCT_FIELD.match(s)
    return bool(m) and _is_id(m.group(1)) and _is_id(m.group(2))

def _root_ptr(ptr: str) -> str:
    """ptr->field → ptr."""
    m = _RE_STRUCT_FIELD.match(ptr)
    return m.group(1) if m else ptr


def detect_struct_field_uaf(code: str) -> List[Dict]:
    """检测结构体字段UAF: free(p->field); p->field = X;"""
    results, lines = [], code.splitlines()

    # 收集所有 struct field free
    field_frees: List[Tuple[str, str, int]] = []  # (struct_var, field, line)
    for i, line in enumerate(lines):
        for m in _RE_FREE_RAW.finditer(line):
            ptr = m.group(1)
            fm = _RE_STRUCT_FIELD.match(ptr)
            if fm and _is_id(fm.group(1)) and _is_id(fm.group(2)):
                field_frees.append((fm.group(1), fm.group(2), i))

    if not field_frees:
        return results

    # 找出free后的field使用
    for struct_var, field, free_ln in field_frees:
        for i in range(free_ln + 1, len(lines)):
            line = lines[i]
            # struct_var->field 的赋值/解引用/数组访问/函数调用
            patterns = [
                rf'{struct_var}->{field}\s*\[',           # p->field[...]
                rf'{struct_var}->{field}\s*=',             # p->field = ...
                rf'{struct_var}->{field}\s*\)',            # func(p->field)
                rf'->{field}\s*\(' if struct_var in line else '',  # p->field(...)
            ]
            for pat in patterns:
                if pat and re.search(pat, line):
                    results.append({
                        'ptr': f'{struct_var}->{field}',
                        'free_line': free_ln, 'use_line': i,
                        'use_detail': line.strip()[:80],
                        'type': 'struct_field_uaf',
                        'verdict': 'CONFIRMED', 'confidence': 0.70,
                    })
                    break
    return results


def detect_realloc_old_use(code: str) -> List[Dict]:
    """检测 realloc 旧指针使用: old=malloc; new=realloc(old,...); use(old)."""
    results = []
    lines = code.splitlines()

    realloc_old_pairs = []
    for i, line in enumerate(lines):
        for m in _RE_REALLOC_OLD.finditer(line):
            new_var, old_var = m.group(1), m.group(2)
            if _is_id(new_var) and _is_id(old_var) and new_var != old_var:
                realloc_old_pairs.append((old_var, new_var, i))

    for old_var, new_var, realloc_ln in realloc_old_pairs:
        for i in range(realloc_ln + 1, len(lines)):
            line = lines[i]
            if f'free({old_var})' in line or f'free({new_var})' in line:
                continue
            if re.search(rf'\b{re.escape(old_var)}\b', line):
                # 确认使用: 解引用/作为参数/数组索引
                if re.search(rf'{re.escape(old_var)}\s*\[|'
                            rf'\*{re.escape(old_var)}|'
                            rf'{re.escape(old_var)}->|'
                            rf'\(\s*{re.escape(old_var)}\s*\)|'
                            rf',\s*{re.escape(old_var)}\s*[,)]|'
                            rf'puts\s*\(\s*{re.escape(old_var)}|'
                            rf'printf\s*\([^)]*{re.escape(old_var)}',
                            line):
                    results.append({
                        'ptr': old_var, 'new_ptr': new_var,
                        'realloc_line': realloc_ln, 'use_line': i,
                        'use_detail': line.strip()[:80],
                        'type': 'realloc_old_use',
                        'verdict': 'CONFIRMED', 'confidence': 0.75,
                    })
                    break
    return results


def detect_loop_double_free(code: str) -> List[Dict]:
    """检测循环内double-free: for/while循环体中调用free()."""
    results, lines = [], code.splitlines()

    # 逐行扫描, 检测 free() 是否在循环体内
    in_loop = False
    loop_start = -1
    loop_free_ptrs: Set[str] = set()
    brace_depth = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # 跟踪循环
        if re.search(r'\b(for|while)\s*\(', stripped):
            in_loop = True
            loop_start = i
            loop_free_ptrs.clear()
            if '{' not in stripped:
                # 单行循环: for(...) free(p); 循环体内free必为double-free
                for m in _RE_FREE_RAW.finditer(stripped):
                    ptr = _root_ptr(m.group(1))
                    results.append({
                        'ptr': ptr, 'free_line': i,
                        'use_detail': stripped[:80],
                        'type': 'loop_double_free',
                        'verdict': 'CONFIRMED', 'confidence': 0.75,
                        'reason': f'free({ptr}) in single-line loop → double-free on next iteration',
                    })
                in_loop = False  # 单行循环体已处理完毕
                continue

        if in_loop:
            # 跟踪花括号深度 (简化: 计数变化)
            brace_delta = stripped.count('{') - stripped.count('}')
            brace_depth += brace_delta

            for m in _RE_FREE_RAW.finditer(stripped):
                ptr = _root_ptr(m.group(1))
                if ptr in loop_free_ptrs:
                    results.append({
                        'ptr': ptr, 'free_line': i,
                        'use_detail': stripped[:80],
                        'type': 'loop_double_free',
                        'verdict': 'CONFIRMED', 'confidence': 0.70,
                        'reason': f'free({ptr}) in loop (first free in body → double-free on iteration)',
                    })
                loop_free_ptrs.add(ptr)

            if brace_depth <= 0:
                in_loop = False
                brace_depth = 0
    return results


def detect_null_deref_alias_uaf(code: str) -> List[Dict]:
    """检测全局指针通过函数间接双重释放: g_f = malloc(); f(); f(); 其中 f() 内 free(g_f)."""
    results = []
    lines = code.splitlines()

    # 收集 globals — 在第一个函数定义前的 name = NULL; 声明
    globals_set = set()
    for i, line in enumerate(lines):
        stripped = line.strip()
        # 遇到函数定义则停止 (全局变量区结束)
        if re.search(r'\w\s*\([^)]*\)\s*\{', stripped):
            break
        # 匹配 name = NULL; 排除明显非声明的行
        sm = re.search(r'(\w+)\s*=\s*(?:NULL|nullptr|0)\s*;', stripped)
        if sm:
            name = sm.group(1)
            if _is_id(name) and ')' not in stripped.split('=')[0]:
                globals_set.add(name)

    if not globals_set:
        return results

    # 在每个函数中查找 free(global)
    func_free_map: Dict[str, List[Tuple[str, int]]] = {}  # func_name → [(global, line)]
    current_func = 'main'
    for i, line in enumerate(lines):
        fm = re.match(r'\w+\s+(\w+)\s*\(', line)
        if fm and _is_id(fm.group(1)):
            current_func = fm.group(1)
            if current_func not in func_free_map:
                func_free_map[current_func] = []
        for g in globals_set:
            if re.search(rf'\bfree\s*\(\s*{re.escape(g)}\s*\)', line):
                func_free_map.setdefault(current_func, []).append((g, i))

    # 检查 main 中是否有函数被多次调用, 且该函数 free 了全局指针
    main_start = -1
    for i, line in enumerate(lines):
        if re.search(r'int\s+main\s*\(', line):
            main_start = i
            break
    if main_start < 0:
        return results

    call_counts: Dict[str, int] = {}
    for i in range(main_start, len(lines)):
        for func_name in func_free_map:
            if func_name != 'main' and re.search(rf'\b{func_name}\s*\(', lines[i]):
                call_counts[func_name] = call_counts.get(func_name, 0) + 1

    for func_name, count in call_counts.items():
        if count >= 2 and func_free_map.get(func_name):
            for g, free_ln in func_free_map[func_name]:
                results.append({
                    'ptr': g, 'free_line': free_ln,
                    'use_detail': f'double-free via {func_name}() called {count}x',
                    'type': 'interproc_double_free',
                    'verdict': 'CONFIRMED', 'confidence': 0.80,
                    'reason': f'{func_name}() frees global {g}, called {count}x in main',
                })

    # 模式: main中free(g)后再调用含free(g)的辅助函数
    # double_free_06: free(g_buf); handler(); // handler内部也有free(g_buf)
    main_freed_globals: Dict[str, int] = {}  # global → free_line in main
    main_func_calls: List[Tuple[str, int]] = []  # (func_name, call_line) after last free
    in_main = False
    for i, line in enumerate(lines):
        if re.search(r'int\s+main\s*\(', line):
            in_main = True
            continue
        if in_main:
            if re.search(r'\breturn\b', line) and '{' not in line:
                break
            for g in globals_set:
                if re.search(rf'\bfree\s*\(\s*{re.escape(g)}\s*\)', line):
                    main_freed_globals[g] = i
            for func_name in func_free_map:
                if func_name != 'main' and re.search(rf'\b{func_name}\s*\(', line):
                    main_func_calls.append((func_name, i))

    for func_name, call_ln in main_func_calls:
        for g in main_freed_globals:
            if g in dict(func_free_map.get(func_name, [])):
                # 确认free在call之前
                if main_freed_globals[g] < call_ln:
                    results.append({
                        'ptr': g, 'free_line': call_ln,
                        'use_detail': f'double-free: free({g}) then {func_name}() also frees {g}',
                        'type': 'interproc_double_free',
                        'verdict': 'CONFIRMED', 'confidence': 0.80,
                        'reason': f'free({g}) in main@{main_freed_globals[g]}, then {func_name}()@{call_ln} also frees {g}',
                    })
    return results


def analyze_uaf_enhanced(code: str) -> Dict:
    """增强UAF检测: 基础VRF + 结构体字段 + Realloc + 循环 + 跨函数."""
    # 收集4种增强检测结果
    struct_results = detect_struct_field_uaf(code)
    realloc_results = detect_realloc_old_use(code)
    loop_results = detect_loop_double_free(code)
    interproc_results = detect_null_deref_alias_uaf(code)

    all_results = struct_results + realloc_results + loop_results + interproc_results
    confirmed = [r for r in all_results if r.get('confidence', 0) >= 0.60]
    likely = [r for r in all_results if 0.30 <= r.get('confidence', 0) < 0.60]

    return {
        'total': len(all_results),
        'confirmed': len(confirmed),
        'likely': len(likely),
        'filtered': len(all_results) - len(confirmed) - len(likely),
        'detected': len(confirmed) + len(likely) > 0,
        'details': all_results,
        'by_type': {
            'struct_field': len(struct_results),
            'realloc_old': len(realloc_results),
            'loop_double_free': len(loop_results),
            'interproc_double_free': len(interproc_results),
        },
    }


__all__ = ['analyze_uaf_enhanced', 'detect_struct_field_uaf',
           'detect_realloc_old_use', 'detect_loop_double_free',
           'detect_null_deref_alias_uaf']
