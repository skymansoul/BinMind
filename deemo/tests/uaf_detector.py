"""
TARPS UAF检测器 — 分析 free/use 模式, 判定释放后使用 (CWE-416)。

识别: free(p) 后存在 *p / p->field / p[...] / printf("..", p) 使用,
     且无 p=NULL / p=malloc() 保护。
支持: 别名指针 (q=p; free(p); use(q)), 数组元素 (free(a[i]); use(a[k])),
      结构体字段 (free(it); it->name), 条件释放路径。
"""
import re
from typing import Any, Dict, List

from tests.uaf_detector_helpers import (
    _build_global_alias_map,
    _extract_base_name,
    _extract_used_vars,
    _extract_args_string,
    _resolve_aliases,
)
from tests.cross_func_free import (
    build_cross_func_free_map,
    detect_cross_func_frees,
)


# free 调用: free(p); munmap(p, sz) — 支持单/双参数
_FREE_RE_SINGLE = re.compile(
    r'free\s*\(\s*(\w+(?:\[[^\]]+\])?(?:\->\w+)*)\s*\)\s*;'
)
_FREE_RE_MUNMAP = re.compile(
    r'munmap\s*\(\s*(\w+)\s*,', re.IGNORECASE,
)
# realloc也可能隐式free旧指针: new = realloc(old, sz) — old被释放
_REALLOC_FREE_RE = re.compile(
    r'(\w+)\s*=\s*realloc\s*\(\s*(\w+)\s*,', re.IGNORECASE,
)

# 指针设为 NULL 的保护模式
_NULLIFY_RE = re.compile(r'(\w+)\s*=\s*(?:NULL|0|nullptr)\s*;')

# 重新分配: p = malloc(...)
_REALLOC_RE = re.compile(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(')

# 别名赋值: q = p; saved = old; q = (char *)p;
_ALIAS_RE = re.compile(
    r'(?:\w+\s+)?\*?\s*(\w+)\s*=\s*'       # LHS: type? *? var =
    r'(?:\(\s*\w+\s*\*\s*\)\s*)?'           # 可选: (type *)
    r'(\w+)\s*;'                             # RHS: var;
)

def detect_uaf(source: str) -> Dict[str, Any]:
    """对 C 源码执行 TARPS UAF 检测。

    检测链路: free(p) → use(p) 无 NULLify 保护。
    支持: 别名追踪、数组索引、结构体字段访问、条件释放路径、
          回调全局别名 (g_var=param → func(ptr) → free(ptr) → use(g_var))。
    """
    lines = source.splitlines()
    free_records: List[Dict] = []  # {ptr_var, base_ptr, line_no, line, protected}
    alias_map: Dict[str, List[str]] = {}  # q → [p] (q是p的别名)
    findings = []

# 预扫描: 全局变量别名追踪
    # func(ptr) → 函数体内 g_var = param → g_var 是 ptr 的别名
    global_alias_map = _build_global_alias_map(source)

# 预扫描: 跨函数 free 追踪
    # void cleanup(T *p) { free(p); } → cleanup(data); 视为 free(data)
    cross_func_free_map = build_cross_func_free_map(source)
    detect_cross_func_frees(source, cross_func_free_map,
                             free_records, alias_map)

    # ── 跨函数 free 内部追踪: 在 cross_func_free 函数体内时跳过 raw free ──
    in_crossfree_func = None  # 当前所在函数名 (如果在cross_func_free函数内)
    cf_brace_depth = 0
    cf_entered_body = False  # 是否已看到 {

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith('//') or line.startswith('/*') or line.startswith('*'):
            continue
        # 跳过中文注释行 (专利文档/样本说明)
        if line.startswith(('模式', '调用', '与', '例', '注', '说', '返回', '安全', '补充')):
            continue
        line_no = i + 1

# 跨函数 free 函数体进入/退出追踪
        if in_crossfree_func is not None:
            cf_brace_depth += line.count('{') - line.count('}')
            if '{' in line:
                cf_entered_body = True
            if cf_entered_body and cf_brace_depth <= 0:
                in_crossfree_func = None
                cf_brace_depth = 0
                cf_entered_body = False
        else:
            # 检测是否进入 cross_func_free_map 中的函数
            for cf_func in cross_func_free_map:
                if re.match(rf'(?:void|int|static\s+(?:void|int))\s*{re.escape(cf_func)}\s*\(', line):
                    in_crossfree_func = cf_func
                    cf_brace_depth = line.count('{') - line.count('}')
                    cf_entered_body = ('{' in line)
                    break
        # 在 cross_func_free 函数内部, 跳过 raw free(param) — 由 cross_func_free 处理
        if in_crossfree_func is not None:
            continue
        am = _ALIAS_RE.search(line)
        if am:
            lhs, rhs = am.group(1), am.group(2)
            if lhs != rhs:
                alias_map.setdefault(lhs, []).append(rhs)

        # ── free(p) / munmap(p, ...) / realloc 隐式free 记录 ──
        free_found = False
        # free(p)
        fm = _FREE_RE_SINGLE.search(line)
        if fm:
            ptr_expr = fm.group(1)
            base_ptr = _extract_base_name(ptr_expr)
            if f'{base_ptr} = NULL' not in line and f'{base_ptr}=NULL' not in line:
                free_records.append({
                    'ptr_var': base_ptr, 'ptr_expr': ptr_expr,
                    'line_no': line_no, 'line': line,
                })
            free_found = True
        # munmap(p, sz)
        mm = _FREE_RE_MUNMAP.search(line)
        if mm:
            base_ptr = mm.group(1)
            free_records.append({
                'ptr_var': base_ptr, 'ptr_expr': base_ptr,
                'line_no': line_no, 'line': line,
            })
            free_found = True
        # realloc隐式释放旧指针: p = realloc(old, sz)
        rm = _REALLOC_FREE_RE.search(line)
        if rm:
            # new_var = rm.group(1), old_var = rm.group(2)
            old_var = rm.group(2)
            free_records.append({
                'ptr_var': old_var, 'ptr_expr': old_var,
                'line_no': line_no, 'line': line,
            })
            free_found = True
        if free_found:
            continue

# p=NULL 保护
        nm = _NULLIFY_RE.search(line)
        if nm:
            nullified = nm.group(1)
            for fr in free_records:
                candidates = _resolve_aliases(fr['ptr_var'], alias_map) | {fr['ptr_var']}
                if nullified in candidates and fr['line_no'] < line_no:
                    fr['protected'] = True

# p=malloc(...) 重新分配
        rm = _REALLOC_RE.search(line)
        if rm:
            realloced = rm.group(1)
            for fr in free_records:
                candidates = _resolve_aliases(fr['ptr_var'], alias_map) | {fr['ptr_var']}
                if realloced in candidates and fr['line_no'] < line_no:
                    fr['protected'] = True

# 使用检测
        used_vars = _extract_used_vars(line)
        if not used_vars:
            continue

        for used in used_vars:
            # 展开别名: 如果 used=q 且 q是p的别名, 则等价于使用了p
            resolved = _resolve_aliases(used, alias_map) | {used}
            for fr in free_records:
                ptr_base = fr['ptr_var']
                if (ptr_base in resolved
                        and fr['line_no'] < line_no
                        and not fr.get('protected')):
                    # 避免重复报告同一 free-use 对
                    dup = any(f['ptr_var'] == ptr_base
                              and f['free_line'] == fr['line_no']
                              and f['use_line'] == line_no
                              for f in findings)
                    if not dup:
                        findings.append({
                            'ptr_var': ptr_base,
                            'free_line': fr['line_no'],
                            'use_line': line_no,
                            'use_line_text': line,
                            'used_var': used,
                            'type': 'use-after-free',
                        })

# 补充: 通过全局别名检测使用
    for fr in free_records:
        ptr = fr['ptr_var']
        # 查找: 是否有 func(ptr) 调用, 且 func 内部将参数赋值给全局变量
        for call_m in re.finditer(
                rf'(\w+)\s*\([^)]*{re.escape(ptr)}[^)]*\)', source):
            callee = call_m.group(1)
            if callee in global_alias_map:
                # 该函数将参数赋值给全局变量
                for gv in global_alias_map[callee]:
                    # 在 free 之后寻找该全局变量的使用
                    free_line = fr['line_no']
                    for use_m in re.finditer(
                            rf'\b{gv}\b', source):
                        use_line = source[:use_m.start()].count('\n') + 1
                        if use_line > free_line:
                            use_line_text = lines[use_line - 1].strip() if use_line <= len(lines) else ''
                            dup = any(f['ptr_var'] == ptr
                                      and f['free_line'] == free_line
                                      and f['use_line'] == use_line
                                      for f in findings)
                            if not dup:
                                findings.append({
                                    'ptr_var': ptr,
                                    'free_line': free_line,
                                    'use_line': use_line,
                                    'use_line_text': use_line_text,
                                    'used_var': gv,
                                    'type': 'use-after-free-global-alias',
                                })

    # 汇总
    detected = len(findings) > 0
    return {
        'detected': detected,
        'findings': findings,
        'count': len(findings),
        'free_count': len(free_records),
    }

