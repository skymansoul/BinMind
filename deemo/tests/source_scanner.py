"""

C源码堆操作扫描器 —— 将 C 源码视为"反编译输出", 提取堆分配和写入模式,
传递给 GAPSBV HeapVerify 做误报过滤。

设计原则:
  - 两步匹配: 先找分配→再找写入, 关联到最近的分配
  - 保守: 不确定时默认报, 由后续验证层过滤

依赖 source_matcher.py 提供正则引擎和参数解析。
依赖 source_classifier.py 提供大小求值和分类。
"""
import re
from typing import Any, Dict, List, Optional

from tests.source_matcher import (
    WRITE_RE, ARRAY_WRITE_RE,
    match_alloc, extract_base_ptr, extract_macros, find_nearest_alloc,
)
from tests.source_classifier import eval_size as _eval_size, \
    compute_glibc_effective as _compute_glibc_effective, classify_finding  # noqa: F401
from tests.source_scanner_helpers import (  # noqa: F401
    _extract_multiline_writes,
    _extract_deref_writes,
    _find_return_alloc_funcs,
    _extract_cross_func_allocs,
)


def extract_heap_ops_c(source: str) -> List[Dict[str, Any]]:
    """从C源码提取所有堆操作 (分配+写入) 及上下文。

    返回: [{type, ptr_var, func, line_no, line, alloc_size, write_size, ...}, ...]
    """
    macros = extract_macros(source)
    lines = source.splitlines()
    alloc_list: List[Dict] = []
    # 用户输入变量追踪
    user_vars = _find_user_input_vars(source)

# 多行写入: 用全源扫描捕获跨行函数调用
    findings = []
    _extract_multiline_writes(source, findings, macros)

# 指针解引用写入: *(type*)(ptr+off)=val
    _extract_deref_writes(source, findings, macros)

    # ── 阶段0: 预扫描 — 找到 return malloc 的函数 → 跨函数分配映射 ──
    return_alloc_funcs = _find_return_alloc_funcs(source)
    # ── 阶段0b: 预扫描 — 找到 ptr = ret_alloc_func(args) 模式 (跨函数分配调用) ──
    _extract_cross_func_allocs(source, alloc_list, return_alloc_funcs, macros)

    # ── 阶段0c: 跨函数写入追踪 — f(heap_ptr, sz) 且 f 内部写参数 ──
    from tests.cross_func_write import (  # noqa: E402
        build_param_write_map, detect_cross_func_writes)
    param_write_map = build_param_write_map(source)
    # 延迟到分配检测完成后执行 (需 alloc_list 已填充)
    # detect_cross_func_writes 在配对前调用

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith('//') or line.startswith('/*') or line.startswith('*'):
            continue
        if line.startswith('#'):
            continue
        line_no = i + 1

# 分配检测
        alloc = match_alloc(line)
        if alloc:
            ptr_var = alloc['ptr_var']
            # return_alloc 已在阶段0处理, 跳过
            if alloc.get('alloc_type') == 'return_alloc':
                continue
            # 结构体成员分配 (op->data) 记录基指针供写入侧匹配
            base = extract_base_ptr(ptr_var) if ptr_var else ptr_var
            alloc_list.append({
                'ptr_var': ptr_var,
                'base_ptr': base,
                'func': alloc['func'],
                'size_expr': alloc['size_expr'],
                'line_no': line_no,
                'line': line,
            })
            continue

# 写入检测
        wm = WRITE_RE.search(line)
        if wm:
            func = wm.group(1).lower()
            args_str = wm.group(2)
            args = _parse_args_wrapper(args_str)
            _extract_write_finding(line, line_no, func, args, findings, macros)

# 数组索引写入
        aw = ARRAY_WRITE_RE.search(line)
        if aw:
            idx_var = aw.group(2)
            findings.append({
                'type': 'array_write', 'func': 'array_store',
                'ptr': aw.group(1), 'idx_var': idx_var,
                'write_size': 1, 'size_expr': '1',
                'line_no': line_no, 'line': line,
                'user_controlled': idx_var in user_vars,
            })

# free 检测
        _extract_free_finding(line, line_no, alloc_list, findings)

    # ── 阶段0c(延迟): 跨函数写入检测 (需 alloc_list 已由逐行扫描填充) ──
    detect_cross_func_writes(source, alloc_list, findings, param_write_map)

    # ── 阶段0d: 别名传播 — var = other_var / var = ptr->field 的映射 ──
    alias_map = _build_alias_map(source)

# 配对: 将写入关联到最近分配 (含别名追踪)
    paired = _pair_ops(findings, alloc_list, macros, source, alias_map)

# 后处理: 值范围传播过滤 (C源码级, 轻量)
    # 仅对 is_overflow=True 的候选做 SAFE 降级, 不改变确认漏洞
    from tests.post_filter import apply_post_filter
    paired = apply_post_filter(paired, source)

    return paired


def _parse_args_wrapper(args_str: str) -> List[str]:
    """内联简易参数解析 (避免循环导入)。"""
    from tests.source_matcher import _parse_args
    return _parse_args(args_str)


_ALIAS_RE = re.compile(
    r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*(?:\s*->\s*\w[\w\d_]*|\s*\.\s*\w[\w\d_]*)?)\s*;'
)


def _build_alias_map(source: str) -> Dict[str, str]:
    """构建简单别名映射: var = other_var / var = ptr->field.

    用于追踪 dangling = reg->buf 的别名关系,
    使配对时能通过别名链找到原始堆分配。
    """
    alias_map: Dict[str, str] = {}
    for m in _ALIAS_RE.finditer(source):
        lhs = m.group(1)
        rhs = m.group(2).strip()
        # 跳过 malloc/calloc/realloc 调用 (这些是分配, 非别名)
        if any(fn in rhs for fn in ('malloc', 'calloc', 'realloc')):
            continue
        # 跳过函数调用 (rhs 含括号)
        if '(' in rhs:
            continue
        # 跳过常量赋值
        if re.match(r'^\d+$', rhs):
            continue
        alias_map[lhs] = rhs
    return alias_map



"""
C源码堆操作扫描器辅助函数集 — write finding构造 / free检测 / 配对 / 用户输入追踪。

保持单一职责
"""
import re
from typing import Any, Dict, List, Optional

from tests.source_matcher import (
    WRITE_RE, ARRAY_WRITE_RE,
    match_alloc, extract_base_ptr, extract_macros, find_nearest_alloc,
)
from tests.source_classifier import (
    eval_size as _eval_size,
    compute_glibc_effective as _compute_glibc_effective,
    classify_finding,
)
from tests.source_scanner_helpers import (
    _find_return_alloc_funcs,
    _extract_cross_func_allocs,
    _extract_multiline_writes,
    _extract_deref_writes,
)
from tests.loop_analyzer import (
    _aggregate_loop_writes,
    _detect_off_by_one,
)


def _extract_write_finding(line: str, line_no: int, func: str,
                           args: List[str], findings: List[Dict],
                           macros: dict = None):
    """从 WRITE_RE 匹配结果构造 finding entry。"""
    if func not in ('memcpy', 'memmove', 'memset', 'strcpy', 'strncpy',
                    'strcat', 'strncat', 'sprintf', 'snprintf'):
        return
    if len(args) < 1:
        return
    ptr_expr = args[0].strip()
    base_ptr = extract_base_ptr(ptr_expr)

    for existing in findings:
        if (existing.get('line_no') == line_no
                and existing.get('ptr') == base_ptr
                and existing.get('func') == func):
            return

    write_size = 0
    size_expr = ''
    if func in ('memcpy', 'memmove', 'strncpy', 'strncat', 'snprintf'):
        if len(args) >= 3:
            size_expr = args[2].strip()
            write_size = _eval_size(size_expr, macros)
    elif func == 'memset':
        if len(args) >= 3:
            size_expr = args[2].strip()
            write_size = _eval_size(size_expr, macros)
    elif func in ('strcpy', 'strcat', 'sprintf'):
        write_size = 999999

    findings.append({
        'type': 'write', 'func': func,
        'ptr': base_ptr, 'ptr_full': ptr_expr,
        'write_size': write_size, 'size_expr': size_expr,
        'line_no': line_no, 'line': line,
    })


def _extract_free_finding(line: str, line_no: int,
                          alloc_list: List[Dict], findings: List[Dict]):
    """匹配 free(ptr) 并构造 UAF entry (如果已分配)。"""
    free_m = re.search(r'free\s*\(\s*(\w[\w\d_]*)\s*\)\s*;', line)
    if free_m:
        ptr = free_m.group(1)
        if find_nearest_alloc(alloc_list, ptr, line_no):
            findings.append({
                'type': 'free', 'func': 'free',
                'ptr': ptr, 'line_no': line_no, 'line': line,
            })


def _pair_ops(findings: List[Dict], alloc_list: List[Dict],
              macros: Dict[str, int], source: str = '',
              alias_map: Dict[str, str] = None) -> List[Dict]:
    """将写入/free 配对到最近分配, 计算溢出判定。

    配对策略 (按优先级):
      1. 完整表达式精确匹配: ptr_full (op->data) == alloc ptr_var (op->data)
      2. 基指针匹配: ptr (op) 匹配 alloc ptr_var (op->data) 或 base_ptr (op)
      3. 简单名匹配: ptr (op) == alloc ptr_var (op)
      4. 别名链追踪: ptr (dangling) → alias_map[dangling] (reg->buf) → 递归 1-3
    """
    paired = []
    alias_map = alias_map or {}
    for f in findings:
        if f['type'] in ('write', 'array_write'):
            ptr_full = f.get('ptr_full', '')
            ptr = f['ptr']
            alloc = None
            if ptr_full:
                alloc = find_nearest_alloc(alloc_list, ptr_full, f['line_no'])
            if alloc is None:
                alloc = find_nearest_alloc(alloc_list, ptr, f['line_no'])
            if alloc is None and ptr in alias_map:
                alias_target = alias_map[ptr]
                for _ in range(3):
                    alloc = find_nearest_alloc(alloc_list, alias_target, f['line_no'])
                    if alloc is not None:
                        break
                    if alias_target in alias_map:
                        alias_target = alias_map[alias_target]
                    else:
                        break
            if alloc:
                candidate = {
                    'ptr_var': ptr,
                    'alloc_func': alloc['func'],
                    'alloc_size_expr': alloc['size_expr'],
                    'alloc_line': alloc['line_no'],
                    'alloc_line_text': alloc['line'],
                    'write_func': f['func'],
                    'write_size': f['write_size'],
                    'write_size_expr': f['size_expr'],
                    'write_line': f['line_no'],
                    'write_line_text': f['line'],
                    'type': f['type'],
                    'idx_var': f.get('idx_var', ''),
                    'user_controlled': f.get('user_controlled', False),
                }
                req_size = _eval_size(alloc['size_expr'], macros)
                eff_size = _compute_glibc_effective(req_size) if req_size > 0 else 0
                candidate['alloc_requested'] = req_size
                candidate['alloc_effective'] = eff_size
                if eff_size > 0 and f['write_size'] > 0:
                    candidate['is_overflow'] = f['write_size'] > eff_size
                else:
                    candidate['is_overflow'] = True
                paired.append(candidate)

    for f in findings:
        if f['type'] == 'free':
            ptr = f['ptr']
            alloc = find_nearest_alloc(alloc_list, ptr, f['line_no'])
            if alloc:
                paired.append({
                    'ptr_var': ptr,
                    'alloc_func': alloc['func'],
                    'alloc_size_expr': alloc['size_expr'],
                    'alloc_line': alloc['line_no'],
                    'alloc_line_text': alloc['line'],
                    'write_func': 'use-after-free',
                    'write_size': 0, 'write_line': f['line_no'],
                    'write_line_text': f['line'],
                    'type': 'uaf', 'is_overflow': False,
                    'alloc_effective': 0,
                })
    paired = _aggregate_loop_writes(paired, source)
    paired = _detect_off_by_one(paired, source)
    return paired


_USER_INPUT_SRC_RE = re.compile(
    r'(\w+)\s*=\s*(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull)\s*\('
    r'|(\w+)\s*=\s*argv\['
    r'|(\w+)\s*=\s*getenv\s*\('
    r'|(?:f?scanf)\s*\([^)]*"[^"]*"[^)]*&(\w+)'
    r'|fgets\s*\(\s*(\w+)\s*,'
    r'|recv\s*\([^,]+,\s*(\w+)\s*,',
)


def _find_user_input_vars(source: str) -> set:
    """追踪用户/外部输入变量名 (来自 atoi/argv/scanf/getenv/fgets/recv)。"""
    uv = set()
    for m in re.finditer(
            r'(\w+)\s*=\s*(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull)\s*\(',
            source):
        uv.add(m.group(1))
    for m in re.finditer(r'(\w+)\s*=\s*argv\[', source):
        uv.add(m.group(1))
    for m in re.finditer(r'(\w+)\s*=\s*getenv\s*\(', source):
        uv.add(m.group(1))
    for m in re.finditer(r'(?:f?scanf)\s*\([^)]*"[^"]*"[^)]*&(\w+)', source):
        uv.add(m.group(1))
    for m in re.finditer(r'fgets\s*\(\s*(\w+)\s*,', source):
        uv.add(m.group(1))
    for m in re.finditer(r'recv\s*\([^,]+,\s*(\w+)\s*,', source):
        uv.add(m.group(1))
    for m in re.finditer(r'(\w+)\s*=\s*[^?]+\?\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(?:atoi|atol|strtol)\s*\(\s*argv\[', source):
        uv.add(m.group(1))
    for m in re.finditer(r'(\w+)\s*=\s*(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull)\s*\(', source):
        uv.add(m.group(1))
    return uv
