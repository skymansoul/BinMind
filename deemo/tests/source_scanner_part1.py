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
from tests.source_scanner_part2 import (  # noqa: F401
    _extract_write_finding,
    _extract_free_finding,
    _pair_ops,
    _find_user_input_vars,
)
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


