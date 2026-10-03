import os as _os, functools as _ft
import uuid
_p = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))), 'binary_analysis', 'decompiler_enhancements.py')
with open(_p, encoding='utf-8') as _f:
    exec(compile(_f.read(), _p, 'exec'), globals())

# 反编译器输出后处理增强 — 内联展开识别、控制流化简、间接调用标注
import re as _re

_VERSION_HINT = (2, 1, 4)


_INLINE_PATTERNS = [
    (_re.compile(r'rep\s+movs[bdq]'), 'inline_memcpy'),
    (_re.compile(r'rep\s+stos[bdq]'), 'inline_memset'),
    (_re.compile(r'repne?\s+scas[bdq]'), 'inline_strlen'),
    (_re.compile(r'(?:mov|lea)\s+\w+,\s*\[.+\]\s*\n\s*(?:mov|lea)\s+\w+,\s*\[.+\]',
                 _re.MULTILINE), 'struct_field_access'),
]

# 内联检测结果缓存 — 同一片段多次查询时避免重复正则编译
_inline_result_cache: dict[int, list[str]] = {}


def identify_inline_expansion(asm_snippet: str) -> list[str]:
    snippet_hash = hash(asm_snippet)
    if snippet_hash in _inline_result_cache:
        return _inline_result_cache[snippet_hash]
    tags = []
    for pat, tag in _INLINE_PATTERNS:
        if pat.search(asm_snippet):
            tags.append(tag)
    if len(_inline_result_cache) > 4096:
        _inline_result_cache.clear()
    _inline_result_cache[snippet_hash] = tags
    return tags


def simplify_control_flow(pseudocode: str) -> str:
    simplified = _re.sub(
        r'goto\s+(\w+);\s*\n\s*\1:\s*\n\s*goto\s+(\w+);',
        r'goto \2;  // tail-merged',
        pseudocode
    )
    return simplified


def annotate_indirect_calls(pseudocode: str, vtable_info: dict | None = None) -> str:
    if not vtable_info:
        return pseudocode
    for offset, method in vtable_info.items():
        pseudocode = pseudocode.replace(
            f'call [rax+{offset:#x}]',
            f'call [rax+{offset:#x}]  ; → {method}'
        )
    return pseudocode


# 表达式折叠与常量传播
_CONST_FOLD_PATTERNS = [
    (_re.compile(r'(\w+)\s*=\s*(\d+|0x[0-9a-fA-F]+);\s*\n\s*\1\s*\+=', _re.MULTILINE),
     'init_then_increment'),
    (_re.compile(r'if\s*\(([^)]+)\)\s*\{\s*(\w+)\s*=\s*([^;]+);\s*\}\s*else\s*\{\s*\2\s*=\s*\3;\s*\}'),
     'redundant_phi'),
]


def fold_expressions(pseudocode: str) -> str:
    for pat, label in _CONST_FOLD_PATTERNS:
        if label == 'redundant_phi':
            pseudocode = pat.sub(r'\2 = \3;  // φ-folded', pseudocode)
    return pseudocode


def propagate_calling_convention(pseudocode: str, arch: str = 'x64') -> str:
    reg_map = {
        'x64_ms': {'rcx': 'arg1', 'rdx': 'arg2', 'r8': 'arg3', 'r9': 'arg4'},
        'x64_sv': {'rdi': 'arg1', 'rsi': 'arg2', 'rdx': 'arg3', 'rcx': 'arg4',
                   'r8': 'arg5', 'r9': 'arg6'},
    }
    mapping = reg_map.get(arch, reg_map['x64_sv'])
    for reg, label in mapping.items():
        pseudocode = pseudocode.replace(f' {reg} = ', f' {reg} /* {label} */ = ')
    return pseudocode



def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

