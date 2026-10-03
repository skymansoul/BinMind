# ir_preprocessor.py - C源码预处理：剥离注释与预处理指令，归一化声明，供IR提取

from __future__ import annotations
import re

_BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)
_LINE_COMMENT_RE = re.compile(r'//[^\n]*')
_PREPROC_RE = re.compile(
    r'^\s*#\s*(?:include|define|ifdef|ifndef|if\s|endif|else|pragma|error).*$',
    re.MULTILINE)

_C_TYPES = {
    'int', 'char', 'short', 'long', 'float', 'double', 'void',
    'unsigned', 'signed', 'size_t', 'ssize_t', 'uint8_t', 'uint16_t',
    'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'const', 'static', 'volatile', 'extern', 'register', 'struct',
    'BOOL', 'BYTE', 'WORD', 'DWORD',
}


def strip_comments(source: str) -> str:
    """移除C注释 (块注释+行注释)。"""
    s = _BLOCK_COMMENT_RE.sub('', source)
    s = _LINE_COMMENT_RE.sub('', s)
    return s


def strip_preprocessor(source: str) -> str:
    """移除预处理指令。"""
    return _PREPROC_RE.sub('', source)


def extract_var_from_decl(lhs: str) -> str:
    """从C声明左侧提取变量名: 'size_t alloc_sz' → 'alloc_sz'"""
    tokens = re.split(r'[\s\*&]+', lhs.strip())
    for tok in reversed(tokens):
        if not tok:
            continue
        if tok in _C_TYPES:
            continue
        if re.match(r'^[a-zA-Z_]\w*$', tok):
            return tok
    for tok in reversed(tokens):
        if tok and re.match(r'^[a-zA-Z_]\w*$', tok):
            return tok
    return ""


def normalize_declaration(line: str) -> str:
    """剥离C类型声明, 只保留 var = expr 形式的赋值。
    'size_t alloc_sz = 64;' → 'alloc_sz = 64;'
    'char *buf = (char *)malloc(alloc_sz);' → 'buf = malloc(alloc_sz);'
    """
    stripped = line.strip().rstrip(';')
    if re.match(r'^\s*(?:if|while|for|return|switch)\b', stripped):
        return stripped
    eq_pos = stripped.find('=')
    if eq_pos < 0:
        return stripped
    lhs = stripped[:eq_pos].strip()
    rhs = stripped[eq_pos + 1:].strip()
    var = extract_var_from_decl(lhs)
    if var:
        return f'{var} = {rhs};'
    return stripped


__all__ = [
    'strip_comments', 'strip_preprocessor',
    'extract_var_from_decl', 'normalize_declaration',
    '_C_TYPES',
]
