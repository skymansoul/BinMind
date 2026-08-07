"""
C源码→伪代码IR提取器 — 从C源文件提取malloc/memcpy/赋值等关键IR行,
生成与增强检测器兼容的伪代码。Binary IR提取移至 core/ir_from_binary.py。

Ref: Ghidra decompiler output format, forward_interval_prop.py regex patterns
"""

from __future__ import annotations

import re, os
from typing import Dict, List, Optional, Set, Tuple


# Preprocessing moved to core/ir_preprocessor.py
from core.ir_preprocessor import (
    strip_comments, strip_preprocessor,
    extract_var_from_decl, normalize_declaration,
    _C_TYPES as _C_TYPES,
)

# 感兴趣的堆函数
_HEAP_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc'}
_HEAP_WRITE_FUNCS = {'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat',
                     'strncat', 'sprintf', 'snprintf', 'memset', 'bcopy'}
_HEAP_FREE_FUNCS = {'free'}

# 格式化函数 — 用于格式字符串漏洞检测
_FORMAT_FUNCS = {'printf', 'fprintf', 'dprintf', 'syslog', 'vprintf', 'vfprintf'}

# 用户输入源 — 第一个参数是输出缓冲区, 需发出隐式赋值
_INPUT_FUNCS = {'fgets', 'gets', 'scanf', 'fscanf', 'recv', 'recvfrom', 'read'}

# 常见C库函数 (非用户定义) — 调用时跳过, 避免IR噪声
_C_LIB_FUNCS = {'printf', 'fprintf', 'sprintf', 'snprintf', 'puts', 'fputs',
               'scanf', 'fscanf', 'fgets', 'gets', 'exit', 'abort', 'atexit',
               'qsort', 'bsearch', 'memset', 'memcmp', 'strcmp', 'strlen',
               'strchr', 'strrchr', 'strstr', 'strtok', 'strdup', 'strndup',
               'atoi', 'atol', 'atoll', 'strtol', 'strtoul', 'sscanf'}

_C_KW = {'if', 'for', 'while', 'do', 'else', 'return', 'goto',
         'break', 'continue', 'case', 'default', 'switch'}

# 匹配 func(buf, ...) 提取第一个参数作为隐含赋值目标
_INPUT_CALL_RE = re.compile(
    r'(fgets|gets|scanf|fscanf|recv|recvfrom|read)\s*\(\s*'
    r'(\w[\w.]*)\s*,')


# 堆操作提取 ───────────────────────────────────────────────────────

# 匹配 malloc/calloc/realloc — 提取 size 参数
_HEAP_ALLOC_CALL_RE = re.compile(
    r'(?:malloc|calloc|realloc)\s*\(\s*([^,)]*(?:\([^)]*\)[^,)]*)*)\s*[^)]*\)')

# 匹配 memcpy/strcpy/sprintf — 提取 dst, size
_HEAP_MEMCPY_RE = re.compile(
    r'(memcpy|memmove|strncpy)\s*\(\s*(\w[\w.]*)\s*,\s*[^,]*,\s*([^,)]+)\s*\)')
_HEAP_STRCPY_RE = re.compile(
    r'(strcpy|strcat|sprintf)\s*\(\s*(\w[\w.]*)\s*,')

# 匹配 unsigned/size_t/int 类型的常量赋值 (可能用作alloc/write size)
_SIZE_ASSIGN_RE = re.compile(
    r'(?:size_t|ssize_t|unsigned\s+(?:int|long|long\s+long|char|short)|'
    r'u?int(?:8|16|32|64)_t|int|long)\s+'
    r'(\w[\w.]*)\s*=\s*(\d+)\s*;')

# 匹配 if (var < N) / if (var <= N) — 路径条件
_IF_CMP_RE = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*(<|<=|>|>=|==|!=)\s*(\d+)\s*\)')

# 扩展: 匹配溢出守卫
# if (var > CONST / expr) return → var safe from overflow
# CONST can be SIZE_MAX, UINT_MAX, INT_MAX, or hex literal
_IF_MAX_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*(>|>=)\s*'
    r'(?:SIZE_MAX|UINT_MAX|INT_MAX|ULLONG_MAX|0x[0-9a-fA-F]+)\s*'
    r'/\s*(?:\([^)]*\)\s*)?(\w[\w.(]*)\s*\)')


def extract_from_source(c_source: str) -> List[str]:
    """从C源码提取堆操作相关IR行。

    Returns:
      List[str]: 伪代码IR行, 每行一条语句, 格式与增强检测器兼容
    """
    # 预处理
    s = strip_comments(c_source)
    s = strip_preprocessor(s)

    ir_lines: List[str] = []
    # 用于追踪变量—值的映射 (简单常量传播, 非完整区间分析)
    const_map: Dict[str, int] = {}
    # 追踪struct/typedef体 — 跳过结构体成员声明
    in_struct = 0  # brace depth inside struct definition

    for raw_line in s.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # 追踪struct/typedef体的花括号深度
        _struct_match = re.match(
            r'^\s*(?:typedef\s+)?struct\s+\w*.*\{', raw_line)
        if _struct_match:
            # 单行struct (如 typedef struct { int x; } Foo;) → 不进入跟踪
            _opens = raw_line.count('{')
            _closes = raw_line.count('}')
            if _opens == _closes:
                continue  # 单行定义, 跳过
            in_struct += _opens - _closes
            continue
        if in_struct > 0:
            # 统计此行中的花括号
            in_struct += raw_line.count('{') - raw_line.count('}')
            if in_struct <= 0:
                in_struct = 0
            continue

        # 跳过仅有花括号的行
        if line in ('{', '}', '{', '}'):
            continue
        # 跳过 return / goto / break / continue
        if re.match(r'^(?:return|goto|break|continue|case|default)\b', line):
            continue
        # 跳过函数声明 (仅有类型名和括号, 无=号)
        if re.match(r'^(?:void|int|char|size_t|static|extern)\s+\w+\s*\(', line):
            continue

        # 检测 heap alloc
        if any(fn in line for fn in _HEAP_ALLOC_FUNCS):
            normalized = normalize_declaration(line)
            ir_lines.append(normalized)
            continue

        # 检测 heap free
        if any(fn in line for fn in _HEAP_FREE_FUNCS):
            normalized = normalize_declaration(line)
            ir_lines.append(normalized)
            continue

        # 检测 heap write
        if any(fn in line for fn in _HEAP_WRITE_FUNCS):
            normalized = normalize_declaration(line)
            ir_lines.append(normalized)
            continue

        # 检测 format function (printf/fprintf/dprintf/syslog)
        # 用于格式字符串漏洞检测 — 保留完整调用
        if any(fn in line for fn in _FORMAT_FUNCS):
            normalized = normalize_declaration(line)
            ir_lines.append(normalized)
            continue

        # 检测用户输入源 (fgets/scanf/recv → 隐式赋值)
        # fgets(buf, ...) → 发出 "buf = fgets(...)" 用于溯源
        im = _INPUT_CALL_RE.search(line)
        if im:
            fn = im.group(1)
            arg1 = im.group(2)
            if fn in _INPUT_FUNCS and arg1 not in _C_KW:
                ir_lines.append(f'{arg1} = {fn}(...);')
                continue

        # 检测 getenv("X") 返回值
        if 'getenv' in line:
            normalized = normalize_declaration(line)
            ir_lines.append(normalized)
            continue

        # 检测用户函数调用 (用于跨函数UAF/堆溢出追踪)
        # emit: call func_name(arg1, arg2, ...);
        # 跳过已知库函数和控制关键字, 仅保留用户定义的函数调用
        _ucm = re.match(r'\s*(\w[\w.]*)\s*\(([^)]*)\)\s*;?\s*$', line)
        if _ucm and '=' not in line.split('(')[0]:
            fn = _ucm.group(1)
            if (fn not in _C_KW and fn not in _C_TYPES and
                fn not in _HEAP_ALLOC_FUNCS and fn not in _HEAP_WRITE_FUNCS and
                fn not in _HEAP_FREE_FUNCS and fn not in _FORMAT_FUNCS and
                fn not in _INPUT_FUNCS and fn not in _C_LIB_FUNCS and
                fn != 'main' and fn != 'sizeof' and 'struct' not in fn):
                ir_lines.append(f'call {fn}({_ucm.group(2)});')
                continue

        # 先规范化: 剥离C类型声明
        # 后续所有模式匹配使用规范化后的行, 避免 char *q = p 被误判为 *q 解引用
        normalized = normalize_declaration(line)

        # 检测 size 变量赋值 (如 alloc_sz = 64)
        # 提取简单的 var = number 赋值, 追踪常量
        m = _SIZE_ASSIGN_RE.match(line)  # 用原始line, 因为size声明需要类型
        if m:
            var = m.group(1)
            val = int(m.group(2))
            const_map[var] = val
            ir_lines.append(f'{var} = {val};')
            continue

        # 检测if条件 (路径约束)
        m = _IF_CMP_RE.search(normalized)
        if m:
            ir_lines.append(f'if ({m.group(1)} {m.group(2)} {m.group(3)}) goto L_cond;')
            continue

        # 检测SIZE_MAX溢出守卫
        gm = _IF_MAX_GUARD_RE.search(normalized)
        if gm:
            ir_lines.append(
                f'if ({gm.group(1)} {gm.group(2)} MAX/sizeof) return;')
            continue

        # 检测指针解引用赋值 (p->field = val; p[idx] = val)
        # 注意: 使用normalized避免C类型声明中的 * 被误判为解引用
        _PTR_USE_RE = re.compile(
            r'(?:(\w[\w.]*)\s*->\s*(\w[\w.]*)|'
            r'(\w[\w.]*)\s*\[[^\]]*\])\s*=\s*')
        pm = _PTR_USE_RE.search(normalized)
        if pm:
            ptr_name = (pm.group(1) or pm.group(3) or '')
            if ptr_name and re.match(r'^[a-zA-Z_]\w*$', ptr_name):
                ir_lines.append(f'{ptr_name}-> = ...;  /* deref write */')
                continue

        # 跳过纯声明行 (type identifier; 无赋值, 非函数调用)
        if re.match(r'^\s*(?:int|char|short|long|float|double|void|'
                    r'unsigned|signed|size_t|ssize_t|'
                    r'u?int(?:8|16|32|64)_t|'
                    r'const|static|volatile|extern|struct|enum|union)\s+',
                    normalized):
            continue

        # 指针解引用读取 (printf/条件中)
        _PTR_READ_RE = re.compile(
            r'(?:(\w[\w.]*)\s*->\s*\w[\w.]*|'
            r'(\w[\w.]*)\s*\[[^\]]*\])')
        if '=' not in normalized or normalized.strip().startswith('if'):
            rm = _PTR_READ_RE.search(normalized)
            if rm:
                ptr_name = (rm.group(1) or rm.group(2) or '')
                if ptr_name and re.match(r'^[a-zA-Z_]\w*$', ptr_name):
                    ir_lines.append(f'{ptr_name}->read;  /* deref read */')

        # 检测通用赋值 (var = expr)
        # 包括: 非const size变量(atoi), 指针别名(ptr=buf+60), 简单变量传递
        eq_pos = normalized.find('=')
        if eq_pos > 0:
            lhs = normalized[:eq_pos].strip()
            rhs = normalized[eq_pos + 1:].strip().rstrip(';')
            # 验证LHS是有效标识符
            if re.match(r'^[a-zA-Z_]\w*$', lhs):
                # 跳过 heap alloc/write/free 调用 (已在前面处理)
                if not any(fn in rhs for fn in
                          _HEAP_ALLOC_FUNCS | _HEAP_WRITE_FUNCS | _HEAP_FREE_FUNCS):
                    # 保留所有类型的右值: 常量/变量/函数调用/算术表达式
                    ir_lines.append(f'{lhs} = {rhs};')

    return ir_lines


def extract_from_file(c_path: str) -> List[str]:
    """从C源文件提取IR行。"""
    if not os.path.isfile(c_path):
        return []
    with open(c_path, 'r', encoding='utf-8', errors='replace') as f:
        source = f.read()
    return extract_from_source(source)


# Binary extraction and get_ir_lines moved to core/ir_from_binary.py

__all__ = [
    'extract_from_source', 'extract_from_file',
]
