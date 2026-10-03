"""
C源码模式匹配 —— 正则模式和解析辅助函数.

只包含纯函数和正则定义, 不包含分析入口逻辑.

设计决策:
  用括号深度计数提取 alloc 参数, 而非单纯正则.
  正则无法处理 sizeof(type) 中的嵌套括号, 以及 realloc 的第二参数.
  深度计数方案: 找到 malloc( 后, 逐字符扫描计数 ( 和 ) 深度,
  深度归零时即找到匹配的 ), 中间的字符串按逗号分割得参数列表.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


# 分配点检测正则 (仅检测起始位置, 不提取参数)

_DECL_ALLOC_START = re.compile(
    r'(?:const\s+)?(?:unsigned\s+)?'
    r'(?:void|char|int|long|short|uint8_t|uint32_t|uint64_t|'
    r'size_t|ssize_t|struct\s+\w+|\w+_t)\s*\*+\s*'
    r'(\w+)\s*=\s*'
    r'(?:\([^)]*\*\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(',
    re.IGNORECASE,
)

_ASSIGN_ALLOC_START = re.compile(
    r'(\w+)\s*=\s*'
    r'(?:\([^)]*\*\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(',
    re.IGNORECASE,
)

# 写入点正则

_STORE_PAT_DIRECT = re.compile(
    r'(?:memcpy|memset|memmove|strcpy|strncpy|sprintf|snprintf)\s*\(\s*'
    r'(\w+(?:->\w+)?)', re.IGNORECASE,
)

_STORE_PAT_ARROW = re.compile(
    r'(\w+)\s*\[\s*(\d+|\w+)\s*\]\s*=', re.IGNORECASE,
)

_STORE_PAT_DEREF = re.compile(
    r'\*\s*\(\s*(?:unsigned\s+)?(?:char|int|long|void)\s*\*\s*\)\s*'
    r'\(\s*(\w+)\s*\+\s*(\d+)\s*\)\s*=',
    re.IGNORECASE,
)

_STORE_PAT_PTR_ARITH = re.compile(
    r'\*\s*\(\s*(\w+)\s*\+\s*(\d+)\s*\)\s*=',
    re.IGNORECASE,
)

# 循环边界正则

_LOOP_BOUND_PAT = re.compile(
    r'for\s*\(\s*(?:int|unsigned|size_t)\s+\w+\s*=\s*(\d+)\s*;\s*'
    r'\w+\s*[<]=?\s*(\w+)\s*;\s*\w+\s*\+\+\s*\)',
    re.IGNORECASE,
)

_ATOI_PAT = re.compile(r'(?:atoi|atol|strtol|strtoul)\s*\(\s*(\w+)\s*\)')

# 常量赋值: int var = NUMBER;
_CONST_ASSIGN_PAT = re.compile(
    r'(?:int|unsigned|size_t|long|short|char)\s+(\w+)\s*=\s*(\d+)\s*;',
    re.IGNORECASE,
)

# 纯赋值: var = NUMBER;
_PURE_ASSIGN_PAT = re.compile(
    r'(\w+)\s*=\s*(\d+)\s*;',
)

# sizeof 常见类型查找表
# 不能用编译器 sizeof, 只能硬编码常见类型在 x86_64 LP64 下的值
_SIZEOF_TABLE: Dict[str, int] = {
    'char': 1, 'unsigned char': 1,
    'short': 2, 'unsigned short': 2,
    'int': 4, 'unsigned int': 4,
    'long': 8, 'unsigned long': 8,
    'long long': 8, 'unsigned long long': 8,
    'float': 4, 'double': 8,
    'void*': 8, 'char*': 8, 'int*': 8,
    'size_t': 8, 'ssize_t': 8,
    'int32_t': 4, 'uint32_t': 4,
    'int64_t': 8, 'uint64_t': 8,
}

# 任何用户输入模式 (不限定变量名)
_ANY_USER_INPUT_PAT = re.compile(
    r'(?:atoi|atol|strtol|strtoul)\s*\(|argv\[|getenv\s*\(|scanf\s*\(|fgets\s*\(|read\s*\(',
    re.IGNORECASE,
)


# 括号深度计数参数提取

def _extract_alloc_args(line: str, paren_start: int) -> List[str]:
    """从 malloc( 的左括号位置提取参数列表.

    处理 sizeof(int) 等嵌套括号, 深度计数而非简单正则.
    """
    depth = 0
    args_start = paren_start  # 指向 '('
    i = paren_start
    while i < len(line):
        ch = line[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                args_str = line[args_start + 1:i]
                return [a.strip() for a in args_str.split(',')]
        i += 1
    return []


# 统一分配调用解析

def parse_alloc_call(
    line: str, is_decl: bool
) -> Optional[Tuple[str, str, int, bool, str]]:
    """解析分配调用, 返回 (变量名, alloc_func, size, is_dynamic, size_expr).

    处理 realloc(ptr, size) 取第二参数; calloc(n, size) 计算乘积.
    size_expr 保留原始size表达式 (如 "size", "n*4"), 供约束收集器使用.
    无法解析返回 None.
    """
    pat = _DECL_ALLOC_START if is_decl else _ASSIGN_ALLOC_START
    m = pat.search(line)
    if not m:
        return None

    var = m.group(1)
    func = m.group(2).lower()
    args = _extract_alloc_args(line, m.end() - 1)  # m.end() 在 '(' 后

    if not args:
        return None

    if func == 'realloc':
        # realloc(ptr, newsize) — 大小在第二参数
        if len(args) >= 2:
            size, is_dyn = parse_size(args[1])
            size_expr = args[1] if is_dyn else ""
            return (var, func, size, is_dyn, size_expr)
        return None

    if func == 'calloc':
        # calloc(nmemb, size) — 尝试计算乘积
        if len(args) >= 2:
            n, n_dyn = parse_size(args[0])
            s, s_dyn = parse_size(args[1])
            size_expr = f"{args[0]}*{args[1]}" if (n_dyn or s_dyn) else ""
            if n_dyn or s_dyn:
                return (var, func, 0, True, size_expr)
            return (var, func, n * s, False, "")
        return None

    # malloc(size) — 大小在第一参数
    size, is_dyn = parse_size(args[0])
    size_expr = args[0] if is_dyn else ""
    return (var, func, size, is_dyn, size_expr)


# 常量传播

def resolve_constant(var: str, lines: List[str], max_line: int) -> int:
    """简单常量传播: 在 max_line 之前查找 var=NUMBER 的赋值.

    只追踪一步 (single-def), 不做多跳.
    """
    for i in range(max_line - 1, max(-1, max_line - 30), -1):
        line = lines[i]
        # const 声明: int var = N;
        m = _CONST_ASSIGN_PAT.search(line)
        if m and m.group(1) == var:
            try:
                return int(m.group(2), 0)
            except ValueError:
                pass
        # 纯赋值: var = N;
        m2 = _PURE_ASSIGN_PAT.search(line)
        if m2 and m2.group(1) == var:
            try:
                return int(m2.group(2), 0)
            except ValueError:
                pass
    return -1


# 大小表达式解析

def _resolve_sizeof(match: re.Match) -> str:
    """将 sizeof(type) 替换为实际数值. 查表解析常见类型."""
    inner = match.group(1).strip()
    # 去除前缀修饰符: unsigned, const, struct
    cleaned = re.sub(r'\b(?:unsigned|signed|const|struct)\s+', '', inner)
    cleaned = re.sub(r'\s*\*+\s*', '*', cleaned)  # 规范化指针
    if cleaned in _SIZEOF_TABLE:
        return str(_SIZEOF_TABLE[cleaned])
    # 带 _t 后缀的类型通常是 4 或 8 字节 typedef, 保守取 4
    if cleaned.endswith('_t') or cleaned.startswith('uint') or cleaned.startswith('int'):
        return '4'
    return '1'


def parse_size(size_str: str) -> Tuple[int, bool]:
    """解析 size 表达式. 返回 (常量值, 是否动态).

    支持: 字面量 (64, 0x40), 简单算术 (n*4+8), sizeof 替换.
    """
    size_str = size_str.strip()
    if not size_str:
        return 0, True

    # 纯数字
    try:
        return int(size_str, 0), False
    except (ValueError, TypeError):
        pass

    # sizeof(type) — 查表解析而非替换为占位符
    try:
        resolved = re.sub(
            r'sizeof\s*\(([^)]+)\)', _resolve_sizeof, size_str,
        )
        if re.match(r'^[\d\s+*/\-()]+$', resolved):
            val = eval(resolved, {"__builtins__": {}}, {})
            if isinstance(val, (int, float)) and val == int(val):
                return int(val), False
    except Exception:
        pass

    return 0, True


# 循环边界推断

def infer_loop_bound(lines: List[str], start_pc: int) -> int:
    """推断循环上界. 搜索 for(i=0; i<BOUND; i++) 模式.

    若 BOUND 是数字直接返回; 若是变量名则尝试常量传播.
    """
    end = min(len(lines), start_pc + 20)
    for i in range(start_pc, end):
        m = _LOOP_BOUND_PAT.search(lines[i])
        if m:
            bound_str = m.group(2)
            try:
                return int(bound_str, 0)
            except ValueError:
                pass
            # 变量名 → 尝试常量解析
            resolved = resolve_constant(bound_str, lines, i)
            if resolved > 0:
                return resolved
    return -1


# 用户输入检测

def is_user_controlled(var: str, lines: List[str]) -> bool:
    """启发式检查变量是否来自用户输入.

    同时检查: (1) 变量名直接出现在输入行; (2) 函数中存在任意用户输入源
    (用于动态分配大小的保守判断).
    """
    for line in lines:
        if _ATOI_PAT.search(line) and var in line:
            return True
        if ('argv[' in line or 'getenv' in line or 'scanf' in line
                or 'fgets' in line or 'read(' in line) and var in line:
            return True
    return False


def has_any_user_input(lines: List[str]) -> bool:
    """检查函数中是否存在任何用户输入源 (不限定变量名)."""
    for line in lines:
        if _ANY_USER_INPUT_PAT.search(line):
            return True
    return False


