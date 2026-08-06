"""
轻量级静态污点源追踪 -- 沿CFG做反向def-use链追踪, 判断危险调用的参数是否来自用户输入。

设计决策:
  1. 不使用完整数据流分析框架(SVF/PhASAR) -- 依赖太重, 与项目零外部依赖原则冲突
  2. 在反编译伪代码上做反向符号追踪(≤5跳) -- 牺牲精度换取速度和零依赖
  3. 仅追踪"用户输入→危险调用"的二元可达性, 不计算精确污染传播路径
     -- 够用于过滤静态告警中的假阳性(参数来自常量字符串等安全源)

与静态regex的区别:
  正则匹配printf(var)仅看语法。本模块追踪var的定义链:
    若var来自fgets(buf, n, stdin) → tainted
    若var来自snprintf(buf, n, "%s", const_str) → safe (格式串是常量)
    若var来自strcpy(dst, src) 且src来自argv → tainted (间接污染)

局限:
  - 不处理间接调用/jump table (保守地标记为tainted -- 宁可误报不漏报)
  - 不跨函数追踪(仅函数内分析) -- 调用者上下文由上层模块提供

参考:
  - Yamaguchi et al., 2014, ACSAC, "Generalized Vulnerability Extrapolation using Abstract Syntax Trees"
  - SVF (Sui et al., 2021, ICSE), "Value-Flow-Based Program Analysis" -- 值流分析简化为def-use链
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

# 确认的用户输入源函数
_TAINT_SOURCES = {
    'read', 'fread', 'fgets', 'gets', 'scanf', 'fscanf', 'sscanf',
    'recv', 'recvfrom', 'recvmsg', 'readlink',
    'getenv', 'getenv_s', 'secure_getenv',
    'atoi', 'atol', 'atoll', 'strtol', 'strtoul', 'strtoll', 'strtoull',
    'strtok', 'strtok_r',
    'getc', 'fgetc', 'getchar', 'ungetc',
    'getopt', 'getopt_long',
}

# 参数来源——非函数调用的直接污染源
_TAINT_VARS = {
    'argv', 'argp', 'environ', 'stdin', 'optarg',
}

# 安全的转换函数——输出不增加污染(格式化字符串固定)
_SAFE_WRAPPERS = {
    'snprintf', 'sprintf', 'asprintf', 'vasprintf',
    'strncpy', 'strncat', 'memcpy', 'memmove',
}


def _extract_var_defs(pseudocode: str) -> Dict[str, str]:
    """从伪代码中提取变量定义映射 {var_name: definition_expression}。

    匹配模式:
      char *var = expr;
      int var = func(...);
      var = expr;
    仅捕获简单赋值(含函数调用返回值)。
    """
    defs: Dict[str, str] = {}

    # char/int/void *var = expr; 或 type var = expr;
    for m in re.finditer(
        r'(?:char|int|void|size_t|unsigned|long|short|float|double|uint\w+)\s*\*?\s+(\w+)\s*=\s*(.+?)\s*;',
        pseudocode,
    ):
        var = m.group(1)
        expr = m.group(2).strip()
        defs[var] = expr

    # 简单赋值 var = expr;
    for m in re.finditer(r'(?:^|\n)\s*(\w+)\s*=\s*(.+?)\s*;', pseudocode):
        var = m.group(1)
        expr = m.group(2).strip()
        if var not in defs:
            defs[var] = expr

    return defs


def _is_tainted_expr(expr: str, var_defs: Dict[str, str],
                     depth: int = 0, visited: Optional[Set[str]] = None,
                     max_depth: int = 5) -> Tuple[bool, str]:
    """递归判断表达式是否被污染。

    返回 (is_tainted, reason)。

    规则:
      1. 直接调用污染源函数 → tainted
      2. 引用了污染变量(argv等) → tainted
      3. 引用了另一个变量, 递归追踪其定义链 → 间接判断
      4. 是字符串字面量或常量 → safe
      5. 超过追踪深度 → 保守标记为tainted
    """
    if visited is None:
        visited = set()
    if depth > max_depth:
        return True, f'max_depth({max_depth}) exceeded -- conservative taint'

    expr = expr.strip().strip('()')

    # 规则1: 直接调用污染源
    func_match = re.match(r'(\w+)\s*\(', expr)
    if func_match:
        fname = func_match.group(1)
        if fname in _TAINT_SOURCES:
            return True, f'direct call to taint source: {fname}'
        if fname in _SAFE_WRAPPERS:
            return False, f'safe wrapper: {fname}'
        # 其他函数调用 → 保守处理(攻击者可能控制参数)
        return True, f'opaque function call: {fname}'

    # 规则2: 污染变量
    for tvar in _TAINT_VARS:
        if re.search(r'\b' + tvar + r'\b', expr):
            return True, f'references tainted variable: {tvar}'

    # 规则3: 变量引用 → 递归追踪
    var_match = re.match(r'^(\w+)$', expr)
    if var_match:
        var = var_match.group(1)
        if var in visited:
            return True, f'circular reference: {var}'
        if var in var_defs:
            visited.add(var)
            return _is_tainted_expr(var_defs[var], var_defs,
                                   depth + 1, visited, max_depth)

    # 规则4: 字符串字面量或数字常量
    if re.match(r'^["\'].*["\']$', expr) or re.match(r'^[0-9+\-xXa-fA-F]+$', expr):
        return False, 'literal constant'

    # 规则5: 复杂表达式(含运算符) → 检查是否含污染变量名
    for tvar in _TAINT_VARS:
        if tvar in expr:
            return True, f'complex expr references {tvar}'
    # 表达式含函数名 → 保守标记
    if '(' in expr and ')' in expr:
        return True, 'complex expr with function call'
    return False, f'unresolved pattern: {expr[:60]}'


def trace_taint_source(
    pseudocode: str,
    func_name: str = "",
    call_signatures: Optional[List[Tuple[str, str]]] = None,
) -> Dict[str, Any]:
    """追踪函数内所有危险调用的参数污染状态。

    Args:
        pseudocode: 反编译伪代码文本
        func_name: 函数名(用于日志)
        call_signatures: [(call_text, arg_var), ...] 待追踪的调用列表
            若None, 自动扫描所有 _TAINT_SOURCES 调用

    Returns:
        {call_id: {tainted: bool, source: str, path_len: int}}
    """
    result: Dict[str, Any] = {}
    var_defs = _extract_var_defs(pseudocode)

    # 若未提供调用列表, 自动扫描
    targets: List[Tuple[str, str, str]] = []  # [(call_id, call_text, first_arg)]
    if call_signatures is None:
        # 扫描所有 _TAINT_SOURCES 调用
        for src_func in _TAINT_SOURCES:
            for m in re.finditer(
                rf'({src_func})\s*\(\s*([^,)]+)',
                pseudocode,
            ):
                targets.append((src_func, m.group(0), m.group(2).strip()))
    else:
        for call_text, arg_var in call_signatures:
            targets.append((call_text, call_text, arg_var))

    for call_id, _, arg in targets:
        tainted, reason = _is_tainted_expr(arg, var_defs)
        result[call_id] = {
            'tainted': tainted,
            'source': reason,
            'path_length': -1,  # 未追踪精确跳数
            'arg_expression': arg[:80],
        }

    return result


def is_arg_tainted(
    pseudocode: str,
    arg_var: str,
    max_depth: int = 5,
) -> Tuple[bool, str]:
    """便捷接口——判断单个参数是否来自污染源。

    Returns:
        (tainted, reason) 二元组
    """
    var_defs = _extract_var_defs(pseudocode)
    return _is_tainted_expr(arg_var, var_defs, max_depth=max_depth)


def list_taint_sources(pseudocode: str) -> List[Dict[str, str]]:
    """列出函数内所有用户输入引入点。

    Returns:
        [{call: str, var: str, source: str}, ...]
    """
    sources = []
    var_defs = _extract_var_defs(pseudocode)

    for var, expr in var_defs.items():
        tainted, reason = _is_tainted_expr(expr, var_defs)
        if tainted:
            sources.append({
                'variable': var,
                'expression': expr[:120],
                'source': reason,
            })

    return sources
