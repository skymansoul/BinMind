"""
整数值范围传播 -- 沿赋值链传播数值区间, 收紧溢出检测的边界。

设计理由:
  检测 malloc(width * height) 是否溢出, 需要知道 width 和 height 的
  可能取值范围。若 width 来自 strlen(input)[0..65536] 且 height 来自
  常量 4, 则乘积范围 [0..262144] 远小于 INT_MAX, 不可能溢出。
  本模块沿函数内的赋值链传播这些区间信息。

方法:
  1. 扫描所有整数赋值语句, 建立变量→表达式映射
  2. 从污染源(strlen/atoi等)注入初始区间
  3. 沿赋值图传播区间(加/减/乘/除/左移运算的区间传播)
  4. 对溢出检测点, 查询操作数的合并区间, 判断是否真可能溢出

局限:
  循环变量不处理(需循环不变量分析, 代价太高)
  跨函数传播需要调用图(当前仅单函数内)
"""
import re
from typing import Dict, List, Optional, Tuple

# 污染源默认区间
_SOURCE_RANGES = {
    'strlen': (0, 65536),
    'strnlen': (0, 65536),
    'atoi': (-2**31, 2**31 - 1),
    'atol': (-2**63, 2**63 - 1),
    'strtol': (-2**63, 2**63 - 1),
    'strtoul': (0, 2**64 - 1),
    'sizeof': None,  # 动态计算
    'read': (0, 2**31 - 1),
    'fread': (0, 2**31 - 1),
    'recv': (0, 65536),
}

def _extract_assign_graph(pseudocode: str) -> Dict[str, str]:
    """提取所有整数相关赋值 {var: rhs_expression}。"""
    assigns = {}
    patterns = [
        r'(?:int|long|size_t|ssize_t|uint\w*|unsigned\s+int|unsigned\s+long)\s+(\w+)\s*=\s*(.+?)\s*;',
        r'(?:int|long|size_t|ssize_t|uint\w*)\s+(\w+)\s*=\s*(.+?)\s*;',
    ]
    for pat in patterns:
        for m in re.finditer(pat, pseudocode):
            var, expr = m.group(1), m.group(2).strip()
            if var not in assigns:
                assigns[var] = expr
    # 简单赋值 (var = expr;)
    for m in re.finditer(r'^(\w+)\s*=\s*(.+?)\s*;', pseudocode, re.MULTILINE):
        var, expr = m.group(1), m.group(2).strip()
        if var not in assigns and not expr.startswith('"'):
            assigns[var] = expr
    return assigns

def _eval_range(expr: str, assigns: Dict[str, str],
                cache: Dict[str, Tuple[int,int]],
                depth: int = 0) -> Optional[Tuple[int, int]]:
    """递归求值表达式的数值区间。返回 None 表示无法确定。"""
    if depth > 8: return None
    expr = expr.strip()

    # 缓存
    if expr in cache: return cache[expr]

    # 字面量
    try: v = int(expr); r = (v, v); cache[expr] = r; return r
    except ValueError: pass

    # 污染源函数
    src_match = re.match(r'(strlen|strnlen|atoi|atol|strtol|strtoul|read|fread|recv)\s*\(', expr)
    if src_match:
        r = _SOURCE_RANGES.get(src_match.group(1))
        if r: cache[expr] = r; return r

    # sizeof(type)
    sz_match = re.match(r'sizeof\s*\(\s*(\w+)\s*\)', expr)
    if sz_match:
        sizes = {'int':4,'long':8,'char':1,'short':2,'float':4,'double':8,'void':1}
        s = sizes.get(sz_match.group(1), 4); r = (s, s); cache[expr] = r; return r

    # 二元运算
    for op, fn in [('*', lambda a,b: (min(a[0]*b[0],a[0]*b[1],a[1]*b[0],a[1]*b[1]),
                                      max(a[0]*b[0],a[0]*b[1],a[1]*b[0],a[1]*b[1]))),
                   ('+', lambda a,b: (a[0]+b[0], a[1]+b[1])),
                   ('-', lambda a,b: (a[0]-b[1], a[1]-b[0]))]:
        m = re.match(rf'(.+)\s*\{op}\s*(.+)', expr)
        if m:
            lo = _eval_range(m.group(1).strip(), assigns, cache, depth+1)
            ro = _eval_range(m.group(2).strip(), assigns, cache, depth+1)
            if lo and ro:
                r = fn(lo, ro); cache[expr] = r; return r

    # 变量引用
    if re.match(r'^\w+$', expr) and expr in assigns:
        return _eval_range(assigns[expr], assigns, cache, depth+1)

    return None

def propagate_ranges(pseudocode: str) -> Dict[str, Tuple[int, int]]:
    """传播所有变量的值范围。返回 {var: (lo, hi)}。"""
    assigns = _extract_assign_graph(pseudocode)
    cache = {}
    for var in assigns:
        _eval_range(var, assigns, cache)
    # 筛选出成功推断的变量
    return {k: v for k, v in cache.items() if re.match(r'^\w+$', k) and v is not None}

def filter_by_range(findings: List[Dict], pseudocode: str) -> List[Dict]:
    """用值范围过滤整数溢出告警。

    若乘积/加法的结果区间完全在类型安全范围内 → 过滤。
    """
    ranges = propagate_ranges(pseudocode)
    for f in findings:
        expr = f.get('expression', '')
        # 尝试对表达式整体做区间估计
        r = _eval_range(expr, _extract_assign_graph(pseudocode), {})
        if r:
            lo, hi = r
            # size_t 最大值
            if hi <= 2**31 - 1:  # 完全在安全范围
                f['confidence'] = round(f.get('confidence', 0.5) * 0.30, 3)
                f['range_check'] = f'safe_range:[{lo},{hi}]≤INT32_MAX'
                continue
            if lo > 2**31 - 1:  # 确定溢出
                f['confidence'] = max(0.90, f.get('confidence', 0.5))
                f['range_check'] = f'confirmed_overflow:[{lo},{hi}]>INT32_MAX'
            else:
                f['range_check'] = f'possible_overflow:[{lo},{hi}]crosses_INT32_MAX'
        else:
            f['range_check'] = 'unknown_range'

    return findings
