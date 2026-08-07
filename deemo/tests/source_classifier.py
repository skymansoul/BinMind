"""
GAPSBV 发现分类器 —— 对 source_scanner 提取的候选进行判定。
保守策略: 仅当静态分析能证明安全时才返回 SAFE。
动态索引、变量尺寸等无法静态确定的 → UNCERTAIN。

依赖 source_scanner.py 的 _eval_size, _compute_glibc_effective。
"""
import re
from typing import Any, Dict


def classify_finding(f: Dict) -> str:
    """判定单个发现: OVERFLOW / SAFE / UNCERTAIN。

    保守策略: 仅当静态分析能证明安全时才返回 SAFE。
    动态索引、变量尺寸等无法静态确定的 → UNCERTAIN。
    """
    req = f.get('alloc_requested', 0)
    eff = f.get('alloc_effective', 0)
    ws = f.get('write_size', 0)
    write_func = f.get('write_func', '')
    write_type = f.get('type', '')

    # UAF是独立漏洞类型, 不应在堆溢出管线中报出
    if write_type == 'uaf' or write_func == 'use-after-free':
        return 'SAFE'
    # 循环聚合写入: source_scanner 已判定为溢出 (ws=循环总次数)
    if write_func == 'loop_array_store' and f.get('is_overflow'):
        return 'OVERFLOW'
    # 动态写入: array_store 到变量索引、strcpy/gets 无法确定实际写入量
    if write_func in ('strcpy', 'strcat', 'sprintf', 'gets'):
        return 'UNCERTAIN'  # 无法静态确定写入大小
    if write_type == 'array_write' and ws <= 1:
        # 用户控制索引: buf[user_input] → 索引值不受限 → 可能越界
        if f.get('user_controlled'):
            return 'UNCERTAIN'
        # is_overflow 已由 source_scanner 的 _pair_ops 判定
        # 若 eff>0 且 ws<=eff → is_overflow=False → 安全
        if eff > 0 and ws <= eff:
            return 'SAFE'
        # 无法确定分配大小时保守报
        if eff <= 0:
            return 'UNCERTAIN'
        return 'OVERFLOW' if ws > eff else 'UNCERTAIN'
    if f.get('is_overflow') is None:
        return 'UNCERTAIN'

    if eff > 0 and ws > 0:
        if ws <= eff:
            return 'SAFE'
        elif req > 0 and ws <= req:
            return 'SAFE'
        else:
            return 'OVERFLOW'
    # ws == 0 表示变量驱动的尺寸 → 无法静态确定
    if ws == 0:
        return 'UNCERTAIN'
    return 'UNCERTAIN'


# 大小求值 & 分配器语义 (从 source_scanner 提取, 减小文件粒度)

_SIZE_NUM_RE = re.compile(r'\b(\d+)\b')


def eval_size(expr: str, macros: dict = None) -> int:
    """尝试求值 size 表达式为整数。支持 #define 宏展开。"""
    expr = re.sub(r'\(\s*(?:size_t|unsigned(?:\s+int)?|int|long|uint\w+_t)\s*\)\s*', '', expr)
    expr = expr.strip()
    # 去掉外层多余括号: ((expr)) → expr (与 source_matcher._clean_size_expr 一致)
    while expr.startswith('(') and expr.endswith(')'):
        depth = 0
        ok = True
        for i, ch in enumerate(expr):
            if ch == '(': depth += 1
            elif ch == ')': depth -= 1
            if depth == 0 and i < len(expr) - 1:
                ok = False
                break
        if ok:
            expr = expr[1:-1].strip()
        else:
            break
    if not expr:
        return 0
    # 宏展开: BUF_SIZE → 32 等
    if macros:
        for name, val in macros.items():
            expr = re.sub(r'\b' + re.escape(name) + r'\b', str(val), expr)
    # 检查纯变量名引用
    if re.match(r'^[a-zA-Z_]\w*$', expr):
        return 0  # 纯变量 (非宏), 无法静态确定
    # 尝试计算常量表达式: N * M, N + M, sizeof(T)
    try:
        expr_eval = re.sub(r'sizeof\s*\(\s*\w+\s*\*?\s*\)', '8', expr)
        expr_eval = re.sub(r'sizeof\s*\(\s*\w+\s*\)', '4', expr_eval)
        return abs(int(eval(expr_eval, {"__builtins__": {}})))
    except Exception:
        pass
    # 检查是否有未解析的变量名: len * 2 → len是变量 → 返回0
    idents = re.findall(r'[a-zA-Z_]\w*', expr)
    for ident in idents:
        if not ident.isdigit():
            try:
                int(ident)
            except ValueError:
                return 0  # 存在非宏变量 → 无法静态确定
    # 纯常量表达式: 仅提取数字部分
    nums = _SIZE_NUM_RE.findall(expr)
    if nums:
        val = int(nums[0])
        if '*' in expr and len(nums) >= 2:
            val = int(nums[0]) * int(nums[1])
        return val
    return 0


def compute_glibc_effective(requested: int) -> int:
    """glibc ptmalloc2 有效大小。"""
    if requested <= 0:
        return 0
    MIN_CHUNK = 0x20   # 32
    MALLOC_ALIGN = 0x10  # 16
    OVERHEAD = 8
    chunk = max(MIN_CHUNK, (requested + OVERHEAD + MALLOC_ALIGN - 1) & ~(MALLOC_ALIGN - 1))
    return chunk - OVERHEAD
