"""
三层区间误报抑制 — 按写入超出量分三级分类。
CONFIRMED: 写入明确超出分配 → CRITICAL; PARTIAL: 部分超出(<16B) → WARNING 置信度×0.6;
SUPPRESSED: 安全(写入<=分配) → 排除。
"""


import re

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List


class Tier(Enum):
    CONFIRMED = "confirmed"
    PARTIAL = "partial"
    SUPPRESSED = "suppressed"


@dataclass
class FilterResult:
    alloc_var: str; alloc_size: int
    write_var: str; write_size: int
    tier: Tier; overflow: int; desc: str


def classify(alloc_sz: int, write_sz: int,
             avar: str = "?", wvar: str = "?") -> FilterResult:
    if alloc_sz <= 0 or write_sz <= 0:
        return FilterResult(avar, alloc_sz, wvar, write_sz,
                            Tier.SUPPRESSED, 0, "size unknown")
    ovf = write_sz - alloc_sz
    if ovf <= 0:
        return FilterResult(avar, alloc_sz, wvar, write_sz,
                            Tier.SUPPRESSED, 0, f"safe: {write_sz}<={alloc_sz}")
    if ovf <= 16:
        return FilterResult(avar, alloc_sz, wvar, write_sz,
                            Tier.PARTIAL, ovf, f"partial: +{ovf}B")
    return FilterResult(avar, alloc_sz, wvar, write_sz,
                        Tier.CONFIRMED, ovf, f"confirmed: +{ovf}B")


def apply_filter(findings: List[dict],
                 results: List[FilterResult]) -> tuple[List[dict], int]:
    filtered = []; suppressed = 0
    for f in findings:
        desc = f.get('description', '')
        matched = next((r for r in results
                        if r.alloc_var in desc or r.write_var in desc), None)
        if matched is None:
            filtered.append(f)
        elif matched.tier == Tier.CONFIRMED:
            f['tier'] = 'confirmed'; f['overflow'] = matched.overflow
            filtered.append(f)
        elif matched.tier == Tier.PARTIAL:
            f['severity'] = 'Medium'; f['tier'] = 'partial'
            f['overflow'] = matched.overflow; filtered.append(f)
        else:
            suppressed += 1
    return filtered, suppressed


def filter_stats(results: List[FilterResult]) -> Dict[str, int]:
    return {"confirmed": sum(1 for r in results if r.tier == Tier.CONFIRMED),
            "partial": sum(1 for r in results if r.tier == Tier.PARTIAL),
            "suppressed": sum(1 for r in results if r.tier == Tier.SUPPRESSED),
            "total": len(results)}


# 正则: if(var OP num) 条件守卫
_RE_GUARD = re.compile(
    r'if\s*\(\s*(\w+)\s*([<>=!]+)\s*(\d+)\s*\)')
# 正则: NULL 检查 if(ptr == NULL) 或 if(ptr != NULL)
_RE_NULL_CHECK = re.compile(
    r'if\s*\(\s*(\w+)\s*(==|!=)\s*(NULL|0)\s*\)')
# 正则: cap 守卫 if(var > N) var = N; 截断用户输入到安全上限
_RE_CAP_GUARD = re.compile(
    r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)\s*\1\s*=\s*\2')
# 正则: malloc/calloc/realloc 调用, 捕获目标变量和大小表达式
_RE_ALLOC = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(')
# 正则: 写入函数调用, 捕获大小参数
_RE_WRITE_CALL = re.compile(
    r'(memcpy|memmove|strcpy|strncpy|memset|snprintf|'
    r'read|fread|recv)\s*\(')


def _extract_call_args(text: str, start: int) -> str:
    """从 text[start] '(' 之后提取括号内完整参数串。"""
    depth, i = 1, start
    while i < len(text) and depth > 0:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
        i += 1
    return text[start:i - 1] if depth == 0 else text[start:]


def _split_args(arg_str: str) -> List[str]:
    """按逗号切分参数, 处理嵌套括号。"""
    parts: List[str] = []
    depth, cur = 0, []
    for ch in arg_str:
        if ch == '(':
            depth += 1; cur.append(ch)
        elif ch == ')':
            depth -= 1; cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur).strip()); cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return parts


def _safe_alignment(sz: int) -> int:
    """glibc malloc 对齐: 16 字节粒度, 最小 32。"""
    if sz <= 0:
        return 32
    return max(32, ((sz + 15) // 16) * 16)


def analyze_code_safety(code: str, findings: List[dict]
                        ) -> tuple[List[dict], Dict[str, int]]:
    """Tier 3 保守启发式: 检测三种安全模式并过滤误报。

    bound_guarded: if 条件守卫约束变量后安全。
    constant_safe: 分配与写入均为常量且写入不超过对齐后容量。
    sanitizer_protected: NULL 检查后才使用指针。
    返回 (过滤后 findings, stats)。
    """
    stats = {"bound_guarded": 0, "constant_safe": 0,
             "cap_guarded": 0, "sanitizer_protected": 0,
             "synthetic_noise": 0}
    if not code or not findings:
        return list(findings), stats

    lines = code.split('\n')

    # 预计算: 变量→实际分配大小常量
    alloc_sizes: Dict[str, int] = {}
    for ln in lines:
        m = _RE_ALLOC.search(ln)
        if m:
            var = m.group(1)
            args = _extract_call_args(ln, m.end())
            parts = _split_args(args)
            if m.group(2) == 'calloc' and len(parts) >= 2:
                try:
                    alloc_sizes[var] = int(parts[0]) * int(parts[1])
                except ValueError:
                    pass
            elif parts:
                try:
                    alloc_sizes[var] = int(parts[0])
                except ValueError:
                    pass

    # 预计算: 守卫变量→上限值 (if(size < 64) → size 上限 63)
    guards_le: Dict[str, int] = {}
    # 预计算: cap 守卫变量→上限值 (if(size > 1024) size = 1024)
    cap_guarded: Dict[str, int] = {}
    # 预计算: NULL 检查后使用的变量集合
    null_checked: set = set()

    for i, ln in enumerate(lines):
        gm = _RE_GUARD.search(ln)
        if gm:
            var, op, val = gm.group(1), gm.group(2), int(gm.group(3))
            if op in ('<', '<='):
                guards_le[var] = val if op == '<' else val + 1
            elif op == '==' and var in alloc_sizes:
                guards_le[var] = val

        cm = _RE_CAP_GUARD.search(ln)
        if cm:
            cap_guarded[cm.group(1)] = int(cm.group(2))

        nm = _RE_NULL_CHECK.search(ln)
        if nm:
            null_checked.add(nm.group(1))

    refined: List[dict] = []
    for f in findings:
        suppressed = False

        av = str(f.get('alloc_var', ''))
        wv = str(f.get('write_var', ''))
        alloc_sz = f.get('alloc_size', 0)
        write_sz = f.get('write_size', 0)

        # DEFINITE 已由路径敏感分析确认溢出, Tier 3 常量对齐过滤不适用
        # 但 cap_guarded 可修正跨分支合并导致的 DEFINITE 误报, 仍需检查
        _is_definite = f.get('verdict') == 'DEFINITE'

        # 模式 a: bound_guarded — 守卫变量大小受限
        for var, cap in guards_le.items():
            desc = str(f.get('description', ''))
            if var in desc:
                try:
                    ws = int(write_sz) if not isinstance(write_sz, str) else cap
                except (ValueError, TypeError):
                    ws = cap
                if ws <= _safe_alignment(cap):
                    stats["bound_guarded"] += 1
                    suppressed = True
                    break

        if not suppressed:
            # 模式 b: constant_safe — 常量分配/写入, 写入不超对齐
            # 跳过 write_size_approx finding: 写入大小为下界降级值,
            # 不是真实常量, 常量比较无意义 (会误过滤循环写真阳性)
            if not _is_definite and not f.get('write_size_approx', False):
                try:
                    a_int = int(alloc_sz)
                    w_int = int(write_sz)
                    if a_int > 0 and w_int > 0:
                        if w_int <= _safe_alignment(a_int):
                            stats["constant_safe"] += 1
                            suppressed = True
                except (ValueError, TypeError):
                    pass

        if not suppressed:
            # 模式 d: cap_guarded — if(var > N) var = N 截断守卫
            # alloc_size_expr 匹配被 cap 的变量时, alloc 和 write 同源
            # cap 守卫保证两者均 <= cap, 跨分支配对导致的误报可过滤
            alloc_expr = str(f.get('alloc_size_expr', ''))
            for var, cap in cap_guarded.items():
                if var == alloc_expr or var == av or var == wv:
                    try:
                        a_int = int(alloc_sz) if not isinstance(alloc_sz, str) else cap
                    except (ValueError, TypeError):
                        a_int = cap
                    try:
                        w_int = int(write_sz) if not isinstance(write_sz, str) else cap
                    except (ValueError, TypeError):
                        w_int = cap
                    if a_int <= cap and w_int <= cap:
                        stats["cap_guarded"] = stats.get("cap_guarded", 0) + 1
                        suppressed = True
                        break

        if not suppressed:
            # 模式 c: sanitizer_protected — NULL 检查后使用
            if av in null_checked or wv in null_checked:
                stats["sanitizer_protected"] += 1
                suppressed = True

        if not suppressed:
            # 模式 e: synthetic_noise — 合成分配点无真实分配信息
            # 仅过滤 alloc_var 为非法标识符的噪声 finding (注释残留),
            # 别名指针(ptr=buf+offset)虽为 synthetic 但有真实溢出语义, 保留
            alloc_expr_val = str(f.get('alloc_size_expr', ''))
            alloc_var_name = str(f.get('alloc_var', ''))
            _is_noise_var = not alloc_var_name or alloc_var_name in ('...', 'None')
            if alloc_expr_val == '__synthetic__' and _is_noise_var and not _is_definite:
                stats["synthetic_noise"] = stats.get("synthetic_noise", 0) + 1
                suppressed = True

        if not suppressed:
            refined.append(f)

    return refined, stats
