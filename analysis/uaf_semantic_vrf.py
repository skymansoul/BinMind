"""
UAF语义验证器 — C源码 alloc/free/use 时序分析 + 四层FP过滤 (NULL置零/立即复用/别名/互斥路径)。
参考: Undangle, GUEB.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple
# regex patterns
_RE_MALLOC = re.compile(
    r'(\w[\w.\->]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(')
_RE_FREE = re.compile(r'\bfree\s*\(\s*(\w[\w.\->]*)\s*\)')
_RE_NULLIFY = re.compile(r'(\w[\w.\->]*)\s*=\s*(?:NULL|nullptr|0)\s*;')
_RE_ASSIGN_ID = re.compile(r'(\w[\w.\->]*)\s*=\s*(\w[\w.\->]*)\s*;?\s*$')
_RE_DEREF = re.compile(r'(\w[\w.\->]*)\s*->|(?<!\w)\*(?!\*)\s*(\w[\w.\->]*)')
_RE_ARRAY_IDX = re.compile(r'(\w[\w.\->]*)\s*\[')
# 通用函数调用: p作为参数传递即USE (排除free/if/for/while/return等关键字)
_RE_FUNC_CALL = re.compile(r'\b(\w[\w.\->]*)\s*\(')
_RE_IF_BRANCH = re.compile(r'\bif\s*\(([^)]+)\)')
_RE_RETURN_GOTO = re.compile(r'\b(?:return|goto|break|exit)\b')

_C_KW = {'if','for','while','do','else','return','goto','break','continue',
         'case','default','switch','sizeof','typedef','struct','enum','union',
         'void','int','char','long','short','float','double','unsigned','signed',
         'const','static','extern','volatile','register','auto','NULL','nullptr'}
_NON_FUNC_KW = {'if','for','while','do','else','return','goto','break',
                'continue','case','default','switch','sizeof'}


@dataclass
class UafSite:
    """UAF候选点。"""
    ptr_name: str
    alloc_line: int = 0
    free_line: int = 0
    use_line: int = 0
    use_detail: str = ""
    verdict: str = "UNCERTAIN"    # CONFIRMED | LIKELY | FILTERED
    confidence: float = 0.0
    null_guarded: bool = False
    reassigned: bool = False
    has_alias: bool = False
    path_exclusive: bool = False
    reason: str = ""


def _match_paren(text: str, open_pos: int) -> str:
    d, i = 1, open_pos + 1
    while i < len(text) and d > 0:
        if text[i] == '(': d += 1
        elif text[i] == ')': d -= 1
        i += 1
    return text[open_pos + 1:i - 1] if d == 0 else text[open_pos + 1:]


def _resolve_aliases(alias_map: Dict[str, str], ptr: str) -> str:
    seen = {ptr}; cur = ptr
    while cur in alias_map:
        nxt = alias_map[cur]
        if nxt in seen: break
        seen.add(nxt); cur = nxt
    return cur


def _collect_aliases(alias_map: Dict[str, str], root: str) -> Set[str]:
    aliases = set()
    for a, t in alias_map.items():
        if _resolve_aliases(alias_map, a) == root:
            aliases.add(a)
    return aliases


def _is_valid_ptr(name: str) -> bool:
    return name and name not in _C_KW and re.match(r'^[a-zA-Z_]\w*$', name)


def detect_uaf_semantic(code: str, func_name: str = "") -> List[UafSite]:
    """UAF语义检测 — alloc/free/use 三元组 + 四层FP过滤。"""
    raw_lines = code.split('\n')

    # 预分割: 复合行按 ; 拆分子行, 解决同行动态排序
    lines: List[str] = []
    line_map: Dict[int, int] = {}  # sub_idx → original_line_idx
    for i, raw in enumerate(raw_lines):
        stripped = raw.strip()
        if ';' in stripped and not stripped.startswith('for') and not stripped.startswith('struct'):
            parts = [p.strip() for p in stripped.split(';') if p.strip()]
        else:
            parts = [stripped]
        for j, part in enumerate(parts):
            line_map[len(lines)] = i
            lines.append(part)

    # Pass 1: 收集事件
    allocs: Dict[str, int] = {}        # ptr → sub_line_idx
    frees: List[Tuple[str, int]] = []  # (ptr, sub_line_idx)
    uses: List[Tuple[str, int, str]] = []  # (ptr, sub_line_idx, detail)
    nullifies: List[Tuple[str, int]] = []
    alias_map: Dict[str, str] = {}     # lhs → rhs

    # 收集函数参数名 (用于隐式alloc)
    func_params: Set[str] = set()
    for raw in raw_lines:
        pm = re.search(r'^\w+\s+(\w[\w.\->]*)\s*\(([^)]*)\)', raw.strip())
        if pm:
            for param in pm.group(2).split(','):
                parts = param.strip().split()
                if parts:
                    pname = parts[-1].replace('*', '').strip()
                    if _is_valid_ptr(pname): func_params.add(pname)

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()

        # malloc/calloc/realloc
        for m in _RE_MALLOC.finditer(line):
            ptr = m.group(1)
            if _is_valid_ptr(ptr):
                allocs[ptr] = i

        # free
        for m in _RE_FREE.finditer(line):
            ptr = m.group(1)
            if _is_valid_ptr(ptr):
                frees.append((ptr, i))
                # 隐式alloc: 若free的指针无已知alloc但在参数列表中, 添加隐式alloc
                root = _resolve_aliases(alias_map, ptr)
                if root not in allocs and root in func_params:
                    allocs[root] = -1  # 标记为隐式alloc (函数参数)

        # NULL置零
        for m in _RE_NULLIFY.finditer(line):
            ptr = m.group(1)
            if _is_valid_ptr(ptr):
                nullifies.append((ptr, i))

        # 别名: q = p
        for m in _RE_ASSIGN_ID.finditer(line):
            lhs, rhs = m.group(1), m.group(2)
            if _is_valid_ptr(lhs) and _is_valid_ptr(rhs):
                alias_map[lhs] = rhs

        # 结构体字段别名: ref = obj->field → 不建直接映射, 在use检测时追踪

        # 使用检测: 显式解引用 p->field, *p, p[...]
        deref_ptrs: Set[str] = set()
        for m in _RE_DEREF.finditer(line):
            p = m.group(1) or m.group(2)
            if _is_valid_ptr(p): deref_ptrs.add(p)
        for m in _RE_ARRAY_IDX.finditer(line):
            p = m.group(1)
            if _is_valid_ptr(p): deref_ptrs.add(p)

        # 函数调用中作为参数 (排除free自身)
        for m in _RE_FUNC_CALL.finditer(line):
            fn = m.group(1)
            if fn in _NON_FUNC_KW or fn == 'free':
                continue
            # 提取括号内参数, 检查是否包含已知指针
            try:
                args_str = _match_paren(line, m.end() - 1)
            except Exception:
                continue
            for arg in args_str.split(','):
                arg = arg.strip().lstrip('*&')
                if _is_valid_ptr(arg) and (arg in allocs or arg in alias_map or arg in func_params):
                    deref_ptrs.add(arg)

        # 已知指针集合 = 有alloc的 + 有free的 + 别名 + 函数参数
        known_ptrs = set(allocs.keys()) | set(alias_map.keys()) | func_params
        known_ptrs |= {fp for fp, _ in frees}

        for ptr in deref_ptrs:
            if ptr in known_ptrs and 'free(' not in line:
                uses.append((ptr, i, line[:80]))

    # Pass 2: double-free (同指针两次free, 中间无重分配 → 第二次free就是UAF)
    for i in range(len(frees)):
        fp_i, fl_i = frees[i]
        root_i = _resolve_aliases(alias_map, fp_i)
        for j in range(i + 1, len(frees)):
            fp_j, fl_j = frees[j]
            root_j = _resolve_aliases(alias_map, fp_j)
            if root_i == root_j or fp_i == fp_j or fp_j in _collect_aliases(alias_map, root_i):
                # 检查两次free之间是否有重新分配
                intervening_alloc = any(
                    al > fl_i and ap == root_i
                    for ap, al in allocs.items() if al > 0
                )
                if not intervening_alloc:
                    uses.append((fp_j, fl_j, f"double-free: {lines[fl_j].strip()[:60]}"))

    # Pass 3: 匹配 free→use 对
    sites: List[UafSite] = []
    for free_ptr, free_ln in frees:
        root = _resolve_aliases(alias_map, free_ptr)
        ptr_aliases = _collect_aliases(alias_map, root) | {root} | {free_ptr}
        post_free_uses = [(up, ul, ud) for (up, ul, ud) in uses
            if ul >= free_ln and (up in ptr_aliases or up == free_ptr or
                                  _resolve_aliases(alias_map, up) in ptr_aliases)]
        if not post_free_uses: continue

        # NULL置零 / 立即复用 / 互斥路径
        null_guarded = any(_resolve_aliases(alias_map, np) == root
            for np, nl in nullifies if free_ln < nl < post_free_uses[0][1])
        reassigned = any(al > free_ln and al < post_free_uses[0][1] and
            (_resolve_aliases(alias_map, ap) == root or ap == root)
            for ap, al in allocs.items() if al > 0)
        path_exclusive = _check_path_exclusive(lines, free_ln, post_free_uses[0][1])
        has_alias = len(ptr_aliases) > 1

        for _up, ul, ud in post_free_uses[:5]:
            site = _evaluate_uaf(
                root, free_ln, ul, ud, null_guarded, reassigned,
                has_alias, path_exclusive)
            sites.append(site)

    sites.sort(key=lambda s: (-s.confidence, s.free_line))
    return sites


def _check_path_exclusive(lines: List[str], free_ln: int, use_ln: int) -> bool:
    between = lines[free_ln:use_ln + 1]
    has_if = any(_RE_IF_BRANCH.search(l) for l in between)
    has_else = any(re.search(r'\belse\b', l) for l in between)
    has_jump = any(_RE_RETURN_GOTO.search(l) for l in between[1:-1])
    return has_if and not has_else and has_jump


def _evaluate_uaf(
    ptr: str, free_ln: int, use_ln: int, use_detail: str,
    null_guarded: bool, reassigned: bool, has_alias: bool,
    path_exclusive: bool,
) -> UafSite:
    site = UafSite(ptr_name=ptr, free_line=free_ln, use_line=use_ln,
                   use_detail=use_detail, null_guarded=null_guarded,
                   reassigned=reassigned, has_alias=has_alias,
                   path_exclusive=path_exclusive)
    if null_guarded:
        site.verdict, site.confidence = "FILTERED", 0.05
        site.reason = f"NULL置零: {ptr}=NULL between free@{free_ln} and use@{use_ln}"
        return site
    if reassigned:
        site.verdict, site.confidence = "FILTERED", 0.10
        site.reason = f"立即复用: {ptr}=malloc() after free@{free_ln}"
        return site
    if path_exclusive:
        site.verdict, site.confidence = "FILTERED", 0.15
        site.reason = f"互斥路径: free@{free_ln}和use@{use_ln}在不同分支"
        return site
    distance = use_ln - free_ln
    confidence = 0.75
    if distance > 30: confidence -= 0.20
    elif distance > 10: confidence -= 0.10
    if has_alias: confidence -= 0.15
    if '->' in use_detail or '*' in use_detail or '[' in use_detail:
        confidence += 0.10
    if 'double-free' in use_detail:
        confidence += 0.15  # double-free是高置信UAF变体
    confidence = max(0.05, min(0.95, confidence))
    site.confidence = confidence
    if confidence >= 0.60:
        site.verdict = "CONFIRMED"
        site.reason = f"UAF: {ptr} used@{use_ln} after free@{free_ln} (d={distance})"
    elif confidence >= 0.30:
        site.verdict = "LIKELY"
        site.reason = f"Possible UAF: {ptr} used@{use_ln} after free@{free_ln}"
    else:
        site.verdict = "FILTERED"
        site.reason = f"Low conf: d={distance} alias={has_alias}"
    return site


# 便捷入口

def analyze_uaf(code: str) -> Dict:
    """返回检测摘要, 用于基准测试集成。"""
    sites = detect_uaf_semantic(code)
    confirmed = [s for s in sites if s.verdict == "CONFIRMED"]
    likely = [s for s in sites if s.verdict == "LIKELY"]
    return {
        'total': len(sites),
        'confirmed': len(confirmed),
        'likely': len(likely),
        'filtered': len(sites) - len(confirmed) - len(likely),
        'detected': len(confirmed) + len(likely) > 0,
        'max_confidence': max((s.confidence for s in sites), default=0.0),
        'sites': sites,
    }
