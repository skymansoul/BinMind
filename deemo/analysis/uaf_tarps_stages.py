"""


五阶段:
  T — Type-state tracking: 追踪堆对象生命周期 (alloc→free→use)
  A — Alias analysis: 指针别名追踪 (Union-Find等价类)
  R — Reachability: 基本块可达性 (CFG支配关系 + 正则回退)
  P — Path condition: 路径守卫检查
  S — Sanitization: 安全模式检测 (refcount/scope_guard/realloc检查)
"""


import re
from typing import Dict, List, Tuple


def check_type_state(free_site: int, use_site: int,
                     insns: List[Tuple[int, str]]) -> bool:
    """T阶段: Type-state 追踪.

    返回 True=危险(应保留), False=安全(可过滤).

    查找 free 和 use 之间的 NULL 赋值.
    """
    for addr, text in insns:
        if free_site < addr < use_site:
            tl = text.strip().lower()
            # ptr = NULL 模式
            if re.search(r'=\s*(0|null|nullptr|nil)\s*;?', tl):
                return False  # NULL 置零 → 安全
    return True  # 无保护 → 危险


def check_alias(free_site: int, use_site: int,
                insns: List[Tuple[int, str]]) -> bool:
    """A阶段: 别名分析.

    方法:
      1. 扫描所有指令收集指针赋值 (q=p, q=&p->field)
      2. 构建别名等价类 (Union-Find)
      3. 在 free_site 识别被释放的指针
      4. 在 use_site 识别被使用的指针
      5. 若两者不在同一等价类 → 安全(可过滤), 否则 → 危险

    返回 True=危险(应保留), False=安全(可过滤).
    """
    # 收集指针赋值: q = p 或 q = p->field
    aliases: Dict[str, str] = {}  # dst → src
    ptr_assign = re.compile(r'(\w+)\s*=\s*(\w+)\s*;?$')
    field_assign = re.compile(r'(\w+)\s*=\s*(\w+)->(\w+)\s*;?$')

    for addr, text in insns:
        tl = text.strip()
        m = ptr_assign.match(tl)
        if m:
            dst, src = m.group(1), m.group(2)
            if not dst.startswith(('if', 'while', 'for')):
                aliases[dst] = src
        m = field_assign.match(tl)
        if m:
            dst, base = m.group(1), m.group(2)
            aliases[dst] = base

    # Union-Find 合并等价类
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        if x not in parent:
            parent[x] = x
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(a: str, b: str):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for dst, src in aliases.items():
        union(dst, src)

    # 识别 free 和 use 的指针名
    freed_ptr = None
    used_ptr = None
    for addr, text in insns:
        tl = text.strip()
        if addr == free_site:
            m = re.search(r'free\s*\(\s*(\w+)\s*\)', tl)
            if m:
                freed_ptr = m.group(1)
        if addr == use_site:
            # use: *ptr, ptr->field, ptr[index]
            m = re.search(r'\*(\w+)\b|(\w+)\s*->|(\w+)\s*\[', tl)
            if m:
                used_ptr = m.group(1) or m.group(2) or m.group(3)

    if freed_ptr is None or used_ptr is None:
        return True  # 无法识别, 保守返回危险

    # 关键判定: 别名等价类是否相同
    if find(freed_ptr) == find(used_ptr):
        return True   # 同别名类 → 可能UAF, 危险

    # 不同类 → 安全, 可过滤
    return False


def check_reachability(free_site: int, use_site: int,
                       insns: List[Tuple[int, str]],
                       dom_result=None) -> bool:
    """R阶段: 可达性检查 (v3: 优先CFG支配关系).

    返回 True=free和use在同一可达路径上(危险), False=不可达(安全).

    v3策略:
      1. 若有 dominator result: free_dominates_use=True → 所有到use的路径必经free → 危险
         nullify_postdom_free=True → 所有free后路径必经nullify → 安全
      2. 若无 dominator: 回退到 正则扫描 return/exit.
    """
    # v3: CFG级支配关系
    if dom_result is not None:
        dr = dom_result
        if dr.free_dominates_use:
            return True   # Free block dominates Use block → 不可避免
        if dr.nullify_postdom_free:
            return False  # Nullify post-dominates Free → 安全
        # dominator无法判定 → 退回正则

    # 回退: 正则扫描
    for addr, text in insns:
        if free_site < addr < use_site:
            tl = text.strip().lower()
            if tl.startswith('return') or 'exit(' in tl:
                return False  # 提前返回 → use不可达
    return True


def check_path_guard(use_site: int,
                     insns: List[Tuple[int, str]],
                     dom_result=None) -> bool:
    """P阶段: 路径守卫 (v3: 优先CFG guard detection).

    返回 True=无守卫(危险), False=有守卫(安全).

    v3策略:
      1. 若有 dominator result: guard_protected=True → use在守卫块内 → 安全
      2. 若无: 回退到 正则扫描 if(ptr != NULL).
    """
    # v3: CFG级守卫检测
    if dom_result is not None:
        if dom_result.guard_protected:
            return False  # Use site is guard-gated → 安全

    # 回退: 正则扫描
    for addr, text in insns:
        if addr < use_site and abs(addr - use_site) < 100:
            tl = text.strip().lower()
            if re.search(r'if\s*\(.*!=\s*(0|null|nullptr)', tl):
                return False
            if re.search(r'if\s*\(.*ptr', tl):
                return False
    return True


def check_sanitization(ir_text: str = "") -> bool:
    """S阶段: 安全模式检测.

    返回 True=无sanitization(危险), False=有安全模式(安全).

    检测 refcount保护, scope_guard, realloc后非空检查.
    """
    tl_all = ir_text.lower() if ir_text else ""

    # count 保护
    if re.search(r'ref_?count\s*>\s*0', tl_all):
        return False
    # scope guard
    if re.search(r'scope_guard|defer\s|finally', tl_all):
        return False
    # realloc 后非空检查
    if 'realloc' in tl_all and re.search(
            r'if\s*\(.*!=\s*(0|null|nullptr)\)', tl_all):
        return False

    return True


def addr_to_line(addr: int, insns: List[Tuple[int, str]]) -> int:
    """将指令地址映射到行号 (用于 dominator verifier)."""
    for i, (a, _) in enumerate(insns, 1):
        if a == addr:
            return i
    return -1


def extract_freed_ptr(addr: int, insns: List[Tuple[int, str]]) -> str:
    """从 free 指令提取被释放的指针变量名."""
    for a, text in insns:
        if a == addr:
            m = re.search(r'free\s*\(\s*(\w+)\s*\)', text.strip())
            if m:
                return m.group(1)
    return "ptr"


__all__ = [
    'check_type_state', 'check_alias',
    'check_reachability', 'check_path_guard', 'check_sanitization',
    'addr_to_line', 'extract_freed_ptr',
]
