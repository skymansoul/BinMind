"""
UAF误报削减级联管线 — TARP-E (Taint+Alias+Reach+Escape) 编排器。

四阶段级联:
  Phase 0 — 模式安全检测 (Pattern Safety):    O(n) 文本扫描 → 可证明安全的过滤
  Phase 1 — 别名感知生命周期 (Alias Lifetime): Union-Find + 区间分析
  Phase 2 — 路径敏感支配 (Path Dominance):     简化CFG + BFS可达性
  Phase 3 — 逃逸分析 (Escape Analysis):        STACK/HEAP/GLOBAL/VTABLE 分级
"""

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.uaf_cascade_shared import (
    UafVerdict, EscapeLevel, UafCandidate, CascadeReport,
    _FREE_SET, _ALLOC_SET,
)
from analysis.uaf_candidate_extractor import extract_uaf_candidates


# Phase 0: 模式安全检测

def _is_nullified_after_free(lines: List[str], ptr_var: str,
                              free_lineno: int) -> bool:
    """检查 free(ptr) 后 ptr 是否被置为 NULL."""
    for i in range(free_lineno - 1, min(free_lineno + 3, len(lines))):
        line = lines[i]
        if re.search(rf'\b{ptr_var}\s*=\s*(?:NULL|nullptr|0)\s*;', line):
            return True
    return False


def _is_reused_after_free(lines: List[str], ptr_var: str,
                           free_lineno: int) -> bool:
    """检查 free(ptr) 后 ptr 是否被重新分配. 窗口=10行."""
    end = min(free_lineno + 10, len(lines))
    after_lines = ''.join(lines[free_lineno:end])
    for af in _ALLOC_SET:
        if re.search(
                rf'\b{re.escape(ptr_var)}\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?{re.escape(af)}\s*\(',
                after_lines):
            return True
    return False


def _is_reassigned_after_free(lines: List[str], ptr_var: str,
                               free_lineno: int) -> bool:
    """检查 free(ptr) 后 ptr 是否被重新赋值为有效指针. 窗口=10行."""
    end = min(free_lineno + 10, len(lines))
    for i in range(free_lineno, end):
        l = lines[i]
        if re.search(rf'\b{re.escape(ptr_var)}\s*=\s*\w+\s*\(', l):
            return True
        if re.search(rf'\b{re.escape(ptr_var)}\s*=\s*&', l):
            return True
    return False


def _is_guarded_free_with_null(lines: List[str], ptr_var: str,
                                 free_lineno: int) -> bool:
    """检查 free(ptr) 是否在条件块内且 ptr 随后被NULL或重新赋值."""
    for i in range(free_lineno, min(free_lineno + 10, len(lines))):
        l = lines[i]
        if re.search(rf'\b{re.escape(ptr_var)}\s*=\s*(?:NULL|nullptr|0)\s*;', l):
            return True  # NULL赋值 = 强安全信号
        if re.search(rf'\b{re.escape(ptr_var)}\s*=\s*\w+\s*\(', l):
            return True
        if '}' in l:
            break
    # 往前找: free 是否在条件块内
    depth = 0
    for j in range(free_lineno - 2, max(free_lineno - 15, -1), -1):
        if j < 0 or j >= len(lines):
            continue
        cl = lines[j]
        if '{' in cl:
            if depth == 0:
                for k in range(j - 1, max(j - 3, -1), -1):
                    if k >= 0 and re.search(r'if\s*\(', lines[k]):
                        for m in range(free_lineno, min(j + 15, len(lines))):
                            if re.search(rf'\b{re.escape(ptr_var)}\s*=\s*\w+\s*\(', lines[m]):
                                return True
                            if '}' in lines[m] and m > free_lineno:
                                break
                        return False
                break
            depth -= 1
        if '}' in cl:
            depth += 1
    return False


def _is_branch_exclusive_free_use(lines: List[str], ptr_var: str,
                                    free_lineno: int, use_lineno: int) -> bool:
    """检测 free 和 use 是否在互斥分支内 (if-else 模式).

    模式: if(cond){free(ptr)} else{use(ptr)} → free与use互斥.
    """
    else_brace_line = -1
    for i in range(free_lineno - 1, min(free_lineno + 20, len(lines))):
        if re.search(r'\}\s*else\s*\{', lines[i]):
            else_brace_line = i
            break
        if re.search(r'\}\s*$', lines[i].strip()):
            return False
    if else_brace_line < 0:
        return False
    else_open = lines[else_brace_line].find('{')
    if else_open < 0:
        return False
    depth = 1
    for p in range(else_brace_line, min(else_brace_line + 20, len(lines))):
        cl = lines[p]
        if p == else_brace_line:
            after_open = cl[else_open + 1:]
            depth += after_open.count('{') - after_open.count('}')
        else:
            depth += cl.count('{') - cl.count('}')
        if depth == 0:
            if else_brace_line + 1 <= use_lineno - 1 <= p:
                return True
            return False
        if p == use_lineno - 1:
            return True
    return False


def phase0_pattern_safety(candidates: List[UafCandidate],
                           lines: List[str]) -> Tuple[List[UafCandidate], int]:
    """Phase 0: 模式安全检测 — 过滤可证明安全的候选.

    五种安全模式的检测:
      NULL置零 / 立即复用 / 重新赋值 / 条件守卫 / 互斥分支
    Returns: (kept_candidates, filtered_count)
    """
    kept: List[UafCandidate] = []
    filtered = 0

    for c in candidates:
        ptr = c.ptr_name
        fline = c.free_lineno

        # 检查1: NULL置零
        if _is_nullified_after_free(lines, ptr, fline):
            c.verdict = UafVerdict.SAFE
            c.verdict_reason = f'Phase0: {ptr} nullified after free at L{fline}'
            c.confidence = 0.05
            c.phases_passed.append('P0(nullified)')
            filtered += 1
            continue

        # 检查2: 立即复用
        if _is_reused_after_free(lines, ptr, fline):
            c.verdict = UafVerdict.SAFE
            c.verdict_reason = f'Phase0: {ptr} reused (realloc) after free at L{fline}'
            c.confidence = 0.08
            c.phases_passed.append('P0(reused)')
            filtered += 1
            continue

        # 检查3: 重新赋值
        if _is_reassigned_after_free(lines, ptr, fline):
            c.verdict = UafVerdict.LIKELY_FP
            c.verdict_reason = f'Phase0: {ptr} reassigned after free at L{fline}'
            c.confidence = 0.18
            c.phases_passed.append('P0(reassigned)')
            filtered += 1
            continue

        # 检查4: 条件块内 NULL/重赋值
        if _is_guarded_free_with_null(lines, ptr, fline):
            c.verdict = UafVerdict.LIKELY_FP
            c.verdict_reason = f'Phase0: {ptr} guarded free with reinit at L{fline}'
            c.confidence = 0.22
            c.phases_passed.append('P0(guarded_reinit)')
            filtered += 1
            continue

        # 检查5: 互斥分支
        if _is_branch_exclusive_free_use(lines, ptr, fline, c.use_lineno):
            c.verdict = UafVerdict.LIKELY_FP
            c.verdict_reason = (
                f'Phase0: free(L{fline}) and use(L{c.use_lineno}) '
                f'in mutually exclusive branches')
            c.confidence = 0.15
            c.phases_passed.append('P0(branch_exclusive)')
            filtered += 1
            continue

        c.phases_passed.append('P0(pass)')
        kept.append(c)

    return kept, filtered


# Phase 1: 别名感知生命周期

class AliasTracker:
    """别名追踪器 — union-find 维护指针等价类.

    支持: p = q (直接赋值), p = q->field (字段赋值暂不传播).
    """

    def __init__(self):
        self._parent: Dict[str, str] = {}
        self._obj_map: Dict[str, str] = {}  # ptr → obj_id

    def add_alias(self, lhs: str, rhs: str):
        """记录 lhs = rhs 别名关系."""
        self._parent.setdefault(lhs, lhs)
        self._parent.setdefault(rhs, rhs)
        rl, rr = self._find(lhs), self._find(rhs)
        if rl != rr:
            self._parent[rl] = rr
            if rl in self._obj_map and rr not in self._obj_map:
                self._obj_map[rr] = self._obj_map[rl]
            elif rr in self._obj_map and rl not in self._obj_map:
                self._obj_map[rl] = self._obj_map[rr]

    def bind_obj(self, ptr: str, obj_id: str):
        """绑定 ptr 到堆对象 obj_id."""
        self._parent.setdefault(ptr, ptr)
        root = self._find(ptr)
        self._obj_map[root] = obj_id

    def resolve(self, ptr: str) -> Optional[str]:
        """返回 ptr 指向的 obj_id, 或 None."""
        if ptr not in self._parent:
            return None
        root = self._find(ptr)
        return self._obj_map.get(root)

    def get_alias_set(self, ptr: str) -> Set[str]:
        """获取 ptr 的所有别名."""
        if ptr not in self._parent:
            return {ptr}
        root = self._find(ptr)
        return {p for p in self._parent if self._find(p) == root}

    def _find(self, x: str) -> str:
        """union-find 查找 (路径压缩)."""
        path: List[str] = []
        while self._parent.get(x, x) != x:
            path.append(x)
            x = self._parent.get(x, x)
        for node in path:
            self._parent[node] = x
        return x


def phase1_alias_lifetime(candidates: List[UafCandidate],
                           lines: List[str]) -> Tuple[List[UafCandidate], int]:
    """Phase 1: 别名感知生命周期追踪.

    构建别名图, 追踪每个堆对象从 alloc → free → use 的生命周期.
    若 use_lineno < free_lineno → 时序安全.
    若 use 通过别名变量 (q=p; free(p); use(q)) → 正确追踪.

    Returns: (kept_candidates, filtered_count)
    """
    tracker = AliasTracker()
    kept: List[UafCandidate] = []
    filtered = 0

    # Pass 1: 收集所有赋值别名
    for i, line in enumerate(lines, start=1):
        m = re.match(r'\s*(\w[\w]*)\s*=\s*(\w[\w]*)\s*;', line)
        if m:
            lhs, rhs = m.group(1), m.group(2)
            if rhs not in ('NULL', 'nullptr', '0', 'None'):
                tracker.add_alias(lhs, rhs)

    # Pass 2: 对每个候选检查别名感知的生命周期
    for c in candidates:
        ptr = c.ptr_name
        aliases = tracker.get_alias_set(ptr)
        c.aliases = aliases

        if c.use_lineno < c.free_lineno:
            c.verdict = UafVerdict.SAFE
            c.verdict_reason = (
                f'Phase1: use(L{c.use_lineno}) before free(L{c.free_lineno}) '
                f'— temporally safe')
            c.confidence = 0.10
            c.phases_passed.append('P1(use_before_free)')
            filtered += 1
            continue

        freed_aliases: Set[str] = set()
        for alias in aliases:
            for i in range(c.free_lineno, len(lines)):
                l = lines[i]
                if re.search(rf'free\s*\(\s*\*?\s*{re.escape(alias)}\s*\)', l):
                    freed_aliases.add(alias)
                    break

        if freed_aliases:
            c.verdict_reason = (
                f'Phase1: aliases {freed_aliases} freed; '
                f'use of {ptr} at L{c.use_lineno} after free L{c.free_lineno}')
            c.confidence = min(0.95, c.confidence + 0.15)
            c.verdict = UafVerdict.LIKELY_TP
        else:
            c.verdict_reason = (
                f'Phase1: no alias info for {ptr}, keep as UNCERTAIN')

        c.phases_passed.append('P1(alias_checked)')
        kept.append(c)

    return kept, filtered


# Phase 2: 路径支配分析

@dataclass
class _SimpleBlock:
    """简化的基本块 (用于Phase 2)."""
    id: int
    start_line: int
    end_line: int
    free_vars: Set[str] = field(default_factory=set)
    use_vars: Set[str] = field(default_factory=set)
    successors: List[int] = field(default_factory=list)


def _build_simple_cfg(lines: List[str]) -> List[_SimpleBlock]:
    """从伪代码行构建简化CFG.

    策略: 以 if/else/for/while/return/goto 为块边界分割,
    连接顺序后继和分支目标.
    """
    blocks: List[_SimpleBlock] = []
    bb_start = 0
    bid = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        is_branch = any(
            stripped.startswith(kw) for kw in
            ('if ', 'if(', 'else', 'for ', 'for(', 'while ', 'while(',
             'return', 'goto ', 'switch ', 'case ', 'break', 'continue', '}'))
        if is_branch and i > bb_start:
            block = _make_block(bid, bb_start, i - 1, lines)
            blocks.append(block)
            bid += 1
            bb_start = i

    if bb_start < len(lines):
        block = _make_block(bid, bb_start, len(lines) - 1, lines)
        blocks.append(block)

    # 顺序后继
    for i in range(len(blocks) - 1):
        blocks[i].successors.append(blocks[i + 1].id)

    # 分支: if块添加 else/endif 跳转
    for i, b in enumerate(blocks):
        if b.end_line < len(lines):
            last = lines[b.end_line].strip()
            if last.startswith('if ') or last.startswith('if('):
                depth = 1
                for j in range(i + 1, len(blocks)):
                    for ln in range(blocks[j].start_line, blocks[j].end_line + 1):
                        l = lines[ln].strip()
                        if l.startswith('else') or l == '}':
                            b.successors.append(blocks[j].id)
                            depth = 0
                            break
                    if depth == 0:
                        break

    return blocks


def _make_block(bid: int, start: int, end: int,
                lines: List[str]) -> _SimpleBlock:
    """创建一个基本块并提取 free/use 变量."""
    free_vars: Set[str] = set()
    use_vars: Set[str] = set()
    for i in range(start, min(end + 1, len(lines))):
        l = lines[i]
        for ff in _FREE_SET:
            m = re.search(rf'{re.escape(ff)}\s*\(\s*\*?\s*(\w[\w]*)', l)
            if m:
                free_vars.add(m.group(1))
        for dm in re.finditer(r'\*(\w[\w]*)|(\w[\w]*)\s*->', l):
            v = dm.group(1) or dm.group(2)
            if v:
                use_vars.add(v)
    return _SimpleBlock(id=bid, start_line=start + 1, end_line=end + 1,
                        free_vars=free_vars, use_vars=use_vars)


def _bfs_reachable(adj: Dict[int, List[int]], src: int, dst: int) -> bool:
    """BFS检查 src 到 dst 是否可达."""
    if src == dst:
        return True
    visited = {src}
    queue = [src]
    while queue:
        cur = queue.pop(0)
        if cur == dst:
            return True
        for succ in adj.get(cur, []):
            if succ not in visited:
                visited.add(succ)
                queue.append(succ)
    return False


def phase2_path_dominance(candidates: List[UafCandidate],
                           lines: List[str]) -> Tuple[List[UafCandidate], int]:
    """Phase 2: 路径敏感支配分析.

    对每个候选:
      - free块不能到达use块 → MUTUAL_EXCLUSIVE → FILTER
      - 可到达 → LIKELY_TP, 升级置信度
    Returns: (kept_candidates, filtered_count)
    """
    blocks = _build_simple_cfg(lines)
    if len(blocks) < 2:
        for c in candidates:
            c.phases_passed.append('P2(cfg_too_simple)')
        return candidates, 0

    adj: Dict[int, List[int]] = {}
    for b in blocks:
        adj[b.id] = list(b.successors)

    kept: List[UafCandidate] = []
    filtered = 0

    for c in candidates:
        ptr = c.ptr_name
        free_block = -1
        use_block = -1
        for b in blocks:
            if ptr in b.free_vars and free_block < 0:
                free_block = b.id
            if ptr in b.use_vars and b.end_line >= c.use_lineno:
                if use_block < 0:
                    use_block = b.id

        if free_block < 0 or use_block < 0:
            c.phases_passed.append('P2(no_cfg_match)')
            kept.append(c)
            continue

        reachable = _bfs_reachable(adj, free_block, use_block)

        if not reachable:
            c.verdict = UafVerdict.LIKELY_FP
            c.verdict_reason = (
                f'Phase2: free block {free_block} cannot reach use block '
                f'{use_block} — mutually exclusive branches')
            c.confidence = max(0.10, c.confidence - 0.35)
            c.phases_passed.append('P2(mutual_exclusive)')
            filtered += 1
            continue
        else:
            c.verdict = UafVerdict.LIKELY_TP
            c.confidence = min(0.95, c.confidence + 0.10)
            c.verdict_reason = (
                f'Phase2: free block {free_block} reaches use block '
                f'{use_block} — UAF path confirmed')
            c.phases_passed.append('P2(reachable)')

        kept.append(c)

    return kept, filtered


# Phase 3: 逃逸分析

def _analyze_escape(lines: List[str], ptr: str,
                     use_lineno: int) -> EscapeLevel:
    """分析悬垂指针的逃逸范围.

    检查指针是否: STACK (栈内) / HEAP (写入堆对象字段) /
    GLOBAL (赋值给全局变量) / VTABLE (通过函数指针/虚表).
    """
    # 全局变量模式
    global_pat = re.compile(rf'(?:g_\w+|G_\w+|[A-Z_]{{2,}})\s*=\s*{ptr}\b')
    for i, line in enumerate(lines):
        if global_pat.search(line) and i <= use_lineno:
            return EscapeLevel.GLOBAL

    # 虚表/函数指针
    vtable_pat = re.compile(
        rf'(?:vtable|vtable_ptr|vptr|fn_ptr|callback)\s*.*{ptr}\b')
    for i, line in enumerate(lines):
        if vtable_pat.search(line) and i <= use_lineno:
            return EscapeLevel.VTABLE

    # 堆对象字段写入
    heap_escape_pat = re.compile(rf'(\w+)\s*->\s*\w+\s*=\s*{ptr}\b')
    for i, line in enumerate(lines):
        if heap_escape_pat.search(line) and i <= use_lineno:
            return EscapeLevel.HEAP

    return EscapeLevel.STACK


def phase3_escape_analysis(candidates: List[UafCandidate],
                            lines: List[str]) -> Tuple[List[UafCandidate], int]:
    """Phase 3: 逃逸分析 + 可利用性分级.

    STACK only → 置信度下调; HEAP/GLOBAL → 上调; VTABLE → CONFIRMED.
    Returns: (kept_candidates, downgraded_count)
    """
    kept: List[UafCandidate] = []
    downgraded = 0

    for c in candidates:
        escape = _analyze_escape(lines, c.ptr_name, c.use_lineno)
        c.escape_level = escape

        if escape == EscapeLevel.STACK:
            c.confidence = max(0.30, c.confidence - 0.05)
            c.verdict_reason += (
                f'; Phase3: STACK-only escape → limited exploitability')
            c.phases_passed.append('P3(stack)')
        elif escape == EscapeLevel.HEAP:
            c.confidence = min(0.95, c.confidence + 0.05)
            c.verdict_reason += (
                f'; Phase3: HEAP escape → medium exploitability')
            c.phases_passed.append('P3(heap)')
        elif escape == EscapeLevel.GLOBAL:
            c.confidence = min(0.98, c.confidence + 0.10)
            c.verdict_reason += (
                f'; Phase3: GLOBAL escape → high exploitability')
            c.phases_passed.append('P3(global)')
        elif escape == EscapeLevel.VTABLE:
            c.confidence = min(0.99, c.confidence + 0.15)
            c.verdict = UafVerdict.CONFIRMED
            c.verdict_reason += (
                f'; Phase3: VTABLE escape → critical exploitability')
            c.phases_passed.append('P3(vtable)')

        kept.append(c)

    return kept, downgraded


# 管线编排

def run_uaf_cascade(pseudocode: str,
                     func_name: str = "") -> Tuple[List[UafCandidate], CascadeReport]:
    """运行完整的四阶段 UAF FP 削减级联.

    Args:
        pseudocode: C源码或反编译伪代码
        func_name: 函数名 (可选)

    Returns:
        (final_candidates, cascade_report)
    """
    lines = pseudocode.splitlines()
    if not lines:
        return [], CascadeReport()

    t0 = time.time()

    candidates = extract_uaf_candidates(lines, func_name)
    report = CascadeReport(total_input=len(candidates))

    if not candidates:
        report.total_time_ms = (time.time() - t0) * 1000
        return [], report

    # Phase 0: 模式安全检测
    candidates, report.phase0_filtered = phase0_pattern_safety(candidates, lines)

    # Phase 1: 别名感知生命周期
    if candidates:
        candidates, report.phase1_filtered = phase1_alias_lifetime(
            candidates, lines)

    # Phase 2: 路径敏感支配
    if candidates:
        candidates, report.phase2_filtered = phase2_path_dominance(
            candidates, lines)

    # Phase 3: 逃逸分析
    if candidates:
        candidates, report.phase3_downgraded = phase3_escape_analysis(
            candidates, lines)

    # 统计
    report.final_tp = sum(
        1 for c in candidates
        if c.verdict in (UafVerdict.LIKELY_TP, UafVerdict.CONFIRMED))
    report.final_fp = sum(
        1 for c in candidates
        if c.verdict in (UafVerdict.SAFE, UafVerdict.LIKELY_FP))
    report.per_candidate = [
        {
            'ptr': c.ptr_name,
            'alloc_ln': c.alloc_lineno,
            'free_ln': c.free_lineno,
            'use_ln': c.use_lineno,
            'confidence': round(c.confidence, 3),
            'verdict': c.verdict.value,
            'verdict_reason': c.verdict_reason,
            'escape': c.escape_level.name,
            'phases': c.phases_passed,
        }
        for c in candidates
    ]

    report.total_time_ms = (time.time() - t0) * 1000
    return candidates, report


__all__ = [
    'UafVerdict', 'EscapeLevel', 'UafCandidate', 'CascadeReport',
    'extract_uaf_candidates', 'run_uaf_cascade',
    'phase0_pattern_safety', 'phase1_alias_lifetime',
    'phase2_path_dominance', 'phase3_escape_analysis',
    'AliasTracker', 'run_uaf_cascade',
]
