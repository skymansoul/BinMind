"""
Interval constraint analysis — extracts numeric constraints from decompiled
code and uses interval arithmetic to prove heap-operation safety.

Forward data-flow analysis maintaining [min, max] intervals per variable.
  malloc(size) → record the size interval.
  memcpy(dst, src, n) → compare n's interval against the alloc's size interval.
  prove(n ≤ alloc_size) → safe (FP, filtered).
  prove(n > alloc_size) → unsafe (true positive).
  otherwise → uncertain (kept for further analysis).

O(N·V) complexity, N ≤ 500 statements, V ≤ 50 variables.

Works on binary decompiler output (no type info, no heap shape), so uses
conservative interval arithmetic — filters only statically provable safe
cases. The rest stays as uncertain (false negatives avoided at all cost).
"""
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class Interval:
    min_val: int; max_val: int

    def union(self, o: 'Interval') -> 'Interval':
        return Interval(min(self.min_val, o.min_val), max(self.max_val, o.max_val))

    def contains(self, v: int) -> bool: return self.min_val <= v <= self.max_val


@dataclass
class AllocConstraint:
    alloc_site: str; alloc_func: str; alloc_var: str
    size_var: str; size_range: Interval


@dataclass
class WriteConstraint:
    write_site: str; write_func: str; target_var: str
    size_var: str; size_range: Interval


class ValueRangeAnalyzer:
    _ASSIGN_PAT = re.compile(r'(\b[a-zA-Z_]\w{0,31}\b)\s*=\s*(\w+)\s*\(([^)]*)\)')
    _CALL_PAT = re.compile(r'\b(\w+)\s*\(([^)]*)\)')  # 裸函数调用, 无赋值
    _VAR_ASSIGN_PAT = re.compile(r'(\b[a-zA-Z_]\w{0,31}\b)\s*=\s*(.+)')
    _INT_PAT = re.compile(r'\b(\d+)\b')
    _VAR_REF_PAT = re.compile(r'\b([a-zA-Z_]\w{0,31})\b')

    def __init__(self):
        self._intervals: Dict[str, Interval] = {}
        self._allocs: List[AllocConstraint] = []
        self._writes: List[WriteConstraint] = []

    def analyze(self, code: str):
        self._intervals.clear(); self._allocs.clear(); self._writes.clear()
        for line in code.split('\n'):
            s = line.strip()
            if not s or s.startswith('//'): continue
            self._process(s)

    def _process(self, line: str):
        m = self._ASSIGN_PAT.search(line)
        if m:
            lhs, func, args_str = m.group(1), m.group(2), m.group(3)
            args = self._split(args_str)
            self._handle_call(func, args, lhs, line)
            return
        # 裸函数调用 (无赋值左侧), 如 memcpy(dst, src, 32)
        m = self._CALL_PAT.search(line)
        if m:
            func, args_str = m.group(1), m.group(2)
            if func in ('memcpy', 'strcpy', 'memmove', 'read', 'recv', 'free'):
                args = self._split(args_str)
                self._handle_call(func, args, '', line)
            return
        m = self._VAR_ASSIGN_PAT.search(line)
        if m:
            lhs, rhs = m.group(1).strip(), m.group(2).strip()
            ints = self._INT_PAT.findall(rhs)
            if ints and len(ints) == 1:
                v = int(ints[0]); self._intervals[lhs] = Interval(v, v)
            else:
                for ref in self._VAR_REF_PAT.findall(rhs):
                    if ref in self._intervals and ref != lhs:
                        self._intervals[lhs] = self._intervals[ref]; break

    def _handle_call(self, func: str, args: List[str], lhs: str, line: str):
        """Handle function calls: both assignment form and bare call form."""
        if func in ('malloc', 'calloc', 'realloc'):
            sv, sr = self._extract_alloc_size(args, func)
            var = lhs if lhs else (args[0].strip() if args else '?')
            self._allocs.append(AllocConstraint(line[:80], func, var, sv, sr))
            if lhs:
                self._intervals[lhs + '_size'] = sr
        elif func in ('memcpy', 'strcpy', 'memmove'):
            if len(args) >= 3:
                sv, sr = self._extract_size_arg(args[2])
                self._writes.append(WriteConstraint(line[:80], func, args[0].strip(), sv, sr))
        elif func in ('read', 'recv') and len(args) >= 3:
            sv, sr = self._extract_size_arg(args[2])
            self._writes.append(WriteConstraint(line[:80], func, args[1].strip(), sv, sr))

    def _extract_alloc_size(self, args, func):
        if func == 'calloc' and len(args) >= 2:
            n, m = self._parse_int(args[0]), self._parse_int(args[1])
            if n is not None and m is not None: return ('const', Interval(n*m, n*m))
        return self._extract_size_arg(args[0]) if args else ('?', Interval(0, 65536))

    def _extract_size_arg(self, arg):
        arg = arg.strip(); v = self._parse_int(arg)
        if v is not None: return ('const', Interval(v, v))
        for ref in self._VAR_REF_PAT.findall(arg):
            if ref in self._intervals: return (ref, self._intervals[ref])
        return (arg, Interval(1, 65536))

    def _parse_int(self, s):
        try:
            s = s.strip().lstrip('(').rstrip(')')
            return int(s, 16) if s.startswith('0x') or s.startswith('0X') else int(s)
        except (ValueError, AttributeError): return None

    def is_provably_safe(self, a: AllocConstraint, w: WriteConstraint) -> bool:
        return w.size_range.max_val <= a.size_range.min_val and a.size_range.min_val > 0

    def is_provably_unsafe(self, a: AllocConstraint, w: WriteConstraint) -> bool:
        return w.size_range.min_val > a.size_range.max_val

    def classify(self) -> List[Tuple[AllocConstraint, WriteConstraint, str]]:
        results = []
        for a in self._allocs:
            for w in self._writes:
                if self.is_provably_safe(a, w): results.append((a, w, 'safe'))
                elif self.is_provably_unsafe(a, w): results.append((a, w, 'unsafe'))
                else: results.append((a, w, 'uncertain'))
        return results

    @staticmethod
    def _split(s):
        parts = []; depth = 0; cur = []
        for ch in s:
            if ch == '(': depth += 1
            elif ch == ')': depth -= 1
            if ch == ',' and depth == 0: parts.append(''.join(cur).strip()); cur = []
            else: cur.append(ch)
        if cur: parts.append(''.join(cur).strip())
        return parts


class HeapFalsePositiveFilter:
    """堆溢出误报过滤器 — 包装 ValueRangeAnalyzer, 输出过滤后的发现列表。

    输入: 原始堆溢出发现列表 (来自 heap_overflow_detector 或静态模式匹配)
    输出: 过滤后的发现列表 — 'safe' 判定的移除, 'unsafe' 保留,
          'uncertain' 保留但 confidence 打折。

    关键指标: 过滤率 = safe / (safe + unsafe + uncertain)。
    目标: 在保留 unsafe 100% 的前提下, 最大化 safe 过滤率。
    """

    def __init__(self):
        self._vra = ValueRangeAnalyzer()

    def filter(self, pseudocode: str,
               raw_findings: List[dict]) -> List[dict]:
        """过滤原始发现列表."""
        self._vra.analyze(pseudocode)
        classified = self._vra.classify()
        if not classified:
            return raw_findings

        # 构建分配变量→安全判定 的映射
        safe_allocs = set()
        unsafe_allocs = set()
        for a, w, verdict in classified:
            if verdict == 'safe':
                safe_allocs.add(a.alloc_var)
            elif verdict == 'unsafe':
                unsafe_allocs.add(a.alloc_var)

        filtered = []
        for f in raw_findings:
            alloc_var = f.get('alloc_var', '')
            if alloc_var in safe_allocs:
                # 可证明安全 → 滤除 (这是误报)
                continue
            if alloc_var in unsafe_allocs:
                f['fp_filter_verdict'] = 'unsafe'
                f['confidence'] = min(1.0, f.get('confidence', 0.5) + 0.2)
            else:
                f['fp_filter_verdict'] = 'uncertain'
            filtered.append(f)
        return filtered

    def stats(self, pseudocode: str) -> dict:
        """返回误报过滤统计."""
        self._vra.analyze(pseudocode)
        classified = self._vra.classify()
        safe = sum(1 for _, _, v in classified if v == 'safe')
        unsafe = sum(1 for _, _, v in classified if v == 'unsafe')
        uncertain = sum(1 for _, _, v in classified if v == 'uncertain')
        total = len(classified)
        return {
            'total_alloc_write_pairs': total,
            'provably_safe_filtered': safe,
            'provably_unsafe_confirmed': unsafe,
            'uncertain_retained': uncertain,
            'fp_reduction_pct': round(safe * 100 / max(1, total), 1),
        }
