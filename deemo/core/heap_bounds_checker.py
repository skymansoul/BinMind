# heap_bounds_checker.py - 比较堆写入大小与分配大小, 判定是否越界。
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple
from core.heap_size_tracker import HeapSizeTracker, HeapAllocSite
from core.interval_abstractor import IntervalAbstractor

_WRITE_FNS = r'(?:memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf|read|grub_memcpy)'
_WRITE_PAT = re.compile(_WRITE_FNS + r'\s*\(([^)]+)\)')

@dataclass
class BoundsCheckResult:
    pointer_var: str
    alloc_size: Optional[int] = None
    write_size_expr: str = ""
    write_size: Optional[int] = None
    is_overflow: bool = False
    is_safe: bool = False
    confidence: float = 0.0

class HeapBoundsChecker:
    def check(self, pseudocode: str):
        tracker = HeapSizeTracker()
        allocs = tracker.track(pseudocode)
        results = []
        lines = pseudocode.splitlines()
        for line in lines:
            m = _WRITE_PAT.search(line.strip())
            if not m: continue
            func_match = m.group(0); fn = func_match.split("(")[0].strip().split()[-1] if "(" in func_match else ""; args_str = m.group(1)
            args = self._split(args_str)
            if not args: continue
            dst = args[0].strip()
            base = dst.split("[")[0].strip() if "[" in dst else dst
            alloc = tracker.get_allocation(base)
            if alloc is None: continue
            ws = self._write_size(fn, args)
            if ws is None: continue
            av = alloc.size_value
            wmax = self._estimate(ws)[1]
            results.append(BoundsCheckResult(
                pointer_var=base, alloc_size=av,
                write_size_expr=ws,
                is_overflow=(av is not None and wmax > av),
                confidence=0.85 if av else 0.40))
        # 阶段2: 变量名相关性启发式 — 分配与写入同用变量 V 时视为关联, 标记风险
        for line in lines:
            m = _WRITE_PAT.search(line.strip())
            if not m: continue
            fn_match = m.group(0)
            fn = fn_match.split('(')[0].strip().split()[-1] if '(' in fn_match else ''
            args = self._split(m.group(1))
            if not args or len(args) < 3: continue
            dst = args[0].strip()
            base = dst.split('[')[0].strip() if '[' in dst else dst
            ws = self._write_size(fn, args)
            if ws is None: continue
            for a_name, a_site in tracker._allocations.items():
                if not a_site.is_constant:
                    import re as _re2
                    # 词元匹配: alloc_var 以独立标识符形式出现在写入大小表达式中
                    alloc_var = a_site.size_expr
                    token_match = _re2.search(r'' + _re2.escape(alloc_var) + r'', ws)
                    if token_match:
                        results.append(BoundsCheckResult(
                            pointer_var=base, alloc_size=a_site.size_value,
                            write_size_expr=ws,
                            is_overflow=True, confidence=0.55))
                    results.append(BoundsCheckResult(
                        pointer_var=base, alloc_size=a_site.size_value,
                        write_size_expr=ws,
                        is_overflow=True, confidence=0.55))
        return results
    @staticmethod
    def _write_size(func, args):
        if func in ("memcpy","memmove","memset","strncpy","snprintf","read"):
            return args[2].strip() if len(args)>2 else None
        return None
    @staticmethod
    def _estimate(expr):
        try: v=int(expr); return (float(v),float(v))
        except ValueError: pass
        try: v=float(expr); return (v,v)
        except ValueError: return (0.0,float("inf"))
    @staticmethod
    def _split(s):
        if not s.strip(): return []
        depth,parts,cur=0,[],[]
        for ch in s:
            if ch=="(": depth+=1
            elif ch==")": depth-=1
            if ch=="," and depth==0: parts.append("".join(cur).strip()); cur=[]
            else: cur.append(ch)
        if cur: parts.append("".join(cur).strip())
        return parts