"""
UAF Realloc 辅助检测 — _check_realloc_dangle 和 _check_realloc_safe.

处理 realloc() 导致的指针别名悬空场景.
"""

from typing import List, Tuple


def check_realloc_dangle(use_site: int,
                         insns: List[Tuple[int, str]],
                         ir_text: str = "") -> bool:
    """A+阶段: Realloc 别名悬空检测 (增强 Stage A).

    检测 realloc() 导致的指针别名悬空:
      q = p; p = realloc(p, size); q->field = x;  ← UAF!

    返回 True=有悬空别名(危险), False=无悬空(安全).
    """
    if not ir_text:
        return False
    try:
        from analysis.uaf_realloc_tracker import ReallocPathTracker
        import re as _re

        use_var = None
        for addr, text in insns:
            if addr == use_site:
                m = _re.search(r'\*(\w+)\b|(\w+)\s*->|(\w+)\s*\[', text)
                if m:
                    use_var = m.group(1) or m.group(2) or m.group(3)
                break

        if not use_var:
            return False

        tracker = ReallocPathTracker()
        danglings = tracker.analyze(ir_text)
        if not danglings:
            return False

        for d in danglings:
            if d.alias_var == use_var:
                return True
        return False
    except ImportError:
        return False


def check_realloc_safe(use_site: int,
                       insns: List[Tuple[int, str]],
                       ir_text: str = "") -> bool:
    """A+阶段逆向: 检查 use_site 的变量是否被 realloc 安全更新.

    场景: Stage A 判定 p (freed) 和 p (used) 同别名 → 危险.
    但若 p = realloc(p, size) 更新了 p 且无悬空别名, 则实际安全.

    返回 True=realloc证明安全(应过滤), False=无法证明安全.
    """
    if not ir_text:
        return False
    try:
        from analysis.uaf_realloc_tracker import ReallocPathTracker
        import re as _re

        use_var = None
        for addr, text in insns:
            if addr == use_site:
                m = _re.search(r'\*(\w+)\b|(\w+)\s*->|(\w+)\s*\[', text)
                if m:
                    use_var = m.group(1) or m.group(2) or m.group(3)
                break

        if not use_var:
            return False

        tracker = ReallocPathTracker()
        danglings = tracker.analyze(ir_text)

        for site in tracker.realloc_sites:
            if site.target_var == use_var:
                if not danglings:
                    return True
                dangling_vars = {d.alias_var for d in danglings}
                if use_var not in dangling_vars:
                    return True

        return False
    except ImportError:
        return False
