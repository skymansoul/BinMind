# analysis/uaf_fc_detector — UAF-FC 流相关 UAF 检测 (FC-VRA 方法论向 UAF 迁移)
# 将堆溢出主打点的"流相关 + 状态追踪"迁移到 UAF 检测。
# 现有 uaf_detector_v2 的误报来源:
#   (a) free(p) 后"标识符再次出现"即视为使用 — 把 p=NULL 空态、
#       p=malloc() 重赋值、p 仅作值传递等安全模式误报为 UAF;
#   (b) 无别名闭包 — free(p); q->f 的跨变量解引用漏检;
#   (c) 无守卫路径 — if(p) {...} 内的使用被无条件判定。
#
# UAF-FC 管线:
#   C0 别名闭包: 追踪 p=q 赋值, 同一内存对象跨变量识别
#   C1 空态追踪: free 后 var=NULL → 后续解引用为空指针解引用, 非 UAF
#   C2 重赋值追踪: free 后 var=malloc/calloc/realloc → 指向新对象
#   C3 守卫路径: use 位于 if(var) / if(var!=NULL) 块内 → 可安全访问
#   C4 解引用确认: 仅 p->f / *p / p[i] / 传参计为 use, 单纯标识符不算

from __future__ import annotations
from typing import Dict, List, Set, Tuple, Optional
import re

_ALLOC = re.compile(r"(?:malloc|calloc|realloc|new)\s*\(")
_NULL = re.compile(r"\bNULL\b|\b0\b|nullptr")

def _aliases(code: str, var: str) -> Set[str]:
    """沿赋值链收集 var 的别名 (p=q / q=p)。"""
    aliases = {var}
    for m in re.finditer(r"(\w+)\s*=\s*(\w+)\s*;", code):
        a, b = m.group(1), m.group(2)
        if a in aliases and b.isidentifier():
            aliases.add(b)
        elif b in aliases and a.isidentifier():
            aliases.add(a)
    return aliases

def _uses_after(code: str, var: str, free_end: int,
                aliases: Set[str]) -> List[Dict]:
    """C4: 只收集真实解引用/传参使用, 忽略标识符表面出现。

    真实使用形态:
      p->field, p[expr], *p, &p[..], func(p), *(p+..)
    """
    uses = []
    after = code[free_end:]

    # 字段解引用: var->field
    for m in re.finditer(rf"\b(\w+)\s*->\s*\w+", after):
        if m.group(1) in aliases:
            uses.append({"type": "deref_field", "var": m.group(1),
                         "pos": free_end + m.start(), "ctx": m.group(0)[:40]})
    # 下标解引用: var[expr]
    for m in re.finditer(rf"\b(\w+)\s*\[", after):
        if m.group(1) in aliases:
            uses.append({"type": "deref_index", "var": m.group(1),
                         "pos": free_end + m.start(), "ctx": m.group(0)[:40]})
    # 指针解引用: *var
    for m in re.finditer(rf"\*\s*(\w+)", after):
        if m.group(1) in aliases:
            uses.append({"type": "deref_pointer", "var": m.group(1),
                         "pos": free_end + m.start(), "ctx": m.group(0)[:40]})
    # 传参逃逸: func(var) / func(..., var, ...)
    for m in re.finditer(
        r"\b(?!if|while|for|return|sizeof|switch|case|free)\w+\s*"
        r"\(\s*([^()]*)\)", after):
        if re.search(rf"\b(?:{'|'.join(re.escape(a) for a in aliases)})\b",
                     m.group(1)):
            uses.append({"type": "passed",
                         "var": re.search(r"\b(\w+)\b", m.group(1)).group(1),
                         "pos": free_end + m.start(), "ctx": m.group(0)[:40]})
    # 去重 (同一位置多个别名命中)
    seen = set()
    out = []
    for u in uses:
        key = (u["pos"], u["type"])
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out

def _nulled_after(code: str, var: str, free_end: int,
                  aliases: Set[str]) -> bool:
    """C1: 某别名在 free 后赋 NULL。"""
    after = code[free_end:]
    for v in aliases:
        for m in re.finditer(rf"{re.escape(v)}\s*=\s*(NULL|nullptr|\b0\b)", after):
            # 排除 0 出现在数组下标等场景的粗匹配: 要求紧随赋值
            return True
    return False

def _reallocated_after(code: str, var: str, free_end: int,
                       aliases: Set[str]) -> bool:
    """C2: 某别名在 free 后重新分配 (容忍 (type*) 类型转换)。"""
    after = code[free_end:]
    for v in aliases:
        if re.search(rf"{re.escape(v)}\s*=\s*(?:\([^)]*\*\s*\)\s*)?"
                     r"(?:malloc|calloc|realloc|new)\s*\(", after):
            return True
    return False

def _free_is_conditional(code: str, free_end: int) -> bool:
    """free 是否位于 if(...) 块内 (条件释放)。"""
    seg = code[:free_end]
    # 找 free 的最近包裹 if
    brace_chain = []
    depth = 0
    for i in range(free_end - 1, -1, -1):
        ch = seg[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth > 0:
                depth -= 1
            else:
                brace_chain.append(i)
    for bpos in brace_chain:
        before = seg[max(0, bpos - 200):bpos]
        if re.search(r"if\s*\([^()]*\)\s*\{{?\s*$", before) or \
           re.search(r"if\s*\([^()]*\)\s*$", before):
            return True
    return False

def _use_is_conditional(code: str, free_end: int, use_pos: int) -> bool:
    """use 是否位于 if(...) 块内 (条件使用)。"""
    seg = code[free_end:use_pos]
    return bool(re.search(r"if\s*\([^()]*\)\s*\{", seg))

def _use_in_else_after_free(code: str, free_end: int, use_pos: int) -> bool:
    """free 在 if 块内且 use 位于对应 else 块 → 分支互斥。"""
    seg = code[free_end:use_pos]
    m = re.search(r"\}\s*else\s*\{", seg)
    if not m:
        return False
    return True  # use 位于 else 分支内

def _refcount_guarded_free(code: str, var: str, free_end: int) -> bool:
    """refcount 保护释放: free 位于 if(--var->refs==0) 等计数守卫内。"""
    seg = code[:free_end]
    return bool(re.search(rf"--\s*{re.escape(var)}\s*->\s*(refs?|count)\b",
                          seg)) or \
        bool(re.search(rf"{re.escape(var)}\s*->\s*(refs?|count)\s*--",
                       seg))

def _realloc_invalidations(code: str) -> List[Tuple[str, int, str]]:
    """realloc 使旧指针失效: new = realloc(old, n) → old 被释放。

    返回 [(old_var, realloc_end, new_var), ...]。
    """
    out = []
    for m in re.finditer(
        r"\b(\w+)\s*=\s*(?:\([^)]*\*\s*\)\s*)?realloc\s*\(\s*(\w+)\s*,", code):
        out.append((m.group(2), m.end(), m.group(1)))
    return out

def _guard_path_between(code: str, var: str, free_end: int,
                        use_pos: int) -> bool:
    """C3: 使用点是否位于 if(var) 守卫块内且守卫在 free 之后。

    判定: 在 free 与 use 之间找到 if(var) 块; 若该块在 use_pos 处
    仍未闭合 (深度 >0), 则使用点位于守卫块内 → 可安全访问。
    """
    seg = code[free_end:use_pos]
    m = re.search(
        rf"if\s*\(\s*{re.escape(var)}\s*(?:!=\s*(?:NULL|nullptr|0))?\s*\)\s*\{{",
        seg)
    if not m:
        return False
    depth = 0
    for i in range(m.end(), len(seg)):
        if seg[i] == "{":
            depth += 1
        elif seg[i] == "}":
            depth -= 1
            if depth == 0:
                return False  # 守卫块在 use 前闭合 → use 在守卫外
    return True  # 守卫块未闭合 → use 在守卫内

def detect_uaf_fcv3(code: str, func_name: str = "") -> List[Dict]:
    """UAF-FC 主入口: 返回 UAF 发现列表 (格式与 uaf_detector_v2 兼容)。"""
    findings = []
    events = []  # (var, free_end, is_realloc_invalidation)
    for m in re.finditer(r"\bfree\s*\(\s*(\w+)\s*\)", code):
        events.append((m.group(1), m.end(), False))
    for old_var, realloc_end, new_var in _realloc_invalidations(code):
        events.append((old_var, realloc_end, True))

    for var, free_end, is_realloc in events:
        aliases = _aliases(code, var)

        uses = _uses_after(code, var, free_end, aliases)
        if not uses:
            continue  # 无真实解引用 → 无 UAF 条件

        nulled = _nulled_after(code, var, free_end, aliases)
        reallocated = _reallocated_after(code, var, free_end, aliases)
        first_use = uses[0]["pos"]

        conf = 0.85
        reasons = []
        # 逃逸: 传入函数 (回调/存储)
        escaped = any(u["type"] == "passed" for u in uses)
        if escaped:
            conf = min(0.95, conf + 0.08)
            reasons.append("指针传入函数→逃逸")
        else:
            conf = max(0.40, conf - 0.20)
            reasons.append("未逃逸→局部")

        # 状态压制
        if nulled:
            conf = 0.05
            reasons.append("C1:free后置NULL→空指针解引用而非UAF")
        elif reallocated:
            conf = 0.05
            reasons.append("C2:free后重分配→指向新对象")
        elif _refcount_guarded_free(code, var, free_end):
            conf = 0.05
            reasons.append("C3:refcount计数保护→计数归零才释放")
        else:
            free_cond = _free_is_conditional(code, free_end)
            use_cond = _use_is_conditional(code, free_end, first_use)
            use_else = _use_in_else_after_free(code, free_end, first_use)
            if free_cond and (use_cond or use_else):
                conf = 0.05
                reasons.append("C3:条件释放+条件/else使用→路径互斥")
            elif _guard_path_between(code, var, free_end, first_use):
                conf = 0.05
                reasons.append("C3:守卫路径 if(var) 内→可安全访问")
            elif first_use - free_end < 60:
                conf = min(0.95, conf + 0.05)
                reasons.append("释放后立即解引用")
            if uses[0]["type"] == "deref_field":
                conf = min(0.95, conf + 0.05)
                reasons.append("字段解引用→高置信")

        if conf < 0.25:
            continue  # 被状态分析压制 → 不告警

        findings.append({
            "type": "use-after-free", "cwe": "CWE-416",
            "function": func_name, "variable": var,
            "aliases": sorted(aliases),
            "escaped": escaped,
            "nulled_after_free": nulled,
            "reallocated_after_free": reallocated,
            "use_count": len(uses),
            "uses": uses[:5],
            "severity": "Critical" if conf > 0.70 else "High",
            "confidence": round(conf, 2),
            "description": f"UAF-FC: {var} 释放后解引用 "
                           f"({'realloc失效' if is_realloc else 'free后'}, "
                           f"{len(uses)} uses) " + "; ".join(reasons),
        })

    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings

if __name__ == "__main__":
    samples = [
        "free(p);\nif (p) { p->f = 1; }\n",                       # 空态→安全
        "free(p);\np = malloc(64);\np->f = 1;\n",                 # 重赋值→安全
        "free(p);\nq = p;\nq->f = 1;\n",                          # 别名UAF
        "free(p);\np->f = 1;\n",                                  # 直接UAF
        "free(p);\nfunc(p);\n",                                   # 传参逃逸UAF
    ]
    for s in samples:
        print("=", repr(s))
        for f in detect_uaf_fcv3(s):
            print("  ", f["confidence"], f["description"])
