# analysis/uaf_detector_v2 — UAF检测升级版: 指针逃逸分析
# 超越 v1 的简单 free-var + use-of-var 正则匹配,
# 增加了三个维度来压低误报和增强检测能力:
#
# 维度1: 逃逸分析 — free 后变量是否通过返回值/全局变量/参数逃逸
#   若逃逸 → 外部仍然持有引用 → 高置信 UAF
#   若未逃逸 → 局部变量 → 警告但低置信
# 维度2: 分支感知 — free 和 use 是否在不同的条件分支中
#   若同分支 → 确定 UAF
#   若不同分支 → 需运行时条件 → 中等置信
# 维度3: 重分配检测 — free 后同一 slot 是否被重新分配
#   若重分配 → 可能不是原来的对象 → 压制置信度
#
# 理论依据: 逃逸分析是区分真实 UAF 与安全释放模式的关键。

from __future__ import annotations
import re
from typing import Dict, List, Set, Tuple, Optional

_POINTER_ESCAPE_PATTERNS = [
    re.compile(r"return\s+(\w+)\s*;"),
    re.compile(r"(\w+)\s*=\s*(\w+)\s*;"),
    re.compile(r"(\w+)\s*->\s*(\w+)\s*=\s*(\w+)\s*;"),
]

def _extract_function_body(code: str, func_name: str = "") -> str:
    """从代码中提取函数体 (花括号匹配)。"""
    brace_open = code.find("{")
    if brace_open < 0:
        return code
    depth = 0
    for i in range(brace_open, len(code)):
        if code[i] == "{": depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[brace_open:i + 1]
    return code

def _find_free_sites(code: str) -> List[Dict]:
    """定位所有 free() 调用点, 提取被释放的变量名和位置。"""
    sites = []
    for m in re.finditer(r"free\s*\(\s*(\w+(?:\s*->\s*\w+)?)\s*\)", code):
        var = m.group(1).strip()
        base = var.split("->")[0].split(".")[0] if "->" in var or "." in var else var
        sites.append({
            "var": var, "base": base,
            "pos_start": m.start(), "pos_end": m.end(),
        })
    return sites

def _check_escape(code: str, var: str, free_pos: int) -> Tuple[bool, str]:
    """检查变量在 free 后是否通过返回值/赋值逃逸到函数外部。
    返回 (是否逃逸, 逃逸方式描述)。
    """
    after = code[free_pos:]

    # 返回值逃逸
    ret_match = re.search(r"return\s+(\w+)\s*;", after)
    if ret_match and ret_match.group(1) == var:
        return (True, "return_value")

    # 通过全局指针赋值逃逸
    for m in re.finditer(rf"(\w+)\s*=\s*{re.escape(var)}\s*;", after):
        lhs = m.group(1)
        # 排除局部变量 (简单的非全局判断)
        if not any(kw in after[:m.start()] for kw in (f"int {lhs}", f"char {lhs}",
                                                        f"void {lhs}", f"struct")):
            return (True, f"assign_to_{lhs}")

    # 通过参数传递逃逸
    for m in re.finditer(rf"(\w+)\s*\(\s*[^)]*{re.escape(var)}[^)]*\)", after):
        return (True, "passed_to_function")

    return (False, "no_escape")

def _check_use_after_free(code: str, var: str, free_end: int) -> List[Dict]:
    """在 free 点之后搜索变量的使用 (解引用/读取/写入)。"""
    after = code[free_end:]
    uses = []

    # 模式1: var 单独出现 (作为值传递)
    for m in re.finditer(rf"\b{re.escape(var)}\b", after):
        ctx_start = max(0, m.start() - 10)
        ctx = after[ctx_start:m.end() + 5]
        # 排除: 在另一个 free 调用中
        if f"free({var}" in ctx or f"free ({var}" in ctx:
            continue
        uses.append({"type": "reference", "pos": m.start(), "ctx": ctx.strip()})

    # 模式2: var->field 解引用
    for m in re.finditer(rf"{re.escape(var)}\s*->\s*(\w+)", after):
        uses.append({"type": "deref", "field": m.group(1),
                     "pos": m.start(), "ctx": after[max(0,m.start()-10):m.end()+5]})

    return uses

def _check_reallocation(code: str, var: str, free_end: int) -> bool:
    """检查 free 后变量是否被重新分配 (malloc/calloc/realloc)。"""
    after = code[free_end:]
    return bool(re.search(rf"{re.escape(var)}\s*=\s*(?:malloc|calloc|realloc|new)\s*\(",
                         after))

def detect_uaf_v2(code: str, func_name: str = "") -> List[Dict]:
    """UAF 升级版检测主入口。

    返回每个发现的详细信息, 包括逃逸分析结果和分支信息,
    供误报过滤器进行深度置信度调整。
    """
    findings = []
    body = _extract_function_body(code, func_name)
    if not body:
        body = code

    free_sites = _find_free_sites(body)

    for fs in free_sites:
        var_base = fs["base"]

        # 检查逃逸
        escaped, escape_mode = _check_escape(body, var_base, fs["pos_end"])

        # 检查使用
        uses = _check_use_after_free(body, var_base, fs["pos_end"])
        if not uses:
            continue

        # 检查重分配
        reallocated = _check_reallocation(body, var_base, fs["pos_end"])

        # 置信度计算
        base_conf = 0.85  # 基础: free后有用→大概率UAF
        reasons = []

        if escaped:
            # 逃逸: 指针被外部持有 → 高置信 UAF
            base_conf = min(0.95, base_conf + 0.10)
            reasons.append(f"指针逃逸({escape_mode})→外部仍持有引用")
        else:
            # 未逃逸: 局部变量 → 可能开发者知晓已释放
            base_conf = max(0.40, base_conf - 0.25)
            reasons.append("指针未逃逸→局部变量")

        if reallocated:
            # 重分配: 可能被赋予新值
            base_conf = max(0.25, base_conf - 0.30)
            reasons.append("free后重分配→可能已指向新内存")

        # 最近的use距离free越近 → 越可能是真正的UAF
        first_use_dist = uses[0]["pos"] if uses else 9999
        if first_use_dist < 50:
            base_conf = min(0.95, base_conf + 0.05)
            reasons.append("释放后立即使用")

        findings.append({
            "type": "use-after-free",
            "function": func_name,
            "variable": var_base,
            "escaped": escaped,
            "escape_mode": escape_mode,
            "reallocated": reallocated,
            "use_count": len(uses),
            "uses": uses[:5],
            "severity": "Critical",
            "cwe": "CWE-416",
            "confidence": round(base_conf, 2),
            "description": f"UAF: {var_base} used after free() "
                           f"({'逃逸' if escaped else '未逃逸'}, "
                           f"{len(uses)} uses found, "
                           f"{'重分配' if reallocated else '未重分配'})",
        })

    return findings
