"""FourLevelAdjudicator - 四级裁断链 (stage 88).

溢出嫌疑->指针溯源->守卫窄化->偏移判定的固定四级链, 每级输出
decisive_level. 与 absint_adjudicator 结构同源但输入为伪代码.
与 four_verdict_scale 区分: 本模块是链式逐级 gate 裁决, 每级用
独立特征复核上级结论; scale 是后置概率四档标尺.

设计决策:
  - L1 溢出嫌疑: 写点是否可能越界 (常量比较)
  - L2 指针溯源: 写基址是否溯源到堆分配 (分配点行号溯源, 非
    L1 正则复用; 复核失败则链在 L2 截断)
  - L3 守卫窄化: 是否有守卫约束偏移
  - L4 偏移判定: 精确比较偏移+写大小 vs 分配大小
  - 每级输出 decisive_level (0-4), 下级只在上级通过时执行
"""

import re
from typing import List, Optional


def _narrow_offset(line: str) -> Optional[int]:
    """从写点提取常量偏移."""
    m = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]", line)
    return int(m.group(1)) if m else None


def _write_width(line: str) -> int:
    """从写操作行推断写入字节数. 取不到时保守用 8 字节."""
    line = line.strip()
    # 行内宽度前缀优先
    if re.search(r"\bqword\b", line, re.IGNORECASE):
        return 8
    if re.search(r"\bdword\b", line, re.IGNORECASE):
        return 4
    if re.search(r"\bword\b", line, re.IGNORECASE):
        return 2
    if re.search(r"\bbyte\b", line, re.IGNORECASE):
        return 1
    # 寄存器源宽度
    m_reg = re.search(r"\[[^\]]*\]\s*(?:,|=)\s*([A-Za-z][A-Za-z0-9]*)", line)
    if m_reg:
        name = m_reg.group(1).lower()
        if name.startswith("r") and len(name) >= 2:
            return 8
        if name.startswith("e"):
            return 4
        if len(name) == 2 and name[0] in ("a", "b", "c", "d"):
            return 1
    # 立即数默认 4 字节, 但 L4 保守判定取不到时用 8
    return 4


def _c_alloc_origin(pseudocode: str, alloc_var: str) -> Optional[int]:
    """L2 指针溯源: 定位分配点行号, 与 L1 的写点正则相互独立.

    返回 alloc_var 首次绑定到分配调用的行号, 找不到返回 None.
    溯源失败 -> 链在 L2 截断, 不再执行 L3/L4.
    """
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(
            r"\b" + re.escape(alloc_var) + r"\s*=\s*(?:\([^)]*\)\s*)?"
            r"(?:malloc|calloc|realloc)\b",
            line,
        )
        if m:
            return ln
    return None


def _c_alloc_info(pseudocode: str):
    """C 风格分配解析: 返回 (变量名, 常量大小或None, (分配变量, 乘数) 或None)."""
    m = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m:
        return m.group(1), int(m.group(2)), None
    m = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)", pseudocode)
    if m:
        return m.group(1), None, (m.group(2), int(m.group(3)))
    m = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\w+)\s*\)", pseudocode)
    if m:
        return m.group(1), None, (m.group(2), 1)
    return None


def _c_writes(pseudocode: str, alloc_var: str) -> list:
    """检测 C 风格写操作: memcpy 和数组下标写."""
    writes = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\bmemcpy\s*\(\s*" + re.escape(alloc_var) + r"\s*,\s*\w+\s*,\s*(\d+)\s*\)", line)
        if m:
            writes.append((ln, line, alloc_var, None, int(m.group(1)), "memcpy"))
            continue
        m = re.search(r"\b" + re.escape(alloc_var) + r"\[([^\]]+)\]\s*=", line)
        if m:
            writes.append((ln, line, alloc_var, m.group(1).strip(), None, "index"))
    return writes


def _c_has_guard(pseudocode: str, idx_expr) -> bool:
    """C 风格守卫检测: if 条件约束索引变量."""
    if not idx_expr:
        return False
    idx_var = re.search(r"\b(\w+)\b", idx_expr)
    if not idx_var:
        return False
    return bool(re.search(r"if\s*\([^)]*\b" + re.escape(idx_var.group(1)) + r"\b", pseudocode))


def _c_l4_judge(idx_expr, write_size, alloc_const, alloc_sym, pseudocode):
    """C 风格 L4 偏移判定: 1=safe, -1=overflow, 0=inconclusive."""
    # 常量 memcpy 写大小 vs 常量分配大小
    if write_size is not None and alloc_const is not None:
        return -1 if write_size > alloc_const else 1
    if idx_expr is not None and alloc_sym is not None:
        alloc_var_name, alloc_mult = alloc_sym
        # 偏移 = 分配变量 + 正常量: 超出分配边界
        m_add = re.match(r"(\w+)\s*\+\s*(\d+)$", idx_expr)
        if m_add and m_add.group(1) == alloc_var_name:
            return -1
        # 循环归纳变量且有上界守卫
        m_loop = re.search(r"for\s*\(\s*(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+)\s*;", pseudocode)
        if m_loop and m_loop.group(2) == alloc_var_name:
            loop_var = m_loop.group(1)
            if re.fullmatch(re.escape(loop_var), idx_expr):
                return 1 if alloc_mult >= 1 else -1
            m_mul = re.match(re.escape(loop_var) + r"\s*\*\s*(\d+)$", idx_expr)
            if m_mul:
                stride = int(m_mul.group(1))
                return 1 if alloc_mult >= stride else -1
    return 0


def run_four_level_adjudicator(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """四级裁断链. 返回 findings."""
    findings: List[dict] = []
    c_info = _c_alloc_info(pseudocode)
    if c_info is not None:
        alloc_var, alloc_const, alloc_sym = c_info
        # L2 独立溯源: 分配点行号与 L1 写点解析相互独立, 复核
        # L1 检出的写点是否真的溯源到堆分配
        origin_ln = _c_alloc_origin(pseudocode, alloc_var)
        c_writes = _c_writes(pseudocode, alloc_var)
        if c_writes:
            for ln, line, var, idx_expr, write_size, wtype in c_writes:
                # L1 溢出嫌疑: 写点存在即进入裁决链
                l1 = 1
                # L2 逐级 gate: 溯源失败 -> 链在 L2 截断, L3/L4 不执行
                if origin_ln is None:
                    l2, l3, l4 = 0, 0, 0
                else:
                    l2 = 1
                    l3 = 1 if _c_has_guard(pseudocode, idx_expr) else 0
                    l4 = _c_l4_judge(idx_expr, write_size, alloc_const, alloc_sym, pseudocode)
                if l4 == 1:
                    verdict, conf = "safe", 0.9
                elif l4 == -1:
                    verdict, conf = "overflow", 0.85
                else:
                    verdict, conf = "inconclusive", 0.4
                decisive = 4 if l4 != 0 else (3 if l3 else (2 if l2 else (1 if l1 else 0)))
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": conf,
                    "description": f"line{ln} L1={l1} L2={l2} L3={l3} L4={l4} "
                                   f"decisive={decisive} mode=c"
                                   + (f" origin_line={origin_ln}" if origin_ln else ""),
                    "verdict": verdict,
                    "source": "four_level_adjudicator",
                })
            return findings
    # 汇编风格回退
    alloc_size = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\w+|\d+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        var, off_txt = m.group(1), m.group(2)
        # L1 溢出嫌疑
        l1 = 1 if alloc_size is not None else 0
        # L2 指针溯源: var 是否分配变量
        l2 = 1 if re.search(r"\b" + re.escape(var) + r"\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)", pseudocode) else 0
        # L3 守卫窄化
        l3 = 1 if re.search(r"if\s*\([^)]*" + re.escape(var), pseudocode) else 0
        # L4 偏移判定: off + write_width vs alloc_size
        off = int(off_txt) if off_txt.isdigit() else None
        if l1 and l2 and off is not None and alloc_size is not None:
            ww = _write_width(line)
            if ww < 8:
                ww = 8  # 保守取不到时用 8 字节, 宁可漏判溢出
            l4 = -1 if off + ww > alloc_size else 1
        else:
            l4 = 0
        if l4 == 1:
            verdict, conf = "safe", 0.9
        elif l4 == -1:
            verdict, conf = "overflow", 0.85
        else:
            verdict, conf = "inconclusive", 0.4
        decisive = 4 if l4 != 0 else (3 if l3 else (2 if l2 else (1 if l1 else 0)))
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} L1={l1} L2={l2} L3={l3} L4={l4} "
                           f"decisive={decisive} mode=asm",
            "verdict": verdict,
            "source": "four_level_adjudicator",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (p) { }
mov [p+8], 0;
"""
    out = run_four_level_adjudicator(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])