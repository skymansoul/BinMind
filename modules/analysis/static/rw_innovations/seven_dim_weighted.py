"""SevenDimWeighted - 七维加权融合 (stage 90).

7 个独立证据维度加权投票: 常量差/守卫/slack/循环/别名/污点/阈值,
任一 SAFE 一票否决. 与 仿射边界验证 维度不同: 本模块维度独立且投票.

设计决策:
  - 七维: const_diff, guard, slack, loop, alias, taint, threshold
  - 每维输出 SAFE/UNSAFE/UNKNOWN
  - 任一 SAFE -> 一票否决整体安全
  - 否则加权投票决定
"""

import re
from typing import Dict, List, Optional

_DIMS = ("const_diff", "guard", "slack", "loop", "alias", "taint", "threshold")
_WEIGHTS = {"const_diff": 0.2, "guard": 0.2, "slack": 0.1, "loop": 0.1,
            "alias": 0.15, "taint": 0.1, "threshold": 0.15}


def _extract_write_index(pseudocode: str, var: str) -> Optional[str]:
    """从写点 [var+N] 提取索引变量名(若写点形如 [base+idx])."""
    m = re.search(r"\[\s*" + re.escape(var) + r"\s*\+\s*(\w+)\s*\]", pseudocode)
    return m.group(1) if m else None


def _eval_guard(pseudocode: str, var: str) -> str:
    """守卫约束写点索引变量且上界可提取才计SAFE."""
    idx = _extract_write_index(pseudocode, var)
    if not idx:
        return "UNKNOWN"
    # 查找 if 行内对 idx 的上界约束: if (idx < N) 或 if (idx <= N)
    for line in pseudocode.splitlines():
        if re.search(r"if\s*\(", line) and re.search(
            r"\b" + re.escape(idx) + r"\s*(?:<|<=)\s*(\w+)", line
        ):
            return "SAFE"
    return "UNKNOWN"


def _eval_alias(pseudocode: str, var: str) -> str:
    """别名沿赋值链可达分配点: q=var 且写点在q上才计SAFE."""
    alias_pattern = r"\b(\w+)\s*=\s*" + re.escape(var) + r"\b"
    aliases = re.findall(alias_pattern, pseudocode)
    if not aliases:
        return "UNKNOWN"
    for alias in aliases:
        if re.search(r"\[\s*" + re.escape(alias) + r"\s*[\+\-]", pseudocode):
            return "SAFE"
    return "UNKNOWN"


def _eval_threshold(pseudocode: str, var: str) -> str:
    """阈值: <=出现在if行内且约束写点索引变量才计SAFE."""
    idx = _extract_write_index(pseudocode, var)
    if not idx:
        return "UNKNOWN"
    for line in pseudocode.splitlines():
        if re.search(r"if\s*\(", line) and re.search(
            r"\b" + re.escape(idx) + r"\s*<=\s*\w+", line
        ):
            return "SAFE"
    return "UNKNOWN"


def _dim_evidence(pseudocode: str, var: str) -> Dict[str, str]:
    """计算七维证据."""
    ev: Dict[str, str] = {}
    # 常量差: 写偏移+写宽度 与分配大小比较
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    m_write = re.search(r"\[\s*" + re.escape(var) + r"\s*\+\s*(\d+)\s*\]\s*(?:,|=)\s*(\w+)", pseudocode)
    if m_alloc and m_write:
        offset = int(m_write.group(1))
        operand = m_write.group(2)
        # 写宽度从操作数推断: 64位寄存器8, 32位寄存器4, 8位寄存器1, 立即数按4
        if operand.startswith("r"):
            width = 8
        elif operand.startswith("e"):
            width = 4
        elif len(operand) == 2 and operand[1] in "lh":
            width = 1
        else:
            width = 4  # 立即数默认4字节
        ev["const_diff"] = "SAFE" if offset + width <= int(m_alloc.group(1)) else "UNSAFE"
    else:
        ev["const_diff"] = "UNKNOWN"
    # 守卫: 必须约束写点用到的索引变量且上界可提取才计SAFE
    ev["guard"] = _eval_guard(pseudocode, var)
    # slack
    ev["slack"] = "SAFE" if re.search(r"slack", pseudocode, re.I) else "UNKNOWN"
    # 循环
    ev["loop"] = "UNSAFE" if re.search(r"while|for", pseudocode) else "UNKNOWN"
    # 别名: 别名必须沿赋值链可达分配点(别名目标=malloc变量且写点在别名上)才计SAFE
    ev["alias"] = _eval_alias(pseudocode, var)
    # 污点
    ev["taint"] = "UNSAFE" if re.search(r"scanf|recv|argv", pseudocode) else "UNKNOWN"
    # 阈值: <=必须出现在守卫上下文(if行内)且约束写点索引变量才计SAFE
    ev["threshold"] = _eval_threshold(pseudocode, var)
    return ev


def _c_eval_const_diff(pseudocode: str, var: str) -> str:
    """C 风格常量差: memcpy 写大小或下标写偏移 vs 分配大小(常量或符号)."""
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    m_alloc_sym = re.search(r"malloc\s*\(\s*(\w+)\s*\)", pseudocode)
    # memcpy 写大小 vs 常量分配
    m_mc = re.search(r"\bmemcpy\s*\(\s*" + re.escape(var) + r"\s*,\s*\w+\s*,\s*(\w+)\s*\)", pseudocode)
    if m_mc:
        sz_txt = m_mc.group(1)
        if m_alloc:
            return "SAFE" if int(sz_txt) <= int(m_alloc.group(1)) else "UNSAFE"
        return "UNKNOWN"
    # 下标写偏移 vs 常量分配
    if m_alloc:
        alloc_sz = int(m_alloc.group(1))
        m_idx = re.search(r"\b" + re.escape(var) + r"\[\s*(\w+)\s*\+\s*(\d+)\s*\]\s*=", pseudocode)
        if m_idx:
            return "UNSAFE"
        m_idx2 = re.search(r"\b" + re.escape(var) + r"\[\s*(\d+)\s*\]\s*=", pseudocode)
        if m_idx2:
            return "SAFE" if int(m_idx2.group(1)) < alloc_sz else "UNSAFE"
    # 符号分配 malloc(n) + 偏移 n+const → UNSAFE
    if m_alloc_sym and not m_alloc:
        alloc_sym = m_alloc_sym.group(1)
        m_idx = re.search(r"\b" + re.escape(var) + r"\[\s*" + re.escape(alloc_sym) + r"\s*\+\s*(\d+)\s*\]\s*=", pseudocode)
        if m_idx:
            return "UNSAFE"
        # 归纳变量直接下标且分配为 n*mul
        m_mul = re.search(r"malloc\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)", pseudocode)
        m_loop = re.search(r"for\s*\(\s*(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+)\s*;", pseudocode)
        if m_mul and m_loop:
            if re.search(r"\b" + re.escape(var) + r"\[\s*" + re.escape(m_loop.group(1)) + r"\s*\]", pseudocode):
                return "SAFE"
    return "UNKNOWN"


def _c_eval_guard(pseudocode: str, var: str) -> str:
    """C 风格守卫: if 约束索引变量上界."""
    m_idx = re.search(r"\b" + re.escape(var) + r"\[\s*(\w+)\s*(?:\+\s*\d+)?\s*\]\s*=", pseudocode)
    if not m_idx:
        return "UNKNOWN"
    idx_var = m_idx.group(1)
    for line in pseudocode.splitlines():
        if re.search(r"if\s*\(", line) and re.search(r"\b" + re.escape(idx_var) + r"\s*(?:<|<=)\s*\w+", line):
            return "SAFE"
    return "UNKNOWN"


def _c_eval_loop(pseudocode: str, var: str) -> str:
    """C 风格循环维度: 有循环且归纳变量直接做下标 -> 需配合分配大小判断."""
    m_loop = re.search(r"for\s*\(\s*(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+)", pseudocode)
    if not m_loop:
        return "UNKNOWN"
    loop_var = m_loop.group(1)
    # 归纳变量直接做下标且有 n*mul 分配
    m_alloc = re.search(r"malloc\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)", pseudocode)
    if m_alloc and re.search(r"\b" + re.escape(var) + r"\[\s*" + re.escape(loop_var) + r"\s*\]", pseudocode):
        alloc_sym = m_alloc.group(1)
        alloc_mul = int(m_alloc.group(2))
        if alloc_sym == m_loop.group(2) and alloc_mul >= 1:
            return "SAFE"
        return "UNSAFE"
    # 步长写入: buf[i*stride]
    m_stride = re.search(r"\b" + re.escape(var) + r"\[\s*" + re.escape(loop_var) + r"\s*\*\s*(\d+)\s*\]", pseudocode)
    if m_stride:
        return "UNSAFE"
    return "UNKNOWN"


def _c_eval_slack(pseudocode: str, var: str) -> str:
    """C 风格 slack: memcpy 写大小或下标偏移超出分配边界."""
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    m_mc = re.search(r"\bmemcpy\s*\(\s*" + re.escape(var) + r"\s*,\s*\w+\s*,\s*(\d+)\s*\)", pseudocode)
    if m_mc and m_alloc:
        return "UNSAFE" if int(m_mc.group(1)) > int(m_alloc.group(1)) else "UNKNOWN"
    m_idx = re.search(r"\b" + re.escape(var) + r"\[\s*(\w+)\s*\+\s*(\d+)\s*\]\s*=", pseudocode)
    if m_idx:
        return "UNSAFE"
    return "UNKNOWN"


def _c_eval_taint(pseudocode: str) -> str:
    """C 风格污点: scanf/recv/argv 或 memcpy 源为 input 等外部输入."""
    if re.search(r"\bscanf\b|\brecv\b|\bargv\b", pseudocode):
        return "UNSAFE"
    m_mc = re.search(r"\bmemcpy\s*\(\s*\w+\s*,\s*(\w+)\s*,", pseudocode)
    if m_mc and m_mc.group(1) in ("input", "src", "user", "buf_in"):
        return "UNSAFE"
    return "UNKNOWN"


def _c_eval_threshold(pseudocode: str, var: str) -> str:
    """C 风格阈值: 有下标写但无守卫约束索引变量 -> UNSAFE."""
    m_idx = re.search(r"\b" + re.escape(var) + r"\[\s*(\w+)\s*(?:\+\s*\d+)?\s*\]\s*=", pseudocode)
    if not m_idx:
        return "UNKNOWN"
    idx_var = m_idx.group(1)
    for line in pseudocode.splitlines():
        if re.search(r"if\s*\(", line) and re.search(r"\b" + re.escape(idx_var) + r"\s*(?:<|<=)\s*\w+", line):
            return "SAFE"
    return "UNSAFE"


def _c_dim_evidence(pseudocode: str, var: str) -> Dict[str, str]:
    """C 风格七维证据."""
    ev: Dict[str, str] = {}
    ev["const_diff"] = _c_eval_const_diff(pseudocode, var)
    ev["guard"] = _c_eval_guard(pseudocode, var)
    ev["slack"] = _c_eval_slack(pseudocode, var)
    ev["loop"] = _c_eval_loop(pseudocode, var)
    ev["alias"] = "UNKNOWN"
    ev["taint"] = _c_eval_taint(pseudocode)
    ev["threshold"] = _c_eval_threshold(pseudocode, var)
    return ev


def _has_c_syntax(pseudocode: str) -> bool:
    """判断是否为 C 风格伪代码."""
    return bool(re.search(r"\bmemcpy\b|\bmalloc\b.*\(|\*\s*malloc|\bfor\s*\(", pseudocode)) and bool(re.search(r"->|;|\bint\b|\bchar\b|\bvoid\b|\bstruct\b", pseudocode))


def run_seven_dim_weighted(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """七维加权融合. 返回 findings."""
    findings: List[dict] = []
    # 分配变量
    alloc_vars = re.findall(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(",
        pseudocode)
    if not alloc_vars:
        return findings
    var = alloc_vars[0]
    # C 风格优先
    if _has_c_syntax(pseudocode):
        ev = _c_dim_evidence(pseudocode, var)
    else:
        ev = _dim_evidence(pseudocode, var)
    # 一票否决
    if any(v == "SAFE" for v in ev.values()):
        verdict, conf = "veto_safe", 0.95
    else:
        # 加权投票
        score = sum(_WEIGHTS[d] for d, v in ev.items() if v == "UNSAFE")
        verdict = "weighted_unsafe" if score >= 0.4 else "weighted_unknown"
        conf = round(score, 2)
    findings.append({
        "type": "heap_overflow",
        "function": func_name or "unknown",
        "severity": "medium",
        "cwe": "CWE-122",
        "confidence": conf,
        "description": f"var={var} evidence={ev}",
        "verdict": verdict,
        "source": "seven_dim_weighted",
    })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (p != NULL) { }
mov [p+8], 0x4;
"""
    out = run_seven_dim_weighted(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])