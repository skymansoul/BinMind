"""CorrelatedWrapCheck - 相关回绕检查 (stage 59).

对 a*b+c、(a+b)<<k 等复合表达式建运算树, 检测任一子节点回绕但父节点
吸收 (mask 截断 / 移位补0) 的场景, 定位"中间回绕被吸收"型漏报.
与 INT-RANGE 区间传播不同: 运算树匹配 + 吸收判定.

设计决策:
  - 将表达式解析为二元运算树 (mul/add/shl/mask)
  - 对叶子求常量估值, 子节点若乘法/移位溢出则标记 wrap
  - 父节点若做 & mask 或 << 低位补0则"吸收", 吸收后整体视为漏报候选; 加法不吸收
"""

import re
from typing import List, Optional, Tuple


class _Node:
    """极简运算树节点."""
    __slots__ = ("op", "left", "right", "val", "wrap")

    def __init__(self, op: str = "", left: "_Node" = None,
                 right: "_Node" = None, val: Optional[int] = None):
        self.op = op
        self.left = left
        self.right = right
        self.val = val
        self.wrap = False


def _parse_expr(s: str) -> _Node:
    """把简单算术表达式解析为树 (仅支持 + - * << & 与整数)."""
    s = s.strip()
    # 括号
    if s.startswith("(") and s.endswith(")"):
        return _parse_expr(s[1:-1])
    # 按C优先级从低到高分割: & < << < +/- < *
    for op in ("&", "<<", "+", "-", "*"):
        idx = _find_op(s, op)
        if idx is not None:
            left = _parse_expr(s[:idx])
            right = _parse_expr(s[idx + len(op):])
            return _Node(op=op, left=left, right=right)
    # 叶子
    m = re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", s)
    return _Node(val=int(s, 0) if m else None)


def _find_op(s: str, op: str) -> Optional[int]:
    """从右往左找不处于括号内的运算符位置."""
    depth = 0
    for i in range(len(s) - 1, -1, -1):
        c = s[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
        elif depth == 0 and s.startswith(op, i):
            return i
    return None


def _mark_wrap(node: _Node) -> bool:
    """递归标记节点回绕. 返回该子树是否回绕."""
    if node.val is not None:
        return False
    lw = _mark_wrap(node.left) if node.left else False
    rw = _mark_wrap(node.right) if node.right else False
    lv = node.left.val if node.left else None
    rv = node.right.val if node.right else None
    if node.op == "*":
        node.wrap = (lv is not None and rv is not None and lv * rv > 2**32 - 1)
    elif node.op == "<<":
        node.wrap = (lv is not None and rv is not None and (lv << rv) > 2**32 - 1)
    elif node.op == "+":
        node.wrap = (lv is not None and rv is not None and lv + rv > 2**32 - 1)
    elif node.op == "-":
        node.wrap = (lv is not None and rv is not None and lv - rv < 0)
    else:
        node.wrap = False
    return node.wrap or lw or rw


def _find_absorbed_wrap(node: _Node, out: List[str]) -> None:
    """寻找子节点回绕但父节点吸收的场景.

    只有 & mask (掩码常量) 能真正吸收子节点回绕;
    << 低位补0 视为部分吸收; 加法不能吸收回绕.
    """
    if node.op == "&" and (node.left.wrap or node.right.wrap):
        out.append(f"absorbed_wrap: parent '&' masks wrapped child")
    if node.op == "<<" and (node.left.wrap or node.right.wrap):
        # 移位低位补0, 部分吸收子节点回绕
        out.append(f"absorbed_wrap: parent '<<' partially absorbs wrapped child")
    for child in (node.left, node.right):
        if child:
            _find_absorbed_wrap(child, out)


def run_correlated_wrap_check(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """复合表达式回绕检查. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 匹配形如 x = a*b+c; 或 (a+b)<<k 的赋值
        m = re.search(r"(\w+)\s*=\s*(.+);", line)
        if not m:
            continue
        expr = m.group(2)
        try:
            tree = _parse_expr(expr)
        except Exception:
            continue
        _mark_wrap(tree)
        absorbed: List[str] = []
        _find_absorbed_wrap(tree, absorbed)
        if absorbed:
            findings.append({
                "type": "integer_overflow",
                "function": func_name or "unknown",
                "severity": "high",
                "cwe": "CWE-190",
                "confidence": 0.7,
                "description": f"line{ln} {'; '.join(absorbed)}",
                "verdict": "missed_wrap",
                "source": "correlated_wrap_check",
            })
    # C 风格掩码折叠检测: 变量赋值含 & 0xMASK / % CONST 且结果用于下标写
    # 收集含掩码的赋值变量名与对应行号
    mask_assigns: List[Tuple[str, int, str]] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # off = (expr) & 0xFF 或 off = expr % CONST
        m_mask = re.search(r"(\w+)\s*=\s*.+\s*&\s*(0[xX][0-9a-fA-F]+|\d+)", line)
        if not m_mask:
            m_mask = re.search(r"(\w+)\s*=\s*.+\s*%\s*(\d+)", line)
        if m_mask:
            mask_var = m_mask.group(1)
            mask_val = m_mask.group(2)
            mask_assigns.append((mask_var, ln, mask_val))
    # 检查掩码变量是否用于下标写
    for mask_var, mask_ln, mask_val in mask_assigns:
        for ln, line in enumerate(pseudocode.splitlines(), 1):
            m_sub = re.search(r"(\w+)\[([^\]]*)\]\s*=", line)
            if m_sub and mask_var in m_sub.group(2):
                findings.append({
                    "type": "integer_overflow",
                    "function": func_name or "unknown",
                    "severity": "high",
                    "cwe": "CWE-190",
                    "confidence": 0.7,
                    "description": f"line{mask_ln} mask {mask_val} folds wrap of "
                                   f"{mask_var} used in subscript write line{ln}",
                    "verdict": "missed_wrap",
                    "source": "correlated_wrap_check",
                })
                break
    return findings


if __name__ == "__main__":
    demo = """\
size_t n = a * b + c;
n = (a + b) << 2;
"""
    out = run_correlated_wrap_check(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])