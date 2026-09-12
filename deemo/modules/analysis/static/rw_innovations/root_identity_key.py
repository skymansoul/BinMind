"""RootIdentityKey - 根身份键 (stage 68).

alloc size 表达式与 write 地址基址表达式分别归一化为四元组
(kind, var, coeff, const) 哈希键, 若两者键相等 (同变量、同系数)
说明写操作目标地址与分配基址同源 -> identity_safe.
与 SI-CTA 链 id 不同: 表达式归一化哈希而非链传播.

设计决策:
  - alloc: 提取 malloc 参数表达式作为 alloc_size_key (保持不变)
  - write: 提取写操作的地址偏移表达式 [var+off] 而非 RHS 值
  - 归一化: 表达式 -> (kind, var, coeff, const)
  - 同根判定: alloc size 键 == write offset 基址键 -> identity_safe
  - 语义: 比较分配大小表达式与写地址基址表达式的根同源性
"""

import re
from typing import List, Optional, Tuple


def _normalize(expr: str) -> Tuple[str, str, int, int]:
    """归一化表达式 -> (kind, var, coeff, const).
    kind 为 const / var / unknown.
    """
    expr = expr.strip()
    # 纯常量
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", expr):
        return ("const", "", 0, int(expr, 0))
    # var * coeff + const
    m = re.fullmatch(r"(\w+)\s*\*\s*(\d+)\s*\+\s*(\d+)", expr)
    if m:
        return ("var", m.group(1), int(m.group(2)), int(m.group(3)))
    m = re.fullmatch(r"(\w+)\s*\*\s*(\d+)\s*\+\s*-(\d+)", expr)
    if m:
        return ("var", m.group(1), int(m.group(2)), -int(m.group(3)))
    # var + const
    m2 = re.fullmatch(r"(\w+)\s*\+\s*(\d+)", expr)
    if m2:
        return ("var", m2.group(1), 1, int(m2.group(2)))
    m2n = re.fullmatch(r"(\w+)\s*\+\s*-(\d+)", expr)
    if m2n:
        return ("var", m2n.group(1), 1, -int(m2n.group(2)))
    # var * coeff
    m3 = re.fullmatch(r"(\w+)\s*\*\s*(\d+)", expr)
    if m3:
        return ("var", m3.group(1), int(m3.group(2)), 0)
    # 纯 var
    m4 = re.fullmatch(r"(\w+)", expr)
    if m4:
        return ("var", m4.group(1), 1, 0)
    return ("unknown", "", 0, 0)


def _key(expr: str) -> Tuple[str, str, int, int]:
    """兼容旧接口, 保留 _key 不删除."""
    return _normalize(expr)


def _root(expr: str) -> Tuple[str, str, int, int]:
    """兼容旧接口, 保留 _root 不删除."""
    return _normalize(expr)


def _extract_write_offset_expr(addr_expr: str) -> str:
    """从写地址表达式 [addr] 中提取偏移表达式.
    [p+8] -> 'p+8'; [p] -> 'p'; [p+idx*4+8] -> 'p+idx*4+8'
    提取的是地址基址+偏移表达式, 而非 RHS 值.
    """
    return addr_expr.strip()


def _same_root_key(
    alloc_key: Tuple[str, str, int, int],
    write_key: Tuple[str, str, int, int],
) -> bool:
    """判定两个归一化键是否同根.
    同根条件: kind 相同, var 相同, coeff 相同 (const 可不同, 因偏移可变).
    即同一变量同一系数的地址表达式与分配表达式同源.
    """
    if alloc_key[0] == "unknown" or write_key[0] == "unknown":
        return False
    return (
        alloc_key[0] == write_key[0]
        and alloc_key[1] == write_key[1]
        and alloc_key[2] == write_key[2]
    )


def run_root_identity_key(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """根身份键判定. 返回 findings.
    比较 alloc size 表达式与 write 地址基址表达式的根同源性.
    """
    findings: List[dict] = []
    # 提取 malloc 参数表达式作为 alloc_size_key
    alloc_expr = None
    m_alloc = re.search(r"malloc\s*\(\s*([^)]+)\)", pseudocode)
    if m_alloc:
        alloc_expr = m_alloc.group(1).strip()
    if not alloc_expr:
        return findings
    alloc_key = _normalize(alloc_expr)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 提取写操作的地址偏移表达式 [addr] 而非 RHS 值; 兼容 = 和逗号风格
        m = re.search(r"\[([^\]]+)\]\s*[,=]", line)
        if not m:
            continue
        addr_expr = _extract_write_offset_expr(m.group(1))
        write_key = _normalize(addr_expr)
        same = _same_root_key(alloc_key, write_key)
        verdict = "identity_safe" if same else "identity_diff"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if same else 0.5,
            "description": (
                f"line{ln} alloc_key={alloc_key} write_key={write_key} "
                f"same_root={same}"
            ),
            "verdict": verdict,
            "source": "root_identity_key",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(n * 4 + 8);
mov [p+4], n;
"""
    out = run_root_identity_key(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])
