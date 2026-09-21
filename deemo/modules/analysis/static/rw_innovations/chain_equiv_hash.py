"""ChainEquivHash - 溯源链等价哈希 (stage 71).

alloc 溯源链与 write 溯源链各自序列化后取滚动哈希, 哈希相等 ->
等价安全. 与分配容量溯源 (Allocation Capacity Provenance) classify_pair 不同: 链序列哈希比较.

设计决策:
  - 分配链: 从分配点沿 def-use 收集变量序列
  - 写入链: 从写点沿 use-def 回溯变量序列
  - 两条链序列化后计算滚动哈希 (RK: base=131, mod=2**61-1)
  - 哈希相等 -> 分配链与写链等价 -> 安全

差异化 (vs root_identity_key):
  - 本模块构建"分配点→各写点"溯源链序列, 对链上节点计算规范化哈希
  - 滚动哈希链比较: 全链哈希一致 -> equiv_safe; 任一节点不同 -> 不产
  - root_identity_key 用符号四元组数学比较, 本模块用链序列哈希比较
  - C 分支对齐汇编分支的链哈希逻辑 (不再逐写点表达式比较)
"""

import re
from typing import Dict, List, Optional


def _build_chain(pseudocode: str, start: str, direction: str) -> List[str]:
    """构造溯源链: direction='fwd' 沿 def-use, 'bwd' 沿 use-def 回溯."""
    chain: List[str] = []
    cur = start
    seen = set()
    lines = pseudocode.splitlines()
    seq = (list(enumerate(lines)) if direction == "fwd"
           else list(reversed(list(enumerate(lines)))))
    for _i, line in seq:
        if cur in seen:
            break
        seen.add(cur)
        chain.append(cur)
        m = re.search(r"\b(\w+)\s*=\s*([^;]+)", line)
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        if direction == "fwd" and re.search(r"\b" + re.escape(cur) + r"\b", rhs):
            cur = lhs
        elif direction == "bwd" and lhs == cur:
            vars_in_rhs = re.findall(r"\b([a-z_]\w*)\b", rhs)
            if vars_in_rhs:
                cur = vars_in_rhs[0]
    return chain


def _roll_hash(seq: List[str]) -> int:
    """滚动哈希 (RK 风格)."""
    h = 0
    base = 131
    mod = (1 << 61) - 1
    for s in seq:
        # 内置 hash 受 PYTHONHASHSEED 进程级随机化, 跨进程结果不可复现;
        # 改用逐字符多项式哈希保证描述中 hash 数值确定性
        sh = 0
        for ch in s:
            sh = (sh * base + ord(ch)) % mod
        h = (h * base + sh) % mod
    return h


def _node_hash(func_name: str, key_args: List[str]) -> int:
    """链节点规范化哈希: 函数名+关键参数规范化后逐字符多项式哈希.
    规范化: 去空格, 参数排序去重, 保证同语义节点哈希一致.
    """
    base = 131
    mod = (1 << 61) - 1
    norm_args = sorted(set(a.replace(" ", "") for a in key_args if a))
    token = func_name + ":" + ",".join(norm_args)
    h = 0
    for ch in token:
        h = (h * base + ord(ch)) % mod
    return h


def run_chain_equiv_hash(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """溯源链等价哈希. 返回 findings."""
    findings: List[dict] = []
    m_alloc = re.search(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(([^)]+)\)",
        pseudocode)
    if not m_alloc:
        return findings
    alloc_var = m_alloc.group(1)
    alloc_size_expr = m_alloc.group(2).strip()
    # 分配链: 变量名 + 容量表达式序列化哈希
    alloc_chain = _build_chain(pseudocode, alloc_var, "fwd")
    alloc_hash = _roll_hash(alloc_chain)
    # C 风格: 追踪容量表达式经赋值传递后的规范化形式
    # 收集变量赋值映射, 用于容量表达式归一化
    var_map: Dict[str, str] = {}
    for line in pseudocode.splitlines():
        m_assign = re.search(r"\b(\w+)\s*=\s*([^;]+)", line)
        if m_assign:
            lhs = m_assign.group(1)
            rhs = m_assign.group(2).strip()
            # 仅记录简单变量赋值 (非 malloc/calloc/realloc 调用)
            if not re.search(r"(?:malloc|calloc|realloc|memcpy|free)\s*\(", rhs):
                var_map[lhs] = rhs
    # 归一化容量表达式: 替换已知变量赋值
    def _normalize_size(expr: str) -> str:
        expr = expr.replace(" ", "")
        changed = True
        while changed:
            changed = False
            for var, val in var_map.items():
                if re.search(r"\b" + re.escape(var) + r"\b", expr) and var != expr:
                    expr = expr.replace(var, val)
                    changed = True
        return expr
    alloc_norm = _normalize_size(alloc_size_expr)
    # 差异化: C 分支对齐汇编分支的链哈希逻辑
    # 构建分配节点规范化哈希 (仅归一化容量参数, 不含函数名前缀)
    alloc_node_h = _node_hash("", [alloc_norm])
    # 枚举全部写点, 构建写节点链哈希, 任一节点哈希不同则不产 equiv_safe
    write_points = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # C 风格 memcpy 写操作: memcpy(dst, src, len)
        m_mc = re.search(
            r"memcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*([^)]+)\)", line)
        if m_mc:
            write_size_expr = m_mc.group(2).strip()
            write_norm = _normalize_size(write_size_expr)
            # 写节点哈希: 仅归一化长度参数 (与分配节点同参数空间比较)
            write_node_h = _node_hash("", [write_norm])
            equiv = (alloc_node_h == write_node_h)
            write_points.append((ln, equiv))
        else:
            # C 风格下标写: buf[expr] = val
            m_csub = re.search(r"(\w+)\[([^\]]*)\]\s*=", line)
            if m_csub:
                offset_expr = m_csub.group(2).strip()
                if not offset_expr:
                    offset_expr = "0"
                write_norm = _normalize_size(offset_expr)
                # 写节点哈希: 仅归一化偏移参数
                write_node_h = _node_hash("", [write_norm])
                equiv = (alloc_node_h == write_node_h)
                write_points.append((ln, equiv))
            else:
                # 汇编风格写点: [ptr+off] ,/= val
                m_asm = re.search(r"\[\s*(\w+)\s*(\+\s*\d+)?\]\s*(?:,|=)\s*(\w+)", line)
                if not m_asm:
                    continue
                write_var = m_asm.group(3)
                write_chain = _build_chain(pseudocode, write_var, "bwd")
                write_hash = _roll_hash(write_chain)
                equiv = (alloc_hash == write_hash)
                write_points.append((ln, equiv))
    # 全部写点等价才产 equiv_safe, 否则不产 (避免压真)
    if not write_points or not all(wp[1] for wp in write_points):
        return findings
    for ln, equiv in write_points:
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9,
            "description": f"line{ln} alloc_norm={alloc_norm} "
                           f"equiv={equiv}",
            "verdict": "equiv_safe",
            "source": "chain_equiv_hash",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
q = p;
r = q;
mov [r+8], 0;
"""
    out = run_chain_equiv_hash(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])