"""PtrUnionClosure - 指针并查集闭包 (stage 67).

把所有别名赋值构造成并查集森林, 写入目标与分配点的集合 id 不同时
直接判定"跨缓冲区误报". 与 FC-VRA 配对不同: 纯集合身份判定.

设计决策:
  - 并查集: parent 字典, find/union 标准实现
  - 别名赋值 a = b; 或 a = &b; 时 union(a, b)
  - 分配变量与写目标各自映射到集合根
  - 集合根不同 -> 跨缓冲区误报
"""

import re
from typing import Dict, List, Optional


class _UnionFind:
    """极简并查集."""

    def __init__(self):
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def same(self, a: str, b: str) -> bool:
        return self.find(a) == self.find(b)


def _union_aliases(pseudocode: str, uf: _UnionFind) -> None:
    """扫描别名赋值 a = b; 或 a = &b; 做 union (排除分配行)."""
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(?:&\s*)?(\w+)\s*;", line)
        if m and not re.search(r"malloc|calloc|realloc", line):
            uf.union(m.group(1), m.group(2))


def run_ptr_union_closure(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """指针并查集闭包. 返回 findings."""
    findings: List[dict] = []
    uf = _UnionFind()
    _union_aliases(pseudocode, uf)
    alloc_vars = re.findall(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(",
        pseudocode)
    # 无分配记录时, 所有写目标均无来源 -> cross_buffer_fp
    if not alloc_vars:
        for ln, line in enumerate(pseudocode.splitlines(), 1):
            write_var = None
            m_c = re.search(r"(\w+)\[([^\]]*)\]\s*=", line)
            if m_c:
                write_var = m_c.group(1)
            else:
                m_asm = re.search(r"\[\s*(\w+)\s*(\+\s*\w+)?\]\s*=", line)
                if m_asm:
                    write_var = m_asm.group(1)
            if not write_var:
                continue
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.2,
                "description": f"line{ln} write={write_var} no_alloc -> cross_buffer_fp",
                "verdict": "cross_buffer_fp",
                "source": "ptr_union_closure",
            })
        return findings
    root_alloc = uf.find(alloc_vars[0])
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        write_var = None
        # C 风格下标写: buf[expr] = val -> 写目标为 buf
        m_c = re.search(r"(\w+)\[([^\]]*)\]\s*=", line)
        if m_c:
            write_var = m_c.group(1)
        else:
            # 汇编风格: [ptr+off] = val -> 写目标为 ptr
            m_asm = re.search(r"\[\s*(\w+)\s*(\+\s*\w+)?\]\s*=", line)
            if m_asm:
                write_var = m_asm.group(1)
        if not write_var:
            continue
        same = uf.same(write_var, alloc_vars[0])
        # same_set 不注入, 仅 cross_buffer_fp 降权产出
        if same:
            continue
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.2,
            "description": f"line{ln} write={write_var} root={root_alloc} "
                           f"same_set={same}",
            "verdict": "cross_buffer_fp",
            "source": "ptr_union_closure",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
q = &p;
mov [q+8], 0;
"""
    out = run_ptr_union_closure(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])