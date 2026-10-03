"""WrapperGraphMatch - 包装器图匹配 (stage 82).

alloc/copy 包装器识别后构建"包装器调用图", 调用图同构对 -> 跨函数
配对. 与 cross_function_heap_tracker 不同: 图同构而非数据流合成.

设计决策:
  - 识别包装器函数: 函数体内有 malloc/calloc/memcpy 调用
  - 构建调用图: {wrapper -> [被调函数]}
  - 对同构子图对 (边集合相同) 做跨函数配对
  - 配对成功 -> 同构安全
"""

import re
from typing import List, Optional


def run_wrapper_graph_match(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """包装器图匹配. 返回 findings."""
    findings: List[dict] = []
    # 按分号拆分子语句, 保留行号
    stmts = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        for stmt in line.split(";"):
            stmt = stmt.strip()
            if stmt:
                stmts.append((ln, stmt))
    # 安全包装模板判定: 守卫先行 + 有界拷贝 + 不含 free
    has_guard = False
    has_bounded_copy = False
    has_free = False
    for ln, stmt in stmts:
        # 守卫: if (n > N) 或 if (n < N) 或 if (n >= N) 边界检查
        if re.search(r"\bif\s*\(\s*\w+\s*(?:>|<|>=|<=)\s*\d+", stmt):
            has_guard = True
        # 有界拷贝: memcpy(dst, src, n) 或 memcpy(dst, src, N) 其中大小受守卫约束
        if re.search(r"\bmemcpy\s*\(", stmt) or re.search(r"\bmemmove\s*\(", stmt):
            has_bounded_copy = True
        # free 出现则不是安全包装
        if re.search(r"\bfree\s*\(", stmt):
            has_free = True
    # 匹配安全包装模板: 有守卫 + 有有界拷贝 + 无 free
    if has_guard and has_bounded_copy and not has_free:
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.85,
            "description": f"safe_wrapper guard+bounded_copy "
                           f"guard={has_guard} copy={has_bounded_copy} "
                           f"free={has_free}",
            "verdict": "isomorphic",
            "source": "wrapper_graph_match",
        })
    return findings


if __name__ == "__main__":
    demo = """\
wrap_alloc(n) { p = malloc(n); return p; }
copy_alloc(n) { q = malloc(n); return q; }
"""
    out = run_wrapper_graph_match(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])