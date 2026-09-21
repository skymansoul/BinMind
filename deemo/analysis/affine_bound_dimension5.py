"""
仿射关系边界验证 维度5: 完备性检查 — 基于模式的溢出安全网。 (权重 0.05)

此维度作为低权重安全网, 捕获前四个维度可能遗漏的显式溢出模式。
不引入新算法, 仅基于已知危险模式进行匹配。
保守性: 此维度仅可触发 OVERFLOW 提示, 不可单独触发 SAFE (避免遮蔽其他维度的发现)。
"""

from __future__ import annotations
import re

from analysis.affine_bound_dimensions import DimensionResult


def dim5_completeness_check(pseudocode: str) -> DimensionResult:
    """维度5: 完备性安全网 — 显式溢出模式匹配。 (权重 0.05)

    捕获其他维度可能遗漏的明确危险模式:
      1. 常量溢出: malloc(K) + memcpy(>K) — 当 K 为宏或表达式时可能被遗漏
      2. 无界写入 + 栈分配 → 总是危险
      3. 循环边界溢出: for(i<alloc_sz+delta) 写入
      4. realloc 截断: realloc(ptr, smaller) 后写入 original_size
      5. offset+length 溢出: malloc(n) + memcpy(buf+offset, src, len) where offset+len > n

    保守约束: 仅触发 OVERFLOW 或 UNCERTAIN, 绝不触发 SAFE。
    """
    findings = []

    # 模式1: 常量分配-写入不匹配 (当数值明确时)
    alloc_sizes = re.findall(r'(?:malloc|calloc)\s*\(\s*(\d+)\s*\)', pseudocode)
    write_sizes = re.findall(r'memcpy\s*\([^,]+,\s*[^,]*,\s*(\d+)\s*\)', pseudocode)
    for alloc_str in alloc_sizes:
        alloc_n = int(alloc_str)
        for write_str in write_sizes:
            write_n = int(write_str)
            if write_n > alloc_n:
                findings.append(
                    f"const overflow: malloc({alloc_n}) < memcpy({write_n})")

    # 模式2: 无界写入 + 小分配 (高危组合)
    if re.search(r'\b(?:strcpy|strcat|gets|sprintf)\s*\(', pseudocode):
        small_allocs = re.findall(r'(?:malloc|calloc)\s*\(\s*(\d+)\s*\)', pseudocode)
        for sa in small_allocs:
            if int(sa) < 256:
                findings.append(
                    f"unbounded write (strcpy/gets) with small alloc ({sa}B)")

    # 模式3: 循环中写入 + 偏移量递增 (潜在溢出)
    loop_write = re.search(
        r'for\s*\(.*?(\w+)\s*[<]=?\s*(\w+).*?\).*?'
        r'(?:memcpy|memmove|strcpy|\[\1\])',
        pseudocode, re.DOTALL)
    if loop_write:
        findings.append(
            f"loop-bound write detected: variable={loop_write.group(1)}")

    # 模式4: realloc 缩小后写入原始大小
    realloc_shrink = re.findall(
        r'realloc\s*\(\s*\w+\s*,\s*(\d+)\s*\)', pseudocode)
    if realloc_shrink:
        for rs in realloc_shrink:
            new_sz = int(rs)
            # 查找可能的原始大小引用
            orig_refs = re.findall(r'(?:orig_size|old_size|prev_size)\s*=\s*(\d+)',
                                   pseudocode)
            for orig_str in orig_refs:
                orig_n = int(orig_str)
                if new_sz < orig_n:
                    findings.append(
                        f"realloc shrink {orig_n}→{new_sz} "
                        "with original-size write risk")

    # 模式5: offset+length 溢出 (memcpy(buf+off, src, len), off+len > alloc)
    offset_adds = re.findall(
        r'(?:memcpy|memmove)\s*\(\s*\w+\s*\+\s*(\d+)\s*,\s*\w+\s*,\s*(\d+)\s*\)',
        pseudocode)
    if offset_adds and alloc_sizes:
        for off_str, len_str in offset_adds:
            offset_val = int(off_str)
            length_val = int(len_str)
            total = offset_val + length_val
            for alloc_str in alloc_sizes:
                alloc_n = int(alloc_str)
                if total > alloc_n:
                    findings.append(
                        f"offset+len overflow: {offset_val}+{length_val}={total}"
                        f" > malloc({alloc_n})")

    if findings:
        return DimensionResult(
            "CompletenessCheck", 0.05, "OVERFLOW", 0.60,
            f"{len(findings)} pattern(s) flagged: " + "; ".join(findings[:3]))
    else:
        return DimensionResult(
            "CompletenessCheck", 0.05, "UNCERTAIN", 0.0,
            "no explicit overflow patterns detected")


__all__ = ['dim5_completeness_check']
