"""边缘案例检测器 —— 四类漏洞检测的边界条件补充测试。
针对各检测器已知盲区专项覆盖: 堆溢出 (realloc 缩小后写入)、UAF (全局指针跨函数释放)、
格式化字符串 (间接调用)、整数溢出 (循环累加); 检出均标记低置信度 (0.2-0.4) 供符号执行层接管。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EdgeCaseFinding:
    vulnerability_type: str
    pattern: str          # 边缘模式描述
    address: int
    confidence: float     # 低置信度(0.2-0.4)——需后续验证
    evidence: str
    suggested_action: str  # "symbolic_verify"/"fuzz"/"manual_review"


def detect_edge_cases(
    disasm_lines: List[str],
    func_name: str = "",
) -> List[EdgeCaseFinding]:
    """四类漏洞的边缘案例检测。所有finding置信度≤0.4。"""
    findings: List[EdgeCaseFinding] = []

    for i, line in enumerate(disasm_lines):
        stripped = line.strip().lower()
        if not stripped or stripped.startswith(';'):
            continue

        # 盲区1: realloc缩小(新size < 旧size)→写入旧size范围
        if 'realloc' in stripped:
            # 查找realloc后是否有对原指针的写入
            for j in range(i + 1, min(len(disasm_lines), i + 10)):
                dl = disasm_lines[j].strip().lower()
                if any(kw in dl for kw in ('mov [', 'strcpy', 'memcpy')):
                    findings.append(EdgeCaseFinding(
                        vulnerability_type="heap_overflow",
                        pattern="realloc_shrink_use",
                        address=i, confidence=0.30,
                        evidence=f"realloc后写入@{hex(j)}",
                        suggested_action="symbolic_verify"))
                    break

        # 盲区2: 全局变量free(跨函数UAF高风险)
        m = re.search(r'free\s*\(\s*(g_\w+|&\w+::\w+)', stripped)
        if m:
            findings.append(EdgeCaseFinding(
                vulnerability_type="uaf",
                pattern="global_ptr_free",
                address=i, confidence=0.35,
                evidence=f"全局变量{m.group(1)}被释放",
                suggested_action="manual_review"))

        # 盲区3: 间接调用格式函数
        m = re.search(r'call\s+(?:rax|rbx|rcx|rdx|r8|r9)\b', stripped)
        if m:
            # 检查调用前是否准备了格式参数
            for j in range(i - 5, i):
                prev = disasm_lines[j].strip().lower() if j >= 0 else ""
                if 'mov' in prev and ('rdi' in prev or 'edi' in prev):
                    findings.append(EdgeCaseFinding(
                        vulnerability_type="format_string",
                        pattern="indirect_format_call",
                        address=i, confidence=0.25,
                        evidence=f"间接调用@{hex(i)}可能为printf",
                        suggested_action="symbolic_verify"))
                    break

        # 盲区4: 循环累加(多次add, 累积溢出)
        if 'add' in stripped and i >= 2:
            prev2 = disasm_lines[i-2].strip().lower() if i >= 2 else ""
            if 'add' in prev2:
                findings.append(EdgeCaseFinding(
                    vulnerability_type="integer_overflow",
                    pattern="loop_accumulate",
                    address=i, confidence=0.20,
                    evidence="连续add指令→可能循环累加溢出",
                    suggested_action="fuzz"))

    # 去重: 同类型+同pattern只保留一个
    seen = set()
    unique = []
    for f in findings:
        key = (f.vulnerability_type, f.pattern)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


__all__ = ["EdgeCaseFinding", "detect_edge_cases"]
