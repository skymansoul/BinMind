# analysis/taint_confirm — FC-VRA 阶段C4: 攻击者可控性确认
# 核心创新点5: 告警的"语义强度"取决于是否存在攻击者可控的尺寸维度。
# 堆溢出告警若同时满足 (a) 写入量是编译期常量 (b) 缓冲区不受输入可达,
# 则即使真实存在越界 (如 malloc(32)+memcpy(64) 的静态常量错配),
# 也不构成"攻击者可控的堆溢出" — 此类告警的威胁等级应被压制。
# 现有 taint_propagation 只在导入表层面对"函数名"做粗略路径判断,
# 无法回答"memcpy 的 size 参数变量是否来自 recv"这类问题。
# 本模块在变量级做轻量污点传播: source(输入函数返回值) → 赋值/算术 → 变量。
#
# 与导入级污点传播的关系: 本模块面向"有源码"场景, 精度更高;
# 无源码时回退到导入级 (taint_propagation)。

from __future__ import annotations
from typing import Dict, List, Set
import re

_INPUT_SOURCES = re.compile(
    r"(?:recv|recvfrom|read|fread|fgets|gets|scanf|fscanf|sscanf|"
    r"getenv|readlink|strlen|atoi|atol|strtol|strtoul)\s*\(")

def _seed_sources(code: str) -> Set[str]:
    """识别直接来自输入的变量 (输入函数返回值)。"""
    tainted: Set[str] = set()
    for m in re.finditer(
        r"(\w+)\s*=\s*(?:\(\s*[\w\s]+\*?\s*\)\s*)?"
        r"(?:recv|recvfrom|read|fread|fgets|gets|scanf|"
        r"fscanf|sscanf|getenv|readlink|strlen|atoi|atol|strtol|strtoul)"
        r"\s*\(", code):
        tainted.add(m.group(1))
    for m in re.finditer(r"(\w+)\s*=\s*[^;]*atoi\s*\(\s*argv\s*\[", code):
        tainted.add(m.group(1))
    return tainted

def _propagate(code: str, seeds: Set[str]) -> Set[str]:
    """赋值与算术传播闭包: tainted 变量的下游也 tainted。"""
    tainted = set(seeds)
    changed = True
    iterations = 0
    while changed and iterations < 8:
        changed = False
        iterations += 1
        # x = y;  x = y op z;  x = func(y,...)
        for m in re.finditer(r"(\w+)\s*=\s*([^;]+?)\s*;", code):
            lhs, rhs = m.group(1), m.group(2)
            if lhs in tainted:
                continue
            if any(w in tainted for w in re.findall(r"\b(\w+)\b", rhs)):
                tainted.add(lhs)
                changed = True
    return tainted

def _writes_from_input(code: str, tainted: Set[str]) -> bool:
    """缓冲区内容是否可能来自输入 (memcpy/recv 的源被污染)。"""
    for m in re.finditer(
        r"(?:memcpy|memmove|strcpy|strncpy)\s*\(\s*(\w+)\s*,\s*(\w+)", code):
        if m.group(2) in tainted:
            return True
    return False

def confirm_controllability(code: str, size_expr: str,
                            buffer_var: str) -> Dict:
    """C4 主入口: 判定写入量/缓冲区是否攻击者可控。

    返回 {
      "size_tainted": bool,
      "buffer_tainted": bool,
      "write_size_is_const": bool,
      "controllable": bool,        # size 或 buffer 任一处可控
      "reaching_sources": int,
    }
    """
    seeds = _seed_sources(code)
    tainted = _propagate(code, seeds)

    size_vars = re.findall(r"\b(\w+)\b", size_expr) if size_expr else []
    # 过滤数字与保留字
    size_vars = [v for v in size_vars
                 if not v.isdigit() and v not in ("int", "char", "short",
                                                  "long", "size", "t")]
    size_tainted = any(v in tainted for v in size_vars)

    buffer_tainted = buffer_var in tainted or _writes_from_input(code, tainted)

    write_is_const = bool(size_expr) and not any(
        re.search(rf"\b{v}\b", size_expr) for v in size_vars) \
        and size_expr.replace(" ", "").isdigit()

    return {
        "size_tainted": size_tainted,
        "buffer_tainted": buffer_tainted,
        "write_size_is_const": write_is_const,
        "controllable": size_tainted or buffer_tainted,
        "reaching_sources": len(seeds),
    }

if __name__ == "__main__":
    code = ("int n = atoi(argv[1]);\n"
            "char *buf = malloc(n);\n"
            "int k = 64;\n"
            "memcpy(buf, src, n);\n"
            "memcpy(buf, src, k);\n")
    print("n:", confirm_controllability(code, "n", "buf"))
    print("64:", confirm_controllability(code, "64", "buf"))
