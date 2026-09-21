"""ColorClassQuad - 四色分类 + 交叉域互斥审计 (stage 86).

HEAP/STACK/GLOBAL/UNKNOWN 四色着色传播, 写点查色, 交叉域写入互斥性审计.
与 ProvenanceOctagon(89) 不同: 四色分类 + 交叉域互斥检测, 非八类溯源格.

设计决策:
  - 四色: HEAP(0)/STACK(1)/GLOBAL(2)/UNKNOWN(3)
  - 分配点 -> HEAP; 栈相关 -> STACK; 命名全局 -> GLOBAL
  - 赋值传播: b = a 时 b 继承 a 的颜色
  - 写点基址非 HEAP 色 -> 降权
  - 交叉域互斥: 堆变量被栈地址赋值/栈变量被堆指针赋值/全局被堆别名
"""

import re
from typing import Dict, List, Optional

_HEAP, _STACK, _GLOBAL, _UNKNOWN = 0, 1, 2, 3
_COLOR_NAME = {0: "HEAP", 1: "STACK", 2: "GLOBAL", 3: "UNKNOWN"}


def _paint_colors(pseudocode: str) -> Dict[str, int]:
    """着色: 分配=HEAP, 栈=STACK, 赋值传播, 其余=GLOBAL/UNKNOWN."""
    colors: Dict[str, int] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line)
        if m:
            colors[m.group(1)] = _HEAP
            continue
        m = re.search(r"\b(\w+)\s*=\s*(?:rbp|rsp)", line)
        if m:
            colors[m.group(1)] = _STACK
            continue
        # C 风格栈数组声明: char local[N] / int arr[N]
        m_stack_arr = re.search(
            r"\b(?:char|int|long|short|unsigned)\s+(\w+)\s*\[\s*\d+\s*\]",
            line,
        )
        if m_stack_arr:
            colors[m_stack_arr.group(1)] = _STACK
            continue
        m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*;", line)
        if m and m.group(2) in colors:
            colors[m.group(1)] = colors[m.group(2)]
        elif m and m.group(1) not in colors:
            colors[m.group(1)] = _GLOBAL
    return colors


def _detect_cross_domain(pseudocode: str) -> List[dict]:
    """交叉域互斥审计: 追踪赋值时变量域的变化, 检测跨域污染.

    堆变量被栈地址赋值 -> cross_domain_contamination
    栈变量被堆指针赋值 -> stack_heap_confusion
    全局变量被堆指针赋值 -> global_heap_alias
    """
    cross_findings: List[dict] = []
    colors: Dict[str, int] = {}
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 堆源赋值: var = malloc(...)
        m_heap = re.search(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line
        )
        if m_heap:
            var = m_heap.group(1)
            old = colors.get(var)
            if old == _STACK:
                cross_findings.append({
                    "line": ln, "var": var,
                    "verdict": "stack_heap_confusion",
                    "desc": f"line{ln} 栈变量 {var} 被堆指针赋值",
                })
            elif old == _GLOBAL:
                cross_findings.append({
                    "line": ln, "var": var,
                    "verdict": "global_heap_alias",
                    "desc": f"line{ln} 全局变量 {var} 被堆指针别名",
                })
            colors[var] = _HEAP
            continue
        # 栈源赋值: var = rbp/rsp
        m_stack = re.search(r"\b(\w+)\s*=\s*(?:rbp|rsp)", line)
        if m_stack:
            var = m_stack.group(1)
            old = colors.get(var)
            if old == _HEAP:
                cross_findings.append({
                    "line": ln, "var": var,
                    "verdict": "cross_domain_contamination",
                    "desc": f"line{ln} 堆变量 {var} 被栈地址污染",
                })
            colors[var] = _STACK
            continue
        # 赋值传播
        m_assign = re.search(r"\b(\w+)\s*=\s*(\w+)\s*;", line)
        if m_assign and m_assign.group(2) in colors:
            dst = m_assign.group(1)
            src_color = colors[m_assign.group(2)]
            old = colors.get(dst)
            # 赋值链跨域冲突: 目标变量已有颜色且与源颜色不同
            # 颜色沿赋值链扩散时被另一域覆盖 -> 颜色归属不可判定, 按 unknown_color 注入
            if old is not None and old != src_color:
                cross_findings.append({
                    "line": ln, "var": dst,
                    "verdict": "unknown_color",
                    "desc": f"line{ln} 变量 {dst} 颜色 "
                            f"{_COLOR_NAME.get(old)} 被赋值链改为 "
                            f"{_COLOR_NAME.get(src_color)}",
                })
            colors[dst] = src_color
        elif m_assign and m_assign.group(1) not in colors:
            colors[m_assign.group(1)] = _GLOBAL
    return cross_findings


def run_color_class_quad(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """四色分类 + 交叉域互斥审计. 返回 findings."""
    findings: List[dict] = []
    colors = _paint_colors(pseudocode)
    # 交叉域互斥审计
    cross_findings = _detect_cross_domain(pseudocode)
    for cf in cross_findings:
        findings.append({
            "type": "memory_write",
            "function": func_name or "unknown",
            "severity": "high",
            "cwe": "CWE-787",
            "confidence": 0.7,
            "description": cf["desc"],
            "verdict": cf["verdict"],
            "source": "color_class_quad",
        })
    # 四色分类写点审计 (汇编风格)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"(?<!\w)\[\s*(\w+)\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue
        base = m.group(1)
        color = colors.get(base, _UNKNOWN)
        if color == _HEAP:
            verdict, conf = "heap_write", 0.5
        elif color == _STACK:
            verdict, conf = "stack_write", 0.3
        elif color == _GLOBAL:
            verdict, conf = "global_write", 0.3
        else:
            verdict, conf = "unknown_color", 0.4
        findings.append({
            "type": "heap_overflow" if color == _HEAP else "memory_write",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122" if color == _HEAP else "CWE-787",
            "confidence": conf,
            "description": f"line{ln} base={base} "
                           f"color={_COLOR_NAME[color]}",
            "verdict": verdict,
            "source": "color_class_quad",
            # UNKNOWN 色写点: 指针无来源记录无法判定域归属, 是线索不是判定
            "rw_weak": color == _UNKNOWN,
        })

    # C 风格写点审计: buf[expr]=val 基址着色
    # 堆色 (HEAP) 不在降权白名单, 不注入不降权
    # 栈色 → stack_write (target_type=heap_overflow 降权)
    # 全局色 → global_write (target_type=heap_overflow 降权)
    # 未知色 (指针参数无来源记录) → unknown_color
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_idx = re.search(r"(\w+)\s*\[([^\]]+)\]\s*=\s*(\S+)", line)
        if not m_idx:
            # 解引用写: *(int *)(ptr + off) = val
            m_deref = re.search(
                r"\*\s*\([^)]*\)\s*\(\s*(\w+)\s*(?:\+[^)]*)?\)\s*=\s*(\S+)",
                line,
            )
            if not m_deref:
                continue
            base = m_deref.group(1)
        else:
            base = m_idx.group(1)
        color = colors.get(base, _UNKNOWN)
        if color == _HEAP:
            # 堆域写不注入不降权
            continue
        elif color == _STACK:
            verdict, conf = "stack_write", 0.3
        elif color == _GLOBAL:
            verdict, conf = "global_write", 0.3
        else:
            verdict, conf = "unknown_color", 0.4
        findings.append({
            "type": "memory_write",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-787",
            "confidence": conf,
            "description": f"line{ln} base={base} "
                           f"color={_COLOR_NAME[color]}",
            "verdict": verdict,
            "source": "color_class_quad",
            "rw_weak": color == _UNKNOWN,
        })

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
q = p;
p = rbp;
mov [q+8], 0;
mov [rbp-4], 0;
"""
    out = run_color_class_quad(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])
