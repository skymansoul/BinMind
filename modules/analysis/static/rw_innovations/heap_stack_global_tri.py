"""HeapStackGlobalTri - 堆栈全局三分 (stage 70).

写入基址解析为 heap/stack/global 三域标签. 本模块聚焦"三元域显式
分类器": 回答"这个变量属于哪个域"的域指派审计, 与 color_class_quad
的四色传播+交叉域互斥 (stage 86) 区分: 本模块不做赋值传播与写点降权.

设计决策:
  - malloc/calloc/realloc 结果标记为 heap
  - 栈指针 (rbp/rsp 相关) 标记为 stack
  - C 风格栈数组声明标记为 stack
  - 全局符号 (无来源的命名变量) 标记为 global
  - 每个变量按其来源分入三域, 产出域指派类 verdict (assign 审计)
  - C 风格写点降权职责移交 color_class_quad, 旧分支标记 #[DEPRECATED]
"""

import re
from typing import Dict, List, Optional, Set

# 旧 C 风格写点降权分支默认关闭: 职责移交 color_class_quad (stage 86)
_DEPRECATED_C_DOMAIN_DEWEIGHT = False


def _classify_vars(pseudocode: str) -> Dict[str, str]:
    """为变量分配域标签 heap/stack/global, 并记录指派依据.

    返回 (domains, reasons): domains 为变量->域映射, reasons 为
    变量->依据描述, 供域指派审计 verdict 使用. 指派依据是
    color_class_quad 不具备的显式审计输出.
    """
    domains: Dict[str, str] = {}
    reasons: Dict[str, str] = {}
    for line in pseudocode.splitlines():
        # 堆分配: C 风格 type *ptr = (type*)malloc(...) 或 ptr = malloc(...)
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line)
        if m:
            domains[m.group(1)] = "heap"
            reasons[m.group(1)] = "malloc_source"
            continue
        # C 风格栈数组声明: char local[16] / int arr[32]
        m_stk = re.search(r"\b(?:char|short|int|long|unsigned)\s+(\w+)\s*\[", line)
        if m_stk:
            domains[m_stk.group(1)] = "stack"
            reasons[m_stk.group(1)] = "local_array"
            continue
        # 栈相关: 汇编风格 rbp/rsp
        m = re.search(r"\b(\w+)\s*=\s*(?:rbp|rsp)", line)
        if m:
            domains[m.group(1)] = "stack"
            reasons[m.group(1)] = "frame_ptr"
            continue
        # 全局命名变量: 仅未归类且非函数参数/循环变量/类型关键字
        # 排除等号右侧为函数调用的情形 (如 p = get_ptr()), 此类变量域不可判定
        m = re.search(r"\b([a-z_]\w*)\s*=\s*(\w+)\s*\(", line)
        if m and m.group(1) not in domains:
            # 右侧为函数调用, 基址来源未知, 不归入任何域
            continue
        m = re.search(r"\b([a-z_]\w*)\s*=\s*", line)
        if m and m.group(1) not in domains:
            # 跳过类型关键字
            if m.group(1) in ("char", "int", "long", "short", "unsigned", "void"):
                continue
            domains[m.group(1)] = "global"
            reasons[m.group(1)] = "unnamed_global"
    return domains, reasons


def run_heap_stack_global_tri(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """堆栈全局三分. 返回 findings."""
    findings: List[dict] = []
    domains, reasons = _classify_vars(pseudocode)
    # C 风格域指派审计: 每个被归类变量产一条 assign verdict
    # 域指派是中性审计, 不注入告警不降权 (写点降权职责在 quad)
    for var, domain in domains.items():
        rsn = reasons.get(var, "classified")
        if domain == "heap":
            verdict = "heap_assign"
        elif domain == "stack":
            verdict = "stack_assign"
        else:
            verdict = "global_assign"
        findings.append({
            "type": "memory_region",
            "function": func_name or "unknown",
            "severity": "info",
            "cwe": "CWE-787",
            "confidence": 0.8,
            "description": f"var={var} domain={domain} reason={rsn}",
            "verdict": verdict,
            "source": "heap_stack_global_tri",
        })
    # C 风格写点 unknown_domain 注入: 写点基址无法归入任何已知域时注入告警
    # bridge 白名单仅消费 unknown_domain (注入 append), *_assign 不被消费
    # 提取写点基址: 下标写 buf[expr]=val 的 buf、memcpy/memset 第一参 dst
    domain_summary = (
        " ".join(f"{v}={d}" for v, d in domains.items())
        if domains else "no_vars_classified"
    )
    seen_bases: Set[str] = set()
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # C 风格下标写: buf[expr] = val
        m_c = re.search(r"(\w+)\s*\[([^\]]*)\]\s*=", line)
        if m_c:
            base = m_c.group(1)
            if base not in domains and base not in seen_bases:
                seen_bases.add(base)
                findings.append({
                    "type": "memory_write",
                    "function": func_name or "unknown",
                    "severity": "warning",
                    "cwe": "CWE-787",
                    "confidence": 0.4,
                    "description": f"line{ln} base={base} subscript_write "
                                   f"domain=unknown 写点基址域不可判定 "
                                   f"[{domain_summary}]",
                    "verdict": "unknown_domain",
                    "source": "heap_stack_global_tri",
                })
        # memcpy/memset/memmove 第一参为写目标: memcpy(dst, src, n)
        m_cp = re.search(
            r"\b(?:memcpy|memset|memmove)\s*\(\s*(\w+)\s*,", line,
        )
        if m_cp:
            base = m_cp.group(1)
            if base not in domains and base not in seen_bases:
                seen_bases.add(base)
                findings.append({
                    "type": "memory_write",
                    "function": func_name or "unknown",
                    "severity": "warning",
                    "cwe": "CWE-787",
                    "confidence": 0.4,
                    "description": f"line{ln} base={base} copy_write "
                                   f"domain=unknown 写点基址域不可判定 "
                                   f"[{domain_summary}]",
                    "verdict": "unknown_domain",
                    "source": "heap_stack_global_tri",
                })
    # #[DEPRECATED] C 风格写点降权分支: 与 color_class_quad 重复,
    # 降权职责移交 quad, 保留函数体供历史参考; 默认关闭不产出
    if _DEPRECATED_C_DOMAIN_DEWEIGHT:
        for ln, line in enumerate(pseudocode.splitlines(), 1):
            base = None
            # C 风格解引用写: *(type *)(expr) = val -> 基址为 expr 首变量
            m_deref = re.search(r"\*\s*\([^)]*\)\s*\(\s*(\w+)", line)
            if m_deref and re.search(r"=\s*\d+", line):
                base = m_deref.group(1)
            if not base:
                # C 风格下标写: buf[expr] = val -> 基址为 buf
                m_c = re.search(r"(\w+)\[([^\]]*)\]\s*=", line)
                if m_c:
                    base = m_c.group(1)
            if not base:
                # 汇编风格: [ptr+off] ,/= val -> 基址为 ptr
                m_asm = re.search(r"\[\s*(\w+)\s*(\+\s*\d+)?\]\s*(?:,|=)\s*(\w+)", line)
                if m_asm:
                    base = m_asm.group(1)
            if not base:
                continue
            domain = domains.get(base, "unknown")
            # heap 域不在白名单, 不注入不降权
            if domain == "heap":
                continue
            if domain == "stack":
                verdict = "stack_write"
                conf = 0.3
            elif domain == "global":
                verdict = "global_write"
                conf = 0.3
            else:
                verdict = "unknown_domain"
                conf = 0.4
            findings.append({
                "type": "memory_write",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-787",
                "confidence": conf,
                "description": f"line{ln} base={base} domain={domain}",
                "verdict": verdict,
                "source": "heap_stack_global_tri",
            })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+8], 0;
mov [rbp-4], 0;
"""
    out = run_heap_stack_global_tri(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])