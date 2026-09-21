"""TaintSourceGrading - 污点源分级 (stage 66).

scanf/recv/argv/env 分 1-4 级污点强度, 写入大小若由高级污点变量
驱动且无守卫 -> conf 提升; 低级污点 -> 降权.
与 alloc_size_taint 不同: 强度分级而非布尔污点.

设计决策:
  - 污点源分级: scanf=4, recv=3, argv=2, env=1
  - 追踪赋值链: 污点源 -> 变量
  - 若写入大小变量为高级污点且无守卫, conf 提升 0.2
  - 低级污点 (env=1) 且守卫存在, conf 降 0.2
  - C 风格 scanf("%d", &n) 通过取地址参数识别污点变量
  - 仅 high_taint 产出注入, mid/low/unknown 不产出
"""

import re
from typing import Dict, List, Optional, Set

_SOURCE_GRADE = {
    "scanf": 4, "recv": 3, "read": 3, "argv": 2, "getenv": 1, "env": 1,
}

# scanf/sscanf/fscanf 等取地址参数识别模式
_SCANF_FUNCS = ("scanf", "sscanf", "fscanf", "vscanf", "vsscanf")


def _collect_sources(pseudocode: str) -> Dict[str, int]:
    """收集污点源变量及其等级.
    汇编风格: var = ...scanf(...); C 风格: scanf("%d", &var);
    """
    out: Dict[str, int] = {}
    for line in pseudocode.splitlines():
        # 汇编风格: var = ...source...
        for src, grade in _SOURCE_GRADE.items():
            m = re.search(r"\b(\w+)\s*=\s*[^;]*\b" + re.escape(src) + r"\b", line)
            if m:
                out[m.group(1)] = grade
        # C 风格: scanf("%d", &var) 通过取地址参数识别污点变量
        for fname in _SCANF_FUNCS:
            pat = re.compile(r"\b" + fname + r"\s*\(([^)]*)\)")
            for sm in pat.finditer(line):
                args = sm.group(1).split(",")
                for arg in args:
                    am = re.match(r"\s*&\s*(\w+)", arg.strip())
                    if am:
                        out[am.group(1)] = _SOURCE_GRADE.get("scanf", 4)
    return out


def _has_clamp_guard(pseudocode: str, var: str) -> bool:
    """检查变量是否被守卫限制 (if(var>MAX)var=MAX 或 if(var<MAX)var=MAX 等)."""
    pat = re.compile(
        r"if\s*\(\s*" + re.escape(var) +
        r"\s*[<>=!]+\s*\d+\s*\)\s*" + re.escape(var) +
        r"\s*=\s*\d+")
    return bool(pat.search(pseudocode))


def _is_guarded(lines: List[str], idx: int) -> bool:
    """判断当前行是否在守卫(if/while)块范围内."""
    line = lines[idx]
    if "if" in line or "while" in line or "guard" in line:
        return True
    cur_indent = _indent_of(line)
    for j in range(idx - 1, -1, -1):
        prev = lines[j]
        if not prev.strip():
            continue
        prev_indent = _indent_of(prev)
        if cur_indent > prev_indent:
            if "if" in prev or "while" in prev or "guard" in prev:
                return True
        if prev_indent <= cur_indent:
            break
    return False


def _indent_of(line: str) -> int:
    """计算行首缩进."""
    count = 0
    for ch in line:
        if ch == ' ':
            count += 1
        elif ch == '\t':
            count += 4
        else:
            break
    return count


def run_taint_source_grading(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """污点源分级. 返回 findings.
    仅 high_taint 注入, mid/low/unknown 不注入.
    """
    findings: List[dict] = []
    sources = _collect_sources(pseudocode)
    if not sources:
        return findings
    lines = pseudocode.splitlines()
    # 检查每个污点变量是否被 clamp 守卫
    clamped = {v for v in sources if _has_clamp_guard(pseudocode, v)}
    for ln, line in enumerate(lines, 1):
        line_idx = ln - 1
        # 汇编风格写点: [指针表达式], 值 或 [指针表达式] = 值
        m = re.search(r"\[[^\]]*\]\s*(?:,|=)\s*(\w+)", line)
        # C 风格写点: memcpy/memmove/memset/strcpy(dst, ...)
        cm = re.search(
            r"\b(memcpy|memmove|memset|strcpy|strncpy)\s*\(\s*(\w+)\s*,", line)
        ptr_vars: List[str] = []
        if m:
            ptr_expr = re.search(r"\[([^\]]+)\]", line).group(1)
            ptr_vars = re.findall(r"\b(\w+)\b", ptr_expr)
        elif cm:
            # 调式写: dst 是写目标, 后续参数可能是写长
            ptr_vars = [cm.group(2)]
        else:
            continue
        # 收集写点涉及的污点变量等级
        grade = max((sources.get(v, 0) for v in ptr_vars), default=0)
        if grade == 0:
            continue
        guarded = _is_guarded(lines, line_idx)
        # 污点变量被 clamp 守卫 -> 降级, 不产出 high_taint
        tainted_vars = [v for v in ptr_vars if v in sources]
        if any(v in clamped for v in tainted_vars):
            continue
        if grade >= 3 and not guarded:
            conf = 0.9
            verdict = "high_taint"
        elif grade >= 2:
            conf = 0.7
            verdict = "mid_taint"
        elif grade == 1 and guarded:
            conf = 0.3
            verdict = "low_taint_guarded"
        else:
            conf = 0.5
            verdict = "unknown"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} taint_grade={grade} guarded={guarded}",
            "verdict": verdict,
            "source": "taint_source_grading",
        })
    return findings


def _taint_sources(pseudocode: str) -> Dict[str, int]:
    return _collect_sources(pseudocode)


if __name__ == "__main__":
    demo = """\
n = scanf("%d");
p = malloc(64);
mov [p+n], 0;
"""
    out = run_taint_source_grading(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"], item["confidence"])