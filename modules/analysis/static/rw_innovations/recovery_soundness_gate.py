"""RecoverySoundnessGate - 恢复健全性门 (stage 75).

有界写恢复 类尺寸恢复结果必须通过"恢复值 <= 分配上限"健全性检查才可用于
过滤, 否则证据退回. 与 有界写恢复 不同: 对恢复结果二次门禁.

设计决策:
  - 模拟尺寸恢复: 从写操作数宽度恢复写入大小
  - 健全性门: 恢复值必须 <= 分配上限 (alloc_size 或 2**31-1)
  - 通过门 -> 恢复可用; 否则退回 (证据作废)
  - C 风格 memcpy/memmove/memset 从第三参数恢复写入大小
  - C 风格下标写偏移超分配 (buf[n+8] vs malloc(n)) -> unsound
  - 保留汇编风格 qword/dword/word/byte 宽度恢复分支
"""

import re
from typing import List, Optional, Tuple


def _write_width(line: str) -> Optional[int]:
    """从写操作行推断写入字节数. 依据操作数宽度而非立即数值."""
    line = line.strip()
    # 行内宽度前缀优先
    if re.search(r"\bqword\b", line, re.IGNORECASE):
        return 8
    if re.search(r"\bdword\b", line, re.IGNORECASE):
        return 4
    if re.search(r"\bword\b", line, re.IGNORECASE):
        return 2
    if re.search(r"\bbyte\b", line, re.IGNORECASE):
        return 1
    # 寄存器源宽度
    m_reg = re.search(r"\[[^\]]*\]\s*(?:,|=)\s*([A-Za-z][A-Za-z0-9]*)", line)
    if m_reg:
        name = m_reg.group(1).lower()
        if name.startswith("r") and len(name) >= 2:
            return 8
        if name.startswith("e"):
            return 4
        if len(name) == 2 and name[0] in ("a", "b", "c", "d"):
            return 1
    # 立即数默认 4 字节
    return 4


def _recover_size(line: str) -> Optional[int]:
    """从写指令恢复写入大小(操作数宽度)."""
    if not re.search(r"\[[^\]]*\]\s*(?:,|=)", line):
        return None
    return _write_width(line)


def _recover_call_write_size(line: str) -> Optional[int]:
    """C 风格调式写: 从 memcpy/memmove/memset/strncpy 第三参数恢复写长."""
    m = re.search(
        r"\b(memcpy|memmove|memset|strncpy)\s*\(\s*\w+\s*,\s*[^,]+,\s*(\d+)",
        line)
    if m:
        return int(m.group(2))
    return None


def _recover_subscript_offset(line: str) -> Optional[Tuple[str, int]]:
    """C 风格下标写: 从 buf[var + const] 提取偏移基变量与常量偏移."""
    m = re.search(r"\[\s*(\w+)\s*\+\s*(\d+)\s*\]", line)
    if m:
        return m.group(1), int(m.group(2))
    return None


def _find_alloc_var(pseudocode: str) -> Optional[Tuple[str, str]]:
    """提取分配变量名及其容量表达式."""
    m = re.search(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc)\s*\(([^)]*)\)",
        pseudocode)
    if m:
        return m.group(1), m.group(2).strip()
    return None


def _find_freed_ptrs(pseudocode: str) -> dict:
    """按行序收集 free 指针: {name: first_free_line}.

    写点在 free 之后越过释放边界, 恢复结果不可靠, 不得产 sound.
    """
    freed = {}
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\bfree\s*\(\s*(\w+)\s*\)", line)
        if m and m.group(1) not in freed:
            freed[m.group(1)] = ln
    return freed


def _find_mask_offset_vars(pseudocode: str) -> set:
    """收集掩码赋值变量: off = (expr) & 0xFF.

    掩码后取值落在 [0, mask] 区间, 与分配容量无单调关系, 不可证 <= 分配.
    """
    masked = set()
    for line in pseudocode.splitlines():
        m = re.search(
            r"(?:\b\w+\s+)?(\w+)\s*=\s*\([^)]*\)\s*&\s*(?:0x[0-9A-Fa-f]+|\d+)",
            line)
        if m:
            masked.add(m.group(1))
    return masked


def _find_stack_arrays(pseudocode: str) -> set:
    """收集局部栈数组名 (char name[N]; 声明且非 malloc 分配).

    栈对象不在本模块堆分配职责内, 栈写不产 verdict.
    """
    stack = set()
    for line in pseudocode.splitlines():
        line = line.strip()
        if re.search(r"\b(malloc|calloc|realloc)\b", line):
            continue
        m = re.search(
            r"^[A-Za-z_][A-Za-z0-9_ \t]*\b(\w+)\s*\[\s*\d+\s*\]\s*;", line)
        if m:
            stack.add(m.group(1))
    return stack


def _subscript_target(line: str) -> Optional[str]:
    """提取下标写目标: buf[0] = 1 中的 buf."""
    m = re.match(r"^\s*(\w+)\s*\[", line)
    return m.group(1) if m else None


def _subscript_index_var(line: str) -> Optional[str]:
    """提取下标单变量: buf[off] = 1 中的 off."""
    m = re.search(r"\[\s*(\w+)\s*\]", line)
    return m.group(1) if m else None


def _recover_star_subscript(line: str) -> Optional[Tuple[str, int]]:
    """C 风格步长下标: buf[i * K] 提取 (i, K).

    循环 i in [0,n) 时下标覆盖 [0, K*n), 远超 malloc(n), 不得产 sound.
    """
    m = re.search(r"\[\s*(\w+)\s*\*\s*(\d+)\s*\]", line)
    if m:
        return m.group(1), int(m.group(2))
    return None


def run_recovery_soundness_gate(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """恢复健全性门. 返回 findings."""
    findings: List[dict] = []
    alloc_size: Optional[int] = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    upper = alloc_size if alloc_size is not None else (1 << 31) - 1
    # 提取分配变量与容量表达式, 用于偏移越界判定
    alloc_info = _find_alloc_var(pseudocode)
    alloc_var = alloc_info[0] if alloc_info else None
    alloc_expr = alloc_info[1] if alloc_info else None
    # 释放边界/掩码偏移/栈对象与分配无可靠关系, 相关写点不得产 sound
    freed_lines = _find_freed_ptrs(pseudocode)
    masked_vars = _find_mask_offset_vars(pseudocode)
    stack_vars = _find_stack_arrays(pseudocode)
    # 语义变量与分配变量的映射, 供异名/掩码下标比对
    var_aliases = {}
    for line in pseudocode.splitlines():
        am = re.match(
            r"\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc)\s*\((\w+)\)",
            line)
        if am:
            var_aliases[am.group(1)] = am.group(2)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        recovered = _recover_size(line)
        # C 风格调式写: 恢复写长
        call_wsize = _recover_call_write_size(line)
        if recovered is None and call_wsize is None:
            continue
        # C 风格调式写: 用写长替代操作数宽度
        if call_wsize is not None:
            recovered = call_wsize
        # C 风格下标写偏移越界判定: buf[var + const] 且 alloc(var) -> unsound
        offset_info = _recover_subscript_offset(line)
        is_unsound = False
        if offset_info and alloc_var and alloc_expr:
            off_var, off_const = offset_info
            if off_var == alloc_expr and off_const > 0:
                is_unsound = True
        # 写目标: 下标写取 buf, 调用式写取 memcpy 等第一参数
        target = _subscript_target(line)
        if target is None:
            cm = re.search(
                r"\b(memcpy|memmove|memset|strncpy)\s*\(\s*(\w+)", line)
            if cm:
                target = cm.group(2)
        # 悬垂写: 写点在 free 之后, 恢复不可靠, 不得产 sound
        if target and target in freed_lines and ln > freed_lines[target]:
            sound = False
            verdict = "unsound"
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.3,
                "description": f"line{ln} recovered={recovered} "
                               f"upper={upper} sound=False dangling_write",
                "verdict": verdict,
                "source": "recovery_soundness_gate",
            })
            continue
        # 栈数组写不在堆恢复职责内, 不产 verdict
        if target and target in stack_vars:
            continue
        # 掩码偏移/步长下标/异名偏移: 不可证与分配相容, 不得产 sound
        mask_hit = False
        if target and target == alloc_var:
            idx = _subscript_index_var(line)
            if idx in masked_vars or idx in var_aliases:
                mask_hit = True
            elif idx is None:
                star_info = _recover_star_subscript(line)
                if star_info:
                    mask_hit = True
                elif offset_info and offset_info[0] != alloc_expr:
                    mask_hit = True
        if mask_hit:
            sound = False
            verdict = "unsound"
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.3,
                "description": f"line{ln} recovered={recovered} "
                               f"upper={upper} sound=False "
                               f"incomparable_offset",
                "verdict": verdict,
                "source": "recovery_soundness_gate",
            })
            continue
        sound = (recovered <= upper) and not is_unsound
        verdict = "sound" if sound else "unsound"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if sound else 0.3,
            "description": f"line{ln} recovered={recovered} "
                           f"upper={upper} sound={sound}"
                           + (f" offset_oob={off_const}" if is_unsound else ""),
            "verdict": verdict,
            "source": "recovery_soundness_gate",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(16);
mov [p+8], 0x100;
"""
    out = run_recovery_soundness_gate(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])