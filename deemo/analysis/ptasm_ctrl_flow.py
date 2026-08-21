"""
PTASM 控制流辅助 — 分支体定位 / 单行展开 / 状态汇合.

从 ptasm_engine.PTASMEngine 中提取的纯函数 (无副作用, 无实例状态依赖):
  - normalize_single_line_ifs: 展开无括号的单行 if/while/for 为虚拟行
  - find_branch_bodies: 定位 if/while(cond) {then} else {else} 各部分边界
  - join_ptr_states: 两路径状态的保守汇合 (任一路径危险→危险)
"""


import re as _re_mod
from typing import Dict, List, Tuple

from analysis.ptasm_types import PtrState

# 预处理: 单行控制流展开

_CTRL_START_RE = _re_mod.compile(
    r'^\s*(if|while|for)\s*\(|^\s*\}?\s*else\s+if\s*\(')


def normalize_single_line_ifs(lines: List[str]) -> List[str]:
    """预处理: 将单行 if/while/for (无大括号) 展开为虚拟行.

    在分析开始前一次性完成所有展开, 避免分析过程中插入行导致
    end 参数 / 行索引错位.

    处理形式:
      if (cond) stmt;           → if (cond)\n    stmt;
      if (cond) stmt1; else stmt2; → if (cond)\n    stmt1;\n    stmt2;

    排除:
      - 已有大括号的控制流 (保持原样)
      - 下一行以 '{' 开头 (多行块, 保持原样)
      - 预处理指令和注释行
    """
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        result.append(line)
        stripped = line.strip()

        if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
            i += 1
            continue

        cm = _CTRL_START_RE.match(stripped)
        if not cm:
            i += 1
            continue

        ctrl_kw = cm.group(1) if cm.lastindex and cm.group(1) else (
            'else if' if 'else' in cm.group(0) else None)
        if not ctrl_kw:
            i += 1
            continue

        # 查找匹配的条件括号
        cp = stripped.find('(')
        if cp < 0:
            i += 1
            continue

        depth = 0
        rp = -1
        for k in range(cp, len(stripped)):
            if stripped[k] == '(':
                depth += 1
            elif stripped[k] == ')':
                depth -= 1
                if depth == 0:
                    rp = k
                    break
        if rp < 0:
            i += 1
            continue

        # 检查是否有大括号 (当前行或下一行)
        has_brace = '{' in stripped[rp:]
        if not has_brace and i + 1 < len(lines):
            next_stripped = lines[i + 1].strip()
            has_brace = next_stripped.startswith('{')

        if has_brace:
            i += 1
            continue

        # 单行控制流: 提取 then-stmt
        remaining = stripped[rp + 1:].strip()
        if not remaining:
            i += 1
            continue

        # 在剩余部分中找 else 关键字 (注意字符串字面量 — 简化处理)
        else_idx = -1
        pos = 0
        while pos < len(remaining):
            ep = remaining.find('else', pos)
            if ep < 0:
                break
            before_ok = ep == 0 or not remaining[ep - 1].isalnum()
            after_ok = (ep + 4 >= len(remaining)
                        or not remaining[ep + 4].isalnum())
            if before_ok and after_ok:
                else_idx = ep
                break
            pos = ep + 4

        then_stmt = remaining[:else_idx].strip() if else_idx >= 0 else remaining
        else_stmt = remaining[else_idx + 4:].strip() if else_idx >= 0 else ""

        indent = line[:len(line) - len(line.lstrip())]
        if then_stmt and then_stmt != ';':
            result.append(indent + '    ' + then_stmt)
        if else_stmt and else_stmt != ';':
            result.append(indent + '    ' + else_stmt)

        i += 1

    return result


# 分支体边界定位

def find_branch_bodies(lines: List[str], cond_idx: int
                        ) -> Tuple[int, int, int, int, int]:
    """定位 if/while(cond) { then } else { else } 的各部分边界.

    处理两种形式:
      - 带括号: if (cond) { ... } else { ... }
      - 单行:   if (cond) stmt;  (无括号, then-body仅为预处理插入的虚拟行)

    返回 (then_start, then_end, else_start, else_end, merge_idx).
    若找不到: 返回 (-1, -1, -1, -1, cond_idx+1)
    """
    line = lines[cond_idx]

    # 检查是否有 opening brace
    brace_idx = -1
    for k in range(cond_idx, min(cond_idx + 3, len(lines))):
        if '{' in lines[k]:
            brace_idx = k
            break

    if brace_idx < 0:
        # 单行 if/while/for (无大括号): 预处理已插入虚拟then-body行
        if cond_idx + 1 < len(lines):
            next_indent = len(lines[cond_idx + 1]) - len(lines[cond_idx + 1].lstrip())
            cur_indent = len(line) - len(line.lstrip())
            if next_indent > cur_indent:
                return cond_idx + 1, cond_idx + 2, -1, -1, cond_idx + 2
        return -1, -1, -1, -1, cond_idx + 1

    then_start = brace_idx + 1
    depth = 1
    else_start = -1
    then_end = -1
    merge_idx = -1
    else_end = -1

    for k in range(then_start, len(lines)):
        s = lines[k].strip()
        delta = s.count('{') - s.count('}')
        # '} else {' 在一行内: 先关闭then再打开else
        is_else_boundary = (s.startswith('} else') or s.startswith('}else'))
        if is_else_boundary and then_end < 0:
            then_end = k
            depth += delta
            if '{' in s:
                else_start = k + 1
            else:
                for m in range(k + 1, min(k + 3, len(lines))):
                    if '{' in lines[m]:
                        else_start = m + 1
                        break
            if else_start > k:
                depth = 1
            continue
        depth += delta
        if depth <= 0:
            merge_idx = k + 1
            if then_end < 0:
                then_end = k
            if else_start >= 0 and else_end < 0:
                else_end = k
            break

    if then_end < 0:
        then_end = merge_idx if merge_idx > 0 else len(lines)
    if else_start >= 0 and else_end < 0:
        else_end = merge_idx if merge_idx > 0 else len(lines)

    return (then_start, then_end, else_start,
            else_end if else_start >= 0 else -1,
            merge_idx if merge_idx > 0 else len(lines))


# 状态汇合 (路径交汇处)

def join_ptr_states(s1: PtrState, s2: PtrState) -> PtrState:
    """两个路径的状态汇合. 保守原则: 任一路径危险 → 危险.

    USE_AFTER_FREE 是粘性状态 (sticky):
      - 一旦在某路径检测到UAF, 汇合后仍为UAF
      - FREED + 安全状态 = FREED (有一条路径还悬空)
      - 两路径都安全 → 取更强证据 (REASSIGNED > NULLIFIED > LIVE)
    """
    if s1 == s2:
        return s1
    if PtrState.USE_AFTER_FREE in (s1, s2):
        return PtrState.USE_AFTER_FREE
    if PtrState.FREED in (s1, s2):
        return PtrState.FREED
    if PtrState.REASSIGNED in (s1, s2):
        return PtrState.REASSIGNED
    if PtrState.NULLIFIED in (s1, s2):
        return PtrState.NULLIFIED
    return PtrState.LIVE


__all__ = [
    'normalize_single_line_ifs',
    'find_branch_bodies',
    'join_ptr_states',
]
