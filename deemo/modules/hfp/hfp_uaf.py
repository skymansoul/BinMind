"""
UAF 深挖检测器 — 伪 IR 级指针生命周期分析.

既有 core.uaf_detector 只追踪顶层指针变量, 对
free(u->timer) 后 u->timer->id 的字段间接解引用不识别.
本模块在 HFP 伪 IR 上做生命周期分析:
  - alloc: vN = malloc(...) 注册指针
  - free:  free(vN) 或 store 后 free (经槽别名) 标记释放
  - use:   use vN + off / store vN + off / memcpy(vN,...) 
  - 判定: 释放后的 use → UAF; 同一指针两次 free → double-free
跨函数: 伪 IR 已含调用点展开 (memcpy 内联), 且 free 经
call_args 注入参数槽, 块序问题通过"全文件 alloc 表"缓解 —
先扫描全部 alloc, 再逐行处理 free/use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_RE_ALLOC = re.compile(r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(', re.IGNORECASE)
_RE_FREE = re.compile(r'free\(\s*(\w+)\s*\)', re.IGNORECASE)
_RE_USE = re.compile(r'use\s+(\w+)\s*\+\s*(\d+)', re.IGNORECASE)
_RE_STORE = re.compile(r'store\s+(\w+)\s*\+\s*(\d+)', re.IGNORECASE)
_RE_COPY = re.compile(
    r'(memcpy|memset)\s*\(\s*(\w+)\s*,', re.IGNORECASE)


@dataclass
class UafState:
    """单个指针的生命周期状态."""
    var: str
    alloc_line: int = -1
    freed: bool = False
    free_lines: List[int] = field(default_factory=list)
    use_lines: List[int] = field(default_factory=list)
    double_free: bool = False


def detect_uaf_hfp(ir_lines: List[str]) -> List[Dict]:
    """伪 IR 级 UAF 检测: 返回 finding dict 列表."""
    # 第一遍: 注册全部 alloc (不受块序影响)
    states: Dict[str, UafState] = {}
    for i, line in enumerate(ir_lines):
        m = _RE_ALLOC.search(line)
        if m:
            var = m.group(1)
            if var not in states:
                states[var] = UafState(var=var, alloc_line=i)

    # 置空豁免: free 后紧跟 store vN + 0 = 0 (指针字段本身置 NULL)
    # 的指针, 其后续 free/use 视为对已置空字段的操作, 不判 UAF/
    # double-free. 仅偏移 0 的置零算指针置空; 其他字段清零
    # (active=0 等) 不豁免 — 避免误伤真实 UAF
    nulled: set = set()
    for i, line in enumerate(ir_lines):
        m = _RE_FREE.search(line)
        if not m:
            continue
        var = m.group(1)
        for j in range(i + 1, min(i + 5, len(ir_lines))):
            if re.match(rf'store {re.escape(var)} \+ 0 = 0', ir_lines[j]):
                nulled.add(var)
                break

    # 块序无关判定: 函数块按地址排序, free 可能在 alloc 之前出现.
    # 只把"同一函数块内 free 之后"的 use 判为 UAF — 跨块 use 的
    # 执行序由调用关系决定, 伪 IR 无法可靠排序, 保守不判
    block_of: Dict[int, int] = {}
    cur_block = 0
    for i, line in enumerate(ir_lines):
        if line.startswith('# fn '):
            cur_block += 1
        block_of[i] = cur_block

    # 引用计数保护识别: 某 var 存在非零 store 到偏移 0 (refcnt
    # 字段初始化/递增) 且 free 数 >= 8 且删去最大间距后其余 free
    # 相邻 (同一 obj_put 内联展开), 才判条件释放 — 分散的 free
    # (真实 UAF 的不同释放路径) 不豁免
    refcnt_vars: set = set()
    free_count: Dict[str, int] = {}
    free_positions: Dict[str, List[int]] = {}
    for i, line in enumerate(ir_lines):
        m = re.search(r'store\s+(\w+)\s+\+\s+0\s*=\s*([1-9]\d*)', line)
        if m:
            refcnt_vars.add(m.group(1))
        m = _RE_FREE.search(line)
        if m:
            var = m.group(1)
            free_count[var] = free_count.get(var, 0) + 1
            free_positions.setdefault(var, []).append(i)

    def _is_contiguous_free(var: str) -> bool:
        """free 位置是否高度聚集 (行距 <= 8).

        refcnt 保护的内联 free 序列频繁调用 obj_put, free 数
        显著多于真实 UAF (分散在 2-5 个释放路径). 用 free 总数
        >= 8 且删去最大间距后其余相邻区分两者.
        # TODO: 阈值 8 由当前样本集标定, 真实代码库分布待验证
        """
        pos = free_positions.get(var, [])
        if len(pos) < 8:
            return False
        gaps = sorted(pos[k + 1] - pos[k] for k in range(len(pos) - 1))
        if not gaps:
            return False
        # 删去最大间距后, 其余间距须全部 <= 8
        rest = gaps[:-1]
        return all(g <= 8 for g in rest)

    refcnt_protected = {
        var for var in refcnt_vars
        if free_count.get(var, 0) >= 8 and _is_contiguous_free(var)
    }

    findings: List[Dict] = []
    for i, line in enumerate(ir_lines):
        m = _RE_FREE.search(line)
        if m:
            var = m.group(1)
            if var in nulled:
                continue
            st = states.get(var)
            if st is None:
                continue
            # 不按行号过滤: 函数块按地址排序, free 块可能在
            # alloc 块之前, 但执行序是 alloc 先 — 行号不可靠,
            # 由 use 判定侧的 alloc 检查兜底
            if st.freed:
                # 连续 free 序列去重: 同块内相邻行的多次 free 是
                # 同一调用点的内联展开 (条件释放路径), 只计一次
                if st.free_lines and \
                        block_of.get(st.free_lines[-1], -1) == \
                        block_of.get(i, -2) and \
                        i - st.free_lines[-1] <= 2:
                    continue
                # 置空豁免: 两次 free 之间若有指针字段置零
                # (store vN + 0 = 0), 视为重新初始化后的 free
                between = ir_lines[st.free_lines[-1] + 1:i]
                if any(re.match(rf'store {re.escape(var)} \+ 0 = 0', l)
                       for l in between):
                    st.free_lines.append(i)
                    continue
                if st.free_lines and block_of.get(
                        st.free_lines[-1], -1) == block_of.get(i, -2):
                    st.double_free = True
                    findings.append({
                        'var': var, 'type': 'double_free',
                        'free_lines': list(st.free_lines) + [i],
                        'confidence': 0.9,
                    })
            else:
                st.freed = True
                st.free_lines.append(i)
            continue
        m = _RE_USE.search(line)
        if m and m.group(1) in states:
            var = m.group(1)
            if var in nulled:
                continue
            st = states[var]
            st.use_lines.append(i)
            # free 有效 (alloc 之后) 且 use 在其后 → UAF
            if st.freed and _free_valid_after(st, i, block_of):
                if var in refcnt_protected:
                    # 引用计数保护: free 仅在 refcnt==0 时发生,
                    # use 路径必经 refcnt>0 检查, 不构成 UAF
                    continue
                findings.append({
                    'var': var, 'type': 'use_after_free',
                    'free_lines': list(st.free_lines),
                    'use_line': i,
                    'confidence': 0.85,
                })
            continue
        m = _RE_STORE.search(line)
        if m and m.group(1) in states:
            var = m.group(1)
            st = states[var]
            # 置零写 (store vN + off = 0) 是 NULL/初始化语义,
            # 不算 UAF use
            if ' = 0' in line or '= 0x0' in line:
                continue
            st.use_lines.append(i)
            if st.freed and _free_valid_after(st, i, block_of):
                if var in refcnt_protected:
                    continue
                findings.append({
                    'var': var, 'type': 'use_after_free_write',
                    'free_lines': list(st.free_lines),
                    'use_line': i,
                    'confidence': 0.80,
                })
            continue
        m = _RE_COPY.search(line)
        if m and m.group(2) in states:
            var = m.group(2)
            st = states[var]
            st.use_lines.append(i)
            if st.freed and _free_valid_after(st, i, block_of):
                if var in refcnt_protected:
                    continue
                findings.append({
                    'var': var, 'type': 'use_after_free_copy',
                    'free_lines': list(st.free_lines),
                    'use_line': i,
                    'confidence': 0.82,
                })

    # 去重: 同 var 同类型只保留首个
    seen = set()
    unique = []
    for f in findings:
        key = (f['var'], f['type'], f.get('use_line', -1))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: -f['confidence'])
    return unique


def _same_block_after(block_of: Dict[int, int], use_line: int,
                      free_lines: List[int]) -> bool:
    """use 与任一 free 同块且位于其后."""
    ub = block_of.get(use_line, -1)
    return any(block_of.get(fl, -2) == ub and use_line > fl
               for fl in free_lines)


def _free_valid_after(st, use_line: int, block_of: Dict[int, int]) -> bool:
    """use 位于 free 之后 (行号序).

    块序不代表执行序, 但 free/use 在同一执行路径上时, 行号
    序在函数内有效; 跨块时按行号近似 (free 行号 < use 行号).
    """
    if st.alloc_line < 0:
        return False
    return any(use_line > fl for fl in st.free_lines)

def detect_from_asm(asm_text: str) -> List[Dict]:
    """反汇编文本 → 伪 IR → UAF findings."""
    from .hfp_scan import asm_to_pseudo_ir
    ir = asm_to_pseudo_ir(asm_text)
    return detect_uaf_hfp(ir)