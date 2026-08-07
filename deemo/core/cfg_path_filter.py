"""
CFG 可达路径过滤 — 基于控制流图的基本块可达性分析。

问题: vuln_analyzer 的 UAF 检测用 free(X).*?X-> 正则跨行匹配，
不区分 free 和 deref 之间是否有保护性分支、是否在同一可达路径上。
误报来源: 反编译伪代码中 free 在 if 分支内、deref 在 else 分支内,
两者在文本上相邻但永不共存于同一执行路径。

方案: 从 angr 或 r2 获取 CFG 基本块邻接表，做 BFS 可达性判定。
  - 若 free 所在基本块到 deref 所在基本块无路径 → 排除
  - 若路径上存在 realloc/重新赋值 → 排除
  - 若不可获取 CFG → 回退到原始正则（宁误报不漏报）

复杂度: O(V+E) BFS, V=基本块数(通常 <100/函数), E=边数。

参考: CodeGrafter 用跨域 CPG 做编译器无关检测,
本模块退一步只做函数内 CFG 可达——但比纯正则多了路径感知。
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from core.detection_shared import CFGBlock

_log = logging.getLogger(__name__)


def extract_cfg_blocks(
    binary_path: str,
    func_name: str,
) -> List[CFGBlock]:
    """
    从二进制中提取指定函数的基本块及邻接关系。

    优先使用 angr CFG, angr 不可用时回退到 r2 反汇编手动构建。
    返回基本块列表——若提取失败返回空列表。
    """
    blocks: List[CFGBlock] = []

    # 路径A: angr CFGEmulated (最精确，但最重)
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        for f in cfg.functions.values():
            if f.name == func_name:
                for blk in f.blocks:
                    successors = [
                        succ.addr for succ in cfg.functions[f.addr].graph.successors(blk)
                        if hasattr(succ, 'addr')
                    ]
                    insns = []
                    if hasattr(blk, 'capstone') and blk.capstone:
                        for insn in blk.capstone.insns:
                            insns.append(f"{insn.mnemonic} {insn.op_str}")
                    blocks.append(CFGBlock(
                        start_addr=blk.addr,
                        end_addr=blk.addr + blk.size,
                        instructions=insns,
                        successors=successors,
                    ))
                break
        if blocks:
            return blocks
    except ImportError:
        pass
    except Exception as e:
        _log.debug("angr CFG extraction failed: %s", e)

    # 路径B: r2 反汇编手动构建 (轻量，但精度低)
    try:
        import subprocess
        from config import R2_PATH

        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', f's {func_name}', '-c', 'pdb', binary_path],
            capture_output=True, text=True, timeout=15,
        )
        # 从 r2 的基本块输出解析块边界和跳转目标
        current_block: CFGBlock | None = None
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            # r2 pdb 输出格式: 地址 指令...  ; 跳转目标
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if current_block is None:
                current_block = CFGBlock(start_addr=addr, end_addr=addr)
            current_block.end_addr = addr
            current_block.instructions.append(" ".join(parts[1:]))
            instr = " ".join(parts[1:]).lower()
            if any(x in instr for x in ('jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'call', 'ret')):
                for p in parts[2:]:
                    try:
                        target = int(p.rstrip(','), 16)
                        current_block.successors.append(target)
                    except ValueError:
                        pass
                blocks.append(current_block)
                current_block = None
        if current_block is not None:
            blocks.append(current_block)
    except Exception as e:
        _log.debug("r2 CFG extraction failed: %s", e)

    return blocks


def find_block_for_address(
    blocks: List[CFGBlock],
    target_addr: int | None = None,
    instruction_text: str | None = None,
) -> CFGBlock | None:
    """按地址或指令文本搜索基本块。"""
    if target_addr:
        for blk in blocks:
            if blk.start_addr <= target_addr <= blk.end_addr:
                return blk
    if instruction_text:
        instr_lower = instruction_text.lower()
        for blk in blocks:
            for insn in blk.instructions:
                if instr_lower in insn.lower():
                    return blk
    return None


def is_reachable(
    blocks: List[CFGBlock],
    from_block: CFGBlock,
    to_block: CFGBlock,
) -> bool:
    """BFS 检查 from_block 是否可达 to_block。O(V+E)。"""
    if not blocks or from_block == to_block:
        return False

    visited: Set[int] = set()
    queue: List[CFGBlock] = [from_block]
    while queue:
        current = queue.pop(0)
        if current.start_addr == to_block.start_addr:
            return True
        if current.start_addr in visited:
            continue
        visited.add(current.start_addr)
        for succ_addr in current.successors:
            for blk in blocks:
                if blk.start_addr == succ_addr and blk.start_addr not in visited:
                    queue.append(blk)
    return False


def verify_uaf_path(
    binary_path: str,
    func_name: str,
    free_var: str,
    deref_var: str,
    free_lineno: int = 0,
    deref_lineno: int = 0,
) -> Tuple[bool, str]:
    """验证 UAF: free(X) 到 X-> 是否在同一可达路径上。

    返回 (is_valid_true_positive, reason)。
    - True → 确实在同一可达路径上，保留 finding
    - False → 不在同一路径或有重分配，排除（降级或删除）
    """
    blocks = extract_cfg_blocks(binary_path, func_name)
    if not blocks:
        return True, "CFG不可获取，保留原判(宁误报不漏报)"

    free_block = find_block_for_address(blocks, instruction_text='free')
    deref_block = find_block_for_address(blocks, instruction_text='->')

    if free_block is None or deref_block is None:
        return True, "基本块定位失败，保留原判"

    if not is_reachable(blocks, free_block, deref_block):
        return False, (
            f"free({free_var}) 所在基本块 (0x{free_block.start_addr:x}) "
            f"不可达 deref 基本块 (0x{deref_block.start_addr:x})——排除误报"
        )

    # 检查路径上是否有重分配
    for blk in blocks:
        if is_reachable(blocks, free_block, blk) and is_reachable(blocks, blk, deref_block):
            for insn in blk.instructions:
                if 'malloc' in insn or 'realloc' in insn or 'calloc' in insn:
                    if deref_var in insn or free_var in insn:
                        return False, (
                            f"{free_var} 在 free 和 deref 之间被重新分配——排除误报"
                        )

    return True, "free→deref 可达, 无重分配, 确认为真阳性"
