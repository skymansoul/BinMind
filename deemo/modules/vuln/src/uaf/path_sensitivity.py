"""DRIFT 路径敏感分析 — 基本块划分 + CFG可达性 + 路径感知free-use配对.

核心创新: 消除"free和use在不同分支上"的误报.
方法: 将指令序列划分为基本块, 构建CFG边, 对每个free-use对检查free所在块
      能否到达use所在块。若不可达 → 过滤。

与heap_path_sensitivity.py的区别:
  那边做cmp+jcc约束区间交 (值域), 这边做CFG可达性 (控制流).

创建: 2024-08-14
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re


@dataclass
class BasicBlock:
    """一个基本块 — 连续指令序列, 单入口单出口."""
    id: int
    start_line: int       # 第一条指令行号
    end_line: int         # 最后一条指令行号 (含)
    successors: List[int] = field(default_factory=list)  # 后继块ID
    predecessors: List[int] = field(default_factory=list)  # 前驱块ID
    is_return: bool = False  # 是否以ret结尾
    is_call: bool = False    # 是否以call结尾 (可能返回)
    label: str = ""


@dataclass
class CFG:
    """控制流图."""
    blocks: List[BasicBlock] = field(default_factory=list)
    entry_id: int = 0
    # 行→块映射
    line_to_block: Dict[int, int] = field(default_factory=dict)


def build_cfg(asm_lines: List[str]) -> CFG:
    """从汇编指令序列构建控制流图.

    两遍算法:
      Pass 1: 收集所有地址→行号映射
      Pass 2: 找leader + 划分基本块 + 构建边
    """
    cfg = CFG()
    n = len(asm_lines)
    addr_to_line: Dict[int, int] = {}

    # Pass 1: 收集所有地址
    for i, line in enumerate(asm_lines):
        il = line.strip()
        if not il or il.startswith(';') or il.startswith('.'):
            continue
        addr_m = re.match(r'\s*([0-9a-f]+):\s+', il)
        if addr_m:
            addr_to_line[int(addr_m.group(1), 16)] = i

    # Pass 2: 找leader
    leaders: Set[int] = {0}

    for i, line in enumerate(asm_lines):
        il = line.strip()
        if not il or il.startswith(';') or il.startswith('.'):
            continue
        il_lower = il.lower()

        # 跳转指令: 目标地址是leader
        # objdump输出两种格式: "je 0x401000" 或 "je 401000"
        jmp_m = re.search(
            r'\b(jmp|je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|js|jns'
            r'|jo|jno|jp|jnp|jcxz|jecxz|loop|loope|loopne)\s+'
            r'(0x[0-9a-f]+|[0-9a-f]{6,})', il_lower)
        if jmp_m:
            target_str = jmp_m.group(2)
            try:
                target = _parse_addr(target_str)
                if target in addr_to_line:
                    leaders.add(addr_to_line[target])
            except ValueError:
                pass

        # 条件跳转后的下一条指令 → leader
        if re.search(r'\b(jne|je|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe'
                     r'|js|jns|jo|jno|jp|jnp|jcxz|jecxz|loop|loope|loopne)\s+',
                     il_lower):
            if i + 1 < n:
                # 跳过空行
                for j in range(i + 1, min(i + 5, n)):
                    if asm_lines[j].strip() and not asm_lines[j].strip().startswith(';'):
                        leaders.add(j)
                        break

        # call后的下一条指令 → leader (call可能返回)
        if re.search(r'\bcall\b', il_lower):
            if i + 1 < n:
                for j in range(i + 1, min(i + 5, n)):
                    if asm_lines[j].strip() and not asm_lines[j].strip().startswith(';'):
                        leaders.add(j)
                        break

        # ret → 块结束, 下一条指令是leader
        # re.search (非match): objdump行有地址前缀 "1400017b6: c3  ret"
        if re.search(r'\b(ret|retn|rep\s+ret)\b', il_lower):
            if i + 1 < n:
                for j in range(i + 1, min(i + 5, n)):
                    if asm_lines[j].strip() and not asm_lines[j].strip().startswith(';'):
                        leaders.add(j)
                        break

    # 按leader划分基本块
    sorted_leaders = sorted(leaders)
    block_id = 0
    line_to_block: Dict[int, int] = {}

    for idx, start in enumerate(sorted_leaders):
        end = sorted_leaders[idx + 1] - 1 if idx + 1 < len(sorted_leaders) else n - 1
        # 找到最后一条实际指令
        while end >= start and (not asm_lines[end].strip() or
                                 asm_lines[end].strip().startswith(';')):
            end -= 1
        if end < start:
            continue

        block = BasicBlock(id=block_id, start_line=start, end_line=end)
        cfg.blocks.append(block)
        for line in range(start, end + 1):
            line_to_block[line] = block_id
        block_id += 1

    cfg.line_to_block = line_to_block

    # 构建CFG边
    for block in cfg.blocks:
        last_line = asm_lines[block.end_line].strip().lower() if block.end_line < n else ""

        # 无条件跳转 → 只有一个后继
        # objdump输出: "jmp 401000" 或 "jmp 0x401000"
        jmp_m = re.search(r'\bjmp\s+(0x[0-9a-f]+|[0-9a-f]{6,})', last_line)
        if jmp_m:
            target_str = jmp_m.group(1)
            try:
                target = _parse_addr(target_str)
                target_line = addr_to_line.get(target)
                if target_line is not None and target_line in line_to_block:
                    succ = line_to_block[target_line]
                    block.successors.append(succ)
                    cfg.blocks[succ].predecessors.append(block.id)
            except ValueError:
                pass
            # 无条件跳转后不会落空, 跳过后续逻辑
            if not _is_conditional(last_line):
                # 标记exit块
                if 'ret' in last_line:
                    block.is_return = True
                continue

        # 条件跳转 → 两个后继: 跳转目标 + 下一个块
        cond_m = re.search(
            r'\b(jne|je|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|js|jns)\s+'
            r'(0x[0-9a-f]+|[0-9a-f]{6,})', last_line)
        if cond_m:
            target_str = cond_m.group(2)
            try:
                target = _parse_addr(target_str)
                target_line = addr_to_line.get(target)
                if target_line is not None and target_line in line_to_block:
                    succ = line_to_block[target_line]
                    block.successors.append(succ)
                    cfg.blocks[succ].predecessors.append(block.id)
            except ValueError:
                pass
            # 下一块也是后继
            next_block_id = _find_next_block(block.id, cfg.blocks)
            if next_block_id is not None:
                block.successors.append(next_block_id)
                cfg.blocks[next_block_id].predecessors.append(block.id)

        # ret → 无后继
        elif re.search(r'\b(ret|retn|rep\s+ret)\b', last_line):
            block.is_return = True

        # call → 后继是下一个块 (call返回)
        elif re.search(r'\bcall\b', last_line):
            next_block_id = _find_next_block(block.id, cfg.blocks)
            if next_block_id is not None:
                block.successors.append(next_block_id)
                cfg.blocks[next_block_id].predecessors.append(block.id)

        # 顺序执行 → 后继是下一个块
        else:
            next_block_id = _find_next_block(block.id, cfg.blocks)
            if next_block_id is not None:
                block.successors.append(next_block_id)
                cfg.blocks[next_block_id].predecessors.append(block.id)

    return cfg


def _is_conditional(last_line: str) -> bool:
    """检查是否是条件跳转 (而非无条件jmp)."""
    return bool(re.search(
        r'\b(jne|je|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|js|jns)\s+',
        last_line))


def _find_next_block(current_id: int, blocks: List[BasicBlock]) -> Optional[int]:
    """找下一个块 (按行号)."""
    if current_id + 1 < len(blocks):
        return current_id + 1
    return None


def _parse_addr(s: str) -> int:
    """解析objdump地址字符串为整数."""
    s = s.strip().lower()
    if s.startswith('0x'):
        return int(s[2:], 16)
    # 无0x前缀但包含a-f → 十六进制地址
    if any(c in s for c in 'abcdef'):
        return int(s, 16)
    # 纯数字 → 可能是十进制(小数值)或十六进制(大地址)
    v = int(s)
    if v > 0xFFFF:  # 大数值 → 应该是十六进制地址(被误解析)
        return int(s, 16)
    return v


def path_exists(cfg: CFG, from_line: int, to_line: int) -> bool:
    """检查from_line所在块能否到达to_line所在块 (BFS)."""
    from_block = cfg.line_to_block.get(from_line)
    to_block = cfg.line_to_block.get(to_line)
    if from_block is None or to_block is None:
        return True  # 保守: 无法确定时保留
    if from_block == to_block:
        return True

    visited = {from_block}
    queue = [from_block]
    while queue:
        cur = queue.pop(0)
        if cur >= len(cfg.blocks):
            continue
        for succ in cfg.blocks[cur].successors:
            if succ == to_block:
                return True
            if succ not in visited:
                visited.add(succ)
                queue.append(succ)
    return False


def is_path_sensitive_uaf(free_line: int, use_line: int,
                          asm_lines: List[str]) -> bool:
    """主入口: 检查free→use是否在同一条可达路径上.

    返回 True 如果UAF有效 (free可达use), False 如果应过滤.
    """
    if free_line >= use_line:
        return False
    cfg = build_cfg(asm_lines)
    return path_exists(cfg, free_line, use_line)
