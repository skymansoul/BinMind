"""后向值流追踪器 — 从 call malloc 的 size 参数出发反向定义值域.

创建: 2025-03-03
修改: 2025-03-03 (添加寄存器别名 + 栈槽位跟踪)

用途: 独立的后向值流追踪, 从 malloc 调用点沿 def-use 链反向搜索,
      推导 size 参数的跨步区间 (SInterval).

设计决策:
  - 为什么后向而非前向: 前向需从函数入口开始追踪所有寄存器, 计算量大且
    大部分追踪结果与堆操作无关。后向从需求点 (malloc 调用) 出发, 只追踪
    相关的 def-use 链, 追踪步数有界 (MAX_DEPTH=40)。
  - 截断条件: 遇到 call 指令 (跨函数边界)、内存加载 (值未知)、
    或达到最大深度时停下。这些截断点是"有界非健全性"的明确声明:
    复杂数据流 (如从全局变量加载 size) 退化为 TOP, 交给后续阶段处理。
  - 双 ABI 兼容: System V (rdi=arg1) vs Microsoft x64 (rcx=arg1),
    由调用方分别尝试后选择更精确的结果。
  - 寄存器别名: x86_64 上写 ecx 清零 rcx 高 32 位 → mov ecx, 0x40
    等价于 rcx=64。追踪 rcx 时也需要匹配 ecx 的写入。
  - 栈槽位溢出追踪: MS x64 调用约定第一件事就是把 rcx/rdx/r8/r9 溢出
    到栈, 后再从栈加载给 malloc。本模块记录栈溢出并反向恢复参数来源。
"""
import re
from typing import Dict, List, Optional, Set

from .interval_domain import SInterval


# 最大后向追踪深度: 超出则截断 (有界非健全性)
MAX_DEPTH = 40

# x86_64 32-bit → 64-bit 寄存器别名
# mov ecx, 0x40 等价于 rcx=64 (零扩展)
_REG_ALIAS_32TO64: Dict[str, str] = {
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
    'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
    'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15',
}

# 64-bit → 32-bit 反向映射
_REG_ALIAS_64TO32: Dict[str, str] = {
    'rax': 'eax', 'rbx': 'ebx', 'rcx': 'ecx', 'rdx': 'edx',
    'rsi': 'esi', 'rdi': 'edi', 'rbp': 'ebp', 'rsp': 'esp',
    'r8': 'r8d', 'r9': 'r9d', 'r10': 'r10d', 'r11': 'r11d',
    'r12': 'r12d', 'r13': 'r13d', 'r14': 'r14d', 'r15': 'r15d',
}


def _is_same_reg(a: str, b: str) -> bool:
    """判断两个寄存器名是否指同一个物理寄存器 (含 32/64 位别名)."""
    if a == b:
        return True
    return (_REG_ALIAS_32TO64.get(a) == b or
            _REG_ALIAS_64TO32.get(b) == a)


def _canonical_reg(reg: str) -> str:
    """将寄存器名标准化为 64-bit 形式."""
    return _REG_ALIAS_32TO64.get(reg, reg)


def backward_trace(instructions: List[str],
                   start_idx: int,
                   target_reg: str,
                   max_depth: int = MAX_DEPTH) -> SInterval:
    """从 start_idx 出发后向追踪 target_reg 的值.

    兼容 Intel 语法 (Windows objdump -M intel) 和 AT&T 语法.

    增强项:
      - 寄存器别名: mov ecx, 0x40 在追踪 rcx 时被识别
      - 栈槽位溢出: mov [rbp+N], rcx ... mov rcx, [rbp+N] →
        识别为参数传递而非 TOP 截断

    返回 SInterval: 追踪到的值区间, TOP 表示无法确定。
    """
    current_reg = _canonical_reg(target_reg.lower())
    current_si = SInterval.top()
    visited: Set[str] = {current_reg}
    # 栈槽位溢出表: {offset: canonical_reg_that_was_spilled}
    stack_spills: Dict[str, str] = {}
    depth = 0

    for i in range(start_idx - 1,
                   max(-1, start_idx - max_depth), -1):
        if depth >= max_depth:
            break
        instr = instructions[i].strip()
        if not instr or instr.startswith(';') or instr.startswith('.'):
            continue
        depth += 1

# call 边界截断
        if 'call' in instr.lower():
            break

# push/pop 不追踪
        if instr.startswith('push') or instr.startswith('pop'):
            continue

# 记录栈溢出: mov [rbp±N], {rcx,rdx,r8,r9,...}
        m_spill = re.match(
            r'mov\s+(?:\w+\s+ptr\s+)?\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\],\s*(\w+)',
            instr, re.I)
        if m_spill:
            spilled_src = _canonical_reg(m_spill.group(3).lower())
            sign = 1 if m_spill.group(1) == '+' else -1
            slot_offset = sign * int(m_spill.group(2), 16 if '0x' in m_spill.group(2).lower() else 10)
            stack_spills[str(slot_offset)] = spilled_src
            # 如果当前追踪的就是被溢出的寄存器, 继续追踪写入源
            # (mov [rbp+N], rcx → 在追踪 rcx 时, 我们记录这个溢出, 但实际上这是
            #  把 rcx 写出去, 不是写入 rcx — 跳过, 继续反向)
            continue

# 从栈槽位加载: mov reg, [rbp±N]
        m_load = re.match(
            r'mov\s+(\w+),\s*(?:\w+\s+ptr\s+)?\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
            instr, re.I)
        if m_load:
            dst_reg = _canonical_reg(m_load.group(1).lower())
            sign = 1 if m_load.group(2) == '+' else -1
            slot_offset = sign * int(m_load.group(3), 16 if '0x' in m_load.group(3).lower() else 10)

            # 检查是否与我们追踪的寄存器相关
            if _is_same_reg(dst_reg, current_reg):
                slot_key = str(slot_offset)
                if slot_key in stack_spills:
                    # 之前有这个槽位的溢出记录 → 恢复寄存器追踪
                    prev_reg = stack_spills[slot_key]
                    if prev_reg in visited:
                        break
                    visited.add(prev_reg)
                    current_reg = prev_reg
                    continue
                else:
                    # 从栈加载但不知道来源 → TOP (非参数传递)
                    return SInterval.top()

# mov reg, imm (Intel & AT&T)
        m = re.match(r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$',
                     instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            if dst == current_reg:
                v = (int(m.group(2), 16) if '0x' in m.group(2).lower()
                     else int(m.group(2)))
                return SInterval.exact(v)

# mov reg1, reg2
        m = re.match(r'mov\s+(\w+),\s*(\w+)\s*$', instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            src = _canonical_reg(m.group(2).lower())
            if dst == current_reg:
                if src in visited:
                    break
                visited.add(src)
                current_reg = src
                continue

# mov reg, [mem] (非栈帧的通用内存) → TOP
        m = re.match(
            r'mov\s+(\w+),\s*(?:\w+\s+ptr\s+)?\[([^\]]+)\]',
            instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            if dst == current_reg:
                return SInterval.top()

# cdqe / cdq / cqo (符号扩展)
        m = re.match(r'cdqe?\s*$', instr, re.I)
        if m and current_reg == 'rax':
            current_reg = 'rax'  # cdqe: eax→rax, 继续以 rax 追踪
            continue

# movsx/movzx/movsxd reg1, reg2
        m = re.match(r'mov[sz]x[d]?\s+(\w+),\s*(\w+)(?:\s*$|\s*,)',
                     instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            src = _canonical_reg(m.group(2).lower())
            if dst == current_reg:
                if src in visited:
                    break
                visited.add(src)
                current_reg = src
                continue

# lea reg, [base + N*idx + offset]
        m = re.match(
            r'lea\s+(\w+),\s*\[(\w+)\s*([+\-])\s*(\d+)\s*\*?\s*(\w*)\]',
            instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            if dst == current_reg:
                base = _canonical_reg(m.group(2).lower())
                sign = 1 if m.group(3) == '+' else -1
                imm = int(m.group(4))
                idx = m.group(5).lower() if m.group(5) else ''
                if not idx:
                    current_si = SInterval.exact(sign * imm)
                    current_reg = base
                continue

# add reg, imm
        m = re.match(r'add\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$',
                     instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            if dst == current_reg:
                v = (int(m.group(2), 16) if '0x' in m.group(2).lower()
                     else int(m.group(2)))
                current_si = (current_si.add(v) if not current_si.is_top
                              else SInterval.exact(v))
                continue

# sub reg, imm
        m = re.match(r'sub\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$',
                     instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            if dst == current_reg:
                v = (int(m.group(2), 16) if '0x' in m.group(2).lower()
                     else int(m.group(2)))
                current_si = (current_si.add(-v) if not current_si.is_top
                              else SInterval.exact(-v))
                continue

# imul reg, reg, imm
        m = re.match(r'imul\s+(\w+),\s*\w+,\s*(0x[0-9a-f]+|\d+)\s*$',
                     instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            if dst == current_reg:
                factor = (int(m.group(2), 16) if '0x' in m.group(2).lower()
                          else int(m.group(2)))
                current_si = (current_si.mul(factor) if not current_si.is_top
                              else SInterval.top())
                continue

# shl reg, N
        m = re.match(r'shl\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$',
                     instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            if dst == current_reg:
                n = (int(m.group(2), 16) if '0x' in m.group(2).lower()
                     else int(m.group(2)))
                factor = 1 << n
                current_si = (current_si.mul(factor) if not current_si.is_top
                              else SInterval.top())
                continue

# xor reg, reg → 0
        m = re.match(r'xor\s+(\w+),\s*\1\s*$', instr, re.I)
        if m:
            dst = _canonical_reg(m.group(1).lower())
            if dst == current_reg:
                return SInterval.exact(0)

# strlen/strnlen/sizeof → TOP
        for src_func in ('strlen', 'strnlen', 'sizeof'):
            if src_func in instr.lower() and 'call' in instr.lower():
                return SInterval.top()

    return current_si
