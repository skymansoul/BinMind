"""循环累积写入检测器 — 识别循环内的 memcpy/memset 并计算累积溢出.

创建: 2024-11-05
用途: 检测 for/while 循环内逐次写入 malloc 缓冲区的累积溢出模式.
      malloc(512) + for(i=0;i<16;i++) memset(buf+i*64,...,64) → 累积1024>512.
设计: 轻量模式匹配 (cmp+jcc 后向跳转 + 归纳变量追踪), 不依赖完整控制流图.
"""
import os, sys, re
from typing import Dict, List, Optional, Tuple

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

from insn_parser import Instruction, extract_register, extract_constant


def detect_loop_accumulated(insns: List[Instruction],
                            memcpys: List[dict],
                            mallocs: List[dict]) -> List[dict]:
    """识别循环内 memcpy 的累积写入, 返回增强后的 finding 列表.

    策略: 扫描后向跳转 (jle/jne/jl/jg/...), 向前找到 cmp 和循环变量,
          向后扫描循环体内的 add 归纳变量和 memset 调用,
          计算 trip_count * per_iter_size 累积溢出.

    返回每个循环中累积 memcpy 的额外 findings (可能为空)。
    """
    if len(insns) < 6:
        return []

    extra = []
    # 构建 memcpy 地址索引
    mc_by_addr = {}
    for mc in memcpys:
        mc_by_addr[mc.get('addr', 0)] = mc

    for idx, insn in enumerate(insns):
        mn = insn.mnemonic
        if mn not in ('jle', 'jl', 'jne', 'jbe', 'jb', 'jge', 'jg', 'jae', 'ja'):
            continue
        target = _parse_jump_target(insn.operands)
        if target is None or target >= insn.addr:
            continue  # 前向跳转, 不是循环回边

        # 找到了后向跳转 → 可能是循环
        # 向前 (向后扫描) 找 cmp
        cmp_idx = _find_prev_cmp(insns, idx)
        if cmp_idx is None:
            continue

        cmp_insn = insns[cmp_idx]
        cmp_reg = _cmp_register(cmp_insn)
        cmp_const = _cmp_constant(cmp_insn)
        if cmp_reg is None:
            continue

        # 向前找循环变量的初值 (mov reg, const 或 mov reg, 0)
        init_reg, init_val = _find_init(insns, cmp_idx, cmp_reg)
        if init_reg is None:
            continue

        trip_count = _trip_count(mn, cmp_const, init_val)
        if trip_count is None or trip_count <= 1:
            continue

        # 确定循环体范围
        loop_start = target  # 跳转目标地址
        loop_end = insn.addr  # 后向跳转地址

        loop_insns = [i for i in insns if loop_start <= i.addr <= loop_end]

        # 在循环体内找归纳变量 (add reg, const)
        iv_reg, iv_stride, iv_mem = _find_iv(loop_insns, cmp_reg)
        if iv_mem is None:
            # 没有内存归纳变量, 尝试寄存器归纳变量
            # 检查 memset 的 offset 是否使用了归纳变量
            pass  # 继续尝试

        # 在循环体内找 memset/memcpy 调用
        for li in loop_insns:
            if li.mnemonic != 'call':
                continue
            mc = mc_by_addr.get(li.addr)
            if mc is None:
                continue

            # 找到循环内的 memcpy → 计算累积
            # 当前 func_analyzer 只看到初始迭代的 offset
            initial_offset = mc.get('offset', 0)
            per_iter_size = mc.get('size_val', 0)
            if not isinstance(per_iter_size, int) or per_iter_size <= 0:
                continue

            # 若有归纳变量: 计算最大偏移量
            if iv_stride is not None and iv_stride > 0:
                max_offset = initial_offset + (trip_count - 1) * iv_stride
            else:
                max_offset = initial_offset

            cumulative_size = max_offset + per_iter_size

            # 匹配 malloc
            dst_val = str(mc.get('dst_val', ''))
            for m in mallocs:
                m_addr = m.get('addr', 0)
                if f'malloc@{m_addr:x}' in dst_val or f'calloc@{m_addr:x}' in dst_val:
                    alloc_sz = m.get('size_val', 128)
                    if not isinstance(alloc_sz, int) or alloc_sz <= 0:
                        alloc_sz = 128
                    if cumulative_size > alloc_sz:
                        extra.append({
                            'type': 'loop_accumulate',
                            'function': mc.get('function', ''),
                            'insn_addr': mc.get('addr', 0),
                            'alloc_size': alloc_sz,
                            'real_alloc_size': alloc_sz,
                            'offset': max_offset,
                            'access_size': per_iter_size,
                            'malloc_addr': m_addr,
                            'cumulative_size': cumulative_size,
                            'trip_count': trip_count,
                            'iv_stride': iv_stride,
                            'per_iter_size': per_iter_size,
                            'initial_offset': initial_offset,
                            'loop_back_edge': loop_end,
                            'phase': 'LOOP_ACCUM',
                        })
                    break

    return extra


def _parse_jump_target(op_str: str) -> Optional[int]:
    """从跳转操作数提取目标地址. '140001799 <main+0x39>' → 0x140001799."""
    m = re.search(r'([0-9a-fA-F]+)\b', op_str)
    return int(m.group(1), 16) if m else None


def _find_prev_cmp(insns: List[Instruction], jmp_idx: int) -> Optional[int]:
    """从跳转指令向前找最近的 cmp 指令 (向后扫描 ≤8条)."""
    for i in range(jmp_idx - 1, max(jmp_idx - 9, -1), -1):
        if insns[i].mnemonic == 'cmp':
            return i
    return None


def _cmp_register(insn: Instruction) -> Optional[str]:
    """cmp [mem], const 或 cmp reg, const → 返回被比较的寄存器/内存.
    cmp DWORD PTR [rbp-0x8], 0xf → 'rbp-0x8'."""
    op = insn.operands
    left = op.split(',')[0].strip()
    reg = extract_register(left)
    if '[' in left:
        import re as _re
        m = _re.search(r'\[(rbp[+-]0x[0-9a-fA-F]+)\]', left)
        if m:
            return m.group(1)
    return reg


def _cmp_constant(insn: Instruction) -> Optional[int]:
    """cmp ..., const → 返回常量值."""
    op = insn.operands
    if ',' not in op:
        return None
    right = op.split(',')[-1].strip()
    return extract_constant(right)


def _find_init(insns: List[Instruction], cmp_idx: int,
               cmp_reg: str) -> Tuple[Optional[str], Optional[int]]:
    """从 cmp 向前找循环变量初始化 (mov reg, 0 或 mov [mem], 0).
    cmp_reg 形式: 'rbp-0x8' (内存) 或 'eax' (寄存器)."""
    for i in range(cmp_idx - 1, max(cmp_idx - 20, -1), -1):
        insn = insns[i]
        if insn.mnemonic not in ('mov', 'movsxd', 'xor', 'pxor'):
            continue
        op = insn.operands
        dst = op.split(',')[0].strip()
        src = op.split(',')[-1].strip() if ',' in op else ''

        # 内存目的地: mov DWORD PTR [rbp-0x8], 0
        if '[' in dst and cmp_reg.startswith('rbp'):
            if dst == cmp_reg or cmp_reg in dst:
                c = extract_constant(src)
                if src_reg := extract_register(src):
                    continue  # mov from reg, not const init
                # xor 清零
                if insn.mnemonic in ('xor', 'pxor'):
                    src_reg2 = extract_register(src)
                    if src_reg2 and dst == src or src_reg2 == extract_register(dst):
                        return (dst, 0)
                return (dst, c if c is not None else 0)

        # 寄存器目的地: mov eax, 0
        dst_reg = extract_register(dst)
        if dst_reg and dst_reg == cmp_reg:
            if insn.mnemonic in ('xor', 'pxor'):
                src_reg = extract_register(src)
                if src_reg and dst_reg == src_reg:
                    return (dst_reg, 0)
            c = extract_constant(src)
            return (dst_reg, c if c is not None else 0)

    return (None, None)


def _trip_count(jcc: str, cmp_const: Optional[int],
                init_val: Optional[int]) -> Optional[int]:
    """根据跳转类型和比较常量计算循环次数.

    jle:    i <= N → trip = N+1 (i:0..N)
    jl:     i < N  → trip = N
    jne:    i != N → trip = N (假设 i:0→N-1))
    jbe/jb: 同上用无符号比较.
    """
    if cmp_const is None or init_val is None:
        return None
    if jcc in ('jle', 'jbe'):
        return max(0, cmp_const - init_val + 1)
    elif jcc in ('jl', 'jb'):
        return max(0, cmp_const - init_val)
    elif jcc in ('jne',):
        return max(0, cmp_const - init_val + 1)  # 保守: 假设全遍历
    elif jcc in ('jge', 'jae'):
        return max(0, init_val - cmp_const + 1)
    elif jcc in ('jg', 'ja'):
        return max(0, init_val - cmp_const)
    return None


def _find_iv(loop_insns: List[Instruction],
             cmp_target: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """在循环体内找归纳变量: add [mem], const 或 add reg, const.
    返回 (reg_name, stride, mem_target_or_None)."""
    for insn in loop_insns:
        if insn.mnemonic != 'add':
            continue
        op = insn.operands
        dst = op.split(',')[0].strip()
        src = op.split(',')[-1].strip() if ',' in op else ''

        # add [rbp-0x4], 0x40  → 内存归纳变量
        if '[' in dst:
            import re as _re
            m = _re.search(r'\[(rbp[+-]0x[0-9a-fA-F]+)\]', dst)
            if m:
                mem_target = m.group(1)
                stride = extract_constant(src)
                if stride is not None:
                    return (mem_target, stride, mem_target)
        else:
            # add reg, const → 寄存器归纳变量
            dst_reg = extract_register(dst)
            stride = extract_constant(src)
            if dst_reg and stride is not None:
                return (dst_reg, stride, None)

    return (None, None, None)
