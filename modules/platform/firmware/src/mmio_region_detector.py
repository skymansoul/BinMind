# 增加 MMIO 别名检测（同一物理外设映射多个虚拟地址区间）
# TODO: 当前仅处理 ARM Cortex-M 的 PPB 与 AHB/APB 总线，RISC-V MMIO 布局待补

# MMIO 区域检测器 — 固件二进制中自动识别内存映射 IO 区域。
#
# 固件（尤其裸机程序）通过 MMIO 与硬件外设交互，向固定地址
# 写入特定值配置外设、读取状态寄存器获取设备状态。这些 MMIO
# 地址在固件中以立即数常量形式存在。
#
# 静态分析时识别 MMIO 区域的意义：
#   (a) 区分"普通内存访问"与"外设控制操作"，后者可能影响安全
#       （如禁用看门狗、修改 MPU 配置）
#   (b) 为符号执行提供"不对这些地址符号化"的提示
#   (c) 识别外设寄存器读写模式，推断外设类型与固件功能
#
# 检测策略（启发式，不依赖芯片手册）：
#   1. 立即数频率分析：统计 LDR/STR 目标地址立即数，
#      落入已知外设总线范围（0x40000000-0x5FFFFFFF AHB/APB）
#      按频率排序，高频访问更可能是外设寄存器
#   2. 对齐模式：外设寄存器通常 4 字节对齐，访问宽度固定
#      （如始终 32-bit LDR/STR，偶有 8-bit LDRB/STRB）
#   3. 位操作模式：外设配置通常涉及 ORR/BIC（置位/清零），
#      对同一地址反复 ORR 不同立即数，是配置寄存器的强信号

import re
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, Counter


# 常见外设总线基址范围 — ARM Cortex-M 系列
_MMIO_RANGES = [
    (0x40000000, 0x5FFFFFFF),  # AHB/APB 外设总线
    (0xE0000000, 0xE00FFFFF),  # Cortex-M PPB（系统控制块/NVIC/MPU）
    (0x20000000, 0x3FFFFFFF),  # SRAM（非 MMIO，常与外设毗邻，用于对比）
]

# 位操作助记符 — 对这些指令的目标地址重点跟踪
_BIT_MANIP_MNEMS = {'orr', 'bic', 'and', 'eor', 'orn',
                     'bfi', 'bfc', 'ubfx', 'sbfx'}


def _is_in_mmio_range(addr: int) -> Tuple[bool, str]:
    """判断地址是否落入已知外设总线范围。"""
    for base, top in _MMIO_RANGES:
        if base <= addr <= top:
            return True, f"{hex(base)}-{hex(top)}"
    return False, ''


def detect_mmio_regions(disasm_lines: List[str]) -> Dict[int, Dict]:
    """从反汇编行中检测并分类 MMIO 区域。

    返回: {address → {access_count, bit_manip_count, alignment, region_type}}
    仅包含判定为疑似 MMIO 访问的地址。
    """
    addr_access_count: Counter = Counter()
    addr_bit_manip: Counter = Counter()
    addr_widths: Dict[int, Set[int]] = defaultdict(set)

    # 匹配 LDR/STR 直接寻址与字面量池加载
    load_store_re = re.compile(
        r'(ldr|str|ldrb|strb|ldrh|strh|ldrd|strd)\s+\w+,\s*\[[\w\s,+#\-]+\]',
        re.IGNORECASE)
    literal_pool_re = re.compile(
        r'(ldr|str)\s+\w+,\s*=(0x[0-9a-fA-F]+)',
        re.IGNORECASE)

    for line in disasm_lines:
        # 直接寻址
        m = load_store_re.search(line)
        if m:
            mnem = m.group(1).lower()
            # 确定访问宽度
            if mnem in ('ldrb', 'strb'):
                width = 1
            elif mnem in ('ldrh', 'strh'):
                width = 2
            elif mnem in ('ldrd', 'strd'):
                width = 8
            else:
                width = 4

            # 提取行中所有 hex 立即数（保守处理）
            hex_addrs = re.findall(r'0x([0-9a-fA-F]{7,8})', line)
            for ha in hex_addrs:
                addr = int(ha, 16)
                in_range, _ = _is_in_mmio_range(addr)
                if in_range:
                    addr_access_count[addr] += 1
                    addr_widths[addr].add(width)

        # 字面量池加载
        m = literal_pool_re.search(line)
        if m:
            addr = int(m.group(2), 16)
            in_range, _ = _is_in_mmio_range(addr)
            if in_range:
                addr_access_count[addr] += 1

        # 位操作 — 外设配置常见模式
        mnem_line = line.strip().split(None, 1)
        if mnem_line and mnem_line[0].lower() in _BIT_MANIP_MNEMS:
            hex_addrs = re.findall(r'0x([0-9a-fA-F]{7,8})', line)
            for ha in hex_addrs:
                addr = int(ha, 16)
                in_range, _ = _is_in_mmio_range(addr)
                if in_range:
                    addr_bit_manip[addr] += 1

    # 汇总结果
    result: Dict[int, Dict] = {}
    for addr, count in addr_access_count.most_common():
        _, region = _is_in_mmio_range(addr)
        widths = addr_widths.get(addr, set())
        bit_ops = addr_bit_manip.get(addr, 0)

        # 对齐检查 — 外设寄存器几乎总是 4 字节对齐
        alignment_ok = (addr % 4 == 0)

        result[addr] = {
            'access_count': count,
            'bit_manip_count': bit_ops,
            'access_widths': sorted(widths),
            'alignment_ok': alignment_ok,
            'region': region,
            # 置信度: 高频 + 对齐 + 位操作 → high
            'confidence': ('high' if count >= 5 and alignment_ok and bit_ops > 0
                          else 'medium' if count >= 3
                          else 'low'),
        }

    return result
