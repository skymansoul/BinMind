"""
信息泄露比特量化 — 泄露基址→有效ASLR熵损→暴力破解窗口。

问题定义:
  漏洞报告输出 "存在信息泄露" 但不说泄露了多少有效信息。
  不是所有泄露等价: 泄露代码指针 (28 bits ASLR) >> 泄露堆指针
  (~13 bits macOS) >> 泄露零值 (0 bits)。CCS 2024 建立了 Correlation
  Entropy 框架但未提供集成到二进制分析报告的工具。

  本模块从泄露数据类型+偏移推断泄露的有效比特数:
    - 代码指针 (.text/.plt) → 取决于 PIE 状态和 OS
    - 栈指针 → ~28 bits (Linux), ~13 bits (macOS)
    - 堆指针 → ~28 bits (Linux), ~12 bits (macOS)
    - 库指针 → 取决于 Linux folio 退化 (19 vs 29 bits)
    - 数据值 → 取决于值域和分布

  输出: N bits leaked → 暴力破解可行时间 → 利用链可行性。

  Binosi et al.: Correlation Entropy 框架
  ASLR entropy baseline: 本项目的 aslr_entropy.py

修改记录:
  2024-09-02 14:51 - 初始版本，四类泄露源的有效比特映射
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

class LeakType(Enum):
    CODE_PTR = "code_pointer"       # .text / .plt 中的地址
    STACK_PTR = "stack_pointer"     # 栈上的地址
    HEAP_PTR = "heap_pointer"       # brk/mmap 返回的地址
    LIB_PTR = "library_pointer"     # 共享库 (.so/.dylib/.dll) 地址
    DATA_VALUE = "data_value"       # 非指针数据 (密钥/token/结构体)
    UNKNOWN = "unknown"

# 指针类型 → OS → 有效比特
_EFFECTIVE_BITS: Dict[LeakType, Dict[str, float]] = {
    LeakType.CODE_PTR: {
        'linux': 28.8, 'linux_5.18+': 28.8, 'linux_hardened': 32.0,
        'windows': 19.0, 'macos': 14.0, 'macos_arm': 13.0,
    },
    LeakType.STACK_PTR: {
        'linux': 28.8, 'linux_5.18+': 28.8, 'linux_hardened': 40.0,
        'windows': 31.0, 'macos': 13.0, 'macos_arm': 12.0,
    },
    LeakType.HEAP_PTR: {
        'linux': 28.8, 'linux_5.18+': 28.8, 'linux_hardened': 40.0,
        'windows': 31.0, 'macos': 13.0, 'macos_arm': 12.0,
    },
    LeakType.LIB_PTR: {
        'linux': 28.8, 'linux_5.18+': 19.0, 'linux_hardened': 33.0,
        'windows': 19.0, 'macos': 14.0, 'macos_arm': 13.0,
    },
    LeakType.DATA_VALUE: {
        'linux': 0.0, 'linux_5.18+': 0.0, 'linux_hardened': 0.0,
        'windows': 0.0, 'macos': 0.0, 'macos_arm': 0.0,
    },
    LeakType.UNKNOWN: {
        'linux': 14.0, 'linux_5.18+': 14.0, 'linux_hardened': 16.0,
        'windows': 10.0, 'macos': 7.0, 'macos_arm': 6.0,
    },
}

# 暴力破解速率假设 (tries/sec)
_DEFAULT_TPS = 300

@dataclass
class LeakQuantification:
    """信息泄露比特量化结果。"""
    leak_type: LeakType
    bits_disclosed: float           # 有效泄露比特数
    brute_force_time_seconds: float # 暴力破解期望时间
    correlation_danger: str         # none / low / medium / critical
    aslr_degradation: float         # OS 基线 ASLR 的退化百分比
    exploit_chain_value: str = ''   # 该泄露对利用链的价值

def _classify_leak(
    leak_description: str,
    leak_address_type: str = '',
    struct_field_name: str = '',
) -> LeakType:
    """从描述和地址类型推断泄露类型。"""
    combined = (leak_description + ' ' + leak_address_type + ' ' +
               struct_field_name).lower()

    if any(kw in combined for kw in ('code', 'text', 'function',
           'entry', '.text', '.plt', 'got.plt')):
        return LeakType.CODE_PTR
    if any(kw in combined for kw in ('stack', 'rsp', 'esp', 'rbp', 'ebp',
           'return address', 'saved rip')):
        return LeakType.STACK_PTR
    if any(kw in combined for kw in ('heap', 'malloc', 'brk', 'mmap',
           'chunk', 'tcache', 'fastbin')):
        return LeakType.HEAP_PTR
    if any(kw in combined for kw in ('lib', 'so', 'dylib', 'dll',
           'shared library', '.so.', 'libc')):
        return LeakType.LIB_PTR
    if any(kw in combined for kw in ('key', 'token', 'password',
           'secret', 'credential', 'cookie', 'nonce')):
        return LeakType.DATA_VALUE

    return LeakType.UNKNOWN

def _bit_to_time(bits: float, tps: float = _DEFAULT_TPS) -> float:
    """有效比特 → 暴力破解期望时间 (秒)。"""
    if bits <= 0:
        return 0.0
    # 期望尝试次数 (with replacement / geometric)
    expected_tries = 2.0 ** bits
    return expected_tries / tps

def _time_to_label(seconds: float) -> str:
    if seconds <= 0:
        return 'instant'
    if seconds < 60:
        return f'{seconds:.0f}s'
    if seconds < 3600:
        return f'{seconds/60:.0f}min'
    if seconds < 86400:
        return f'{seconds/3600:.0f}hr'
    if seconds < 86400 * 30:
        return f'{seconds/86400:.0f}d'
    if seconds < 86400 * 365:
        return f'{seconds/86400/30:.0f}mo'
    return f'{seconds/86400/365:.0f}yr'

def quantify_leak(
    leak_description: str = '',
    leak_address_type: str = '',
    struct_field_name: str = '',
    os_profile: str = 'linux',
    is_pie: bool = True,
    leak_size_bytes: int = 8,
    tps: float = _DEFAULT_TPS,
) -> LeakQuantification:
    """
    量化单个信息泄露的有效比特数和利用价值。

    os_profile: aslr_entropy.py 的输出 (linux/linux_5.18+/windows/macos/...)
    """
    ltype = _classify_leak(leak_description, leak_address_type, struct_field_name)
    base_bits = _EFFECTIVE_BITS.get(ltype, {}).get(os_profile, 14.0)

    # 修正: 非PIE → 代码指针泄露 = 0 (地址固定已知)
    if ltype == LeakType.CODE_PTR and not is_pie:
        base_bits = 0.0

    # 修正: 部分泄露 (仅泄露低位/高位)
    if leak_size_bytes < 8:
        # 假设泄露的是低 N 字节 → 比特减少
        # 但 ASLR 的随机性主要在页内偏移以上 (bit 12+)
        bits_lost = max(0, (8 - leak_size_bytes) * 8)
        base_bits = max(0.0, base_bits - bits_lost)

    brute_time = _bit_to_time(base_bits, tps)

    # 关联危险度
    if base_bits >= 28:
        corr = 'critical' if ltype in (LeakType.CODE_PTR, LeakType.LIB_PTR) else 'high'
    elif base_bits >= 20:
        corr = 'medium'
    elif base_bits > 0:
        corr = 'low'
    else:
        corr = 'none'

    # 利用链价值
    if ltype in (LeakType.CODE_PTR, LeakType.LIB_PTR) and base_bits >= 20:
        value = '基础原语 — 可直接用于计算 ROP gadget 地址'
    elif ltype == LeakType.HEAP_PTR and base_bits >= 20:
        value = '堆布局原语 — 可计算堆对象位置，辅助 heap feng shui'
    elif ltype == LeakType.STACK_PTR and base_bits >= 20:
        value = '栈原语 — 可定位返回地址和栈变量'
    elif ltype == LeakType.DATA_VALUE:
        value = '数据泄露 — 非地址信息，利用价值取决于泄露的具体内容'
    else:
        value = '有限利用价值 — 泄露比特数不足以绕过 ASLR'

    return LeakQuantification(
        leak_type=ltype,
        bits_disclosed=round(base_bits, 1),
        brute_force_time_seconds=round(brute_time, 1),
        correlation_danger=corr,
        aslr_degradation=round(base_bits / 28.8 * 100, 1) if base_bits > 0 else 0.0,
        exploit_chain_value=value,
    )

def leak_summary(q: LeakQuantification) -> Dict[str, Any]:
    """泄露量化摘要。"""
    return {
        'leak_type': q.leak_type.value,
        'bits_disclosed': q.bits_disclosed,
        'brute_force_time': _time_to_label(q.brute_force_time_seconds),
        'correlation_danger': q.correlation_danger,
        'aslr_degradation_pct': q.aslr_degradation,
        'exploit_chain_value': q.exploit_chain_value,
    }
