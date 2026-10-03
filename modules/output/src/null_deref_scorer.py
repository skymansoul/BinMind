"""
空指针解引用利用性评分 — 用户态×内核态×读写×偏移×缓解措施。

问题定义:
  空指针解引用被统一报告，但利用性差异极大:
    - 用户态 + mmap_min_addr > 0 → 几乎不可利用 (无法映射 NULL 页)
    - 内核态 + 无 SMAP → 可映射 NULL 页 → 提权
    - 读 vs 写 → 读=信息泄露, 写=控制流劫持
    - 偏移 > 0 → 解引用 NULL+X → 可能落在已映射区域


关键缓解:
  - mmap_min_addr: Linux 禁止用户态映射低于此地址 (默认 65536)
  - SMAP (Supervisor Mode Access Prevention): 内核不能访问用户页
  - SMEP (Supervisor Mode Execution Prevention): 内核不能执行用户页代码
  - UMP (User Mode Prevention): ARM 等价于 SMAP
  - KPTI: 内核页表隔离 → 用户页在内核态不可访问

  CWE-476: NULL Pointer Dereference
  Linux mmap_min_addr (默认 65536) / vm.mmap_min_addr
  SMAP/SMEP (x86) / PAN (ARM) 缓解措施

修改记录:
  2025-05-12 14:16 - 初始版本，用户/内核×读写×偏移×缓解矩阵
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class DerefMode(Enum):
    USER_READ = "user_read"         # 用户态读 NULL
    USER_WRITE = "user_write"       # 用户态写 NULL
    KERNEL_READ = "kernel_read"     # 内核态读 NULL
    KERNEL_WRITE = "kernel_write"   # 内核态写 NULL
    UNKNOWN = "unknown"

# 缓解措施 → 惩罚分 (从基准中减去)
_MITIGATION_PENALTY: Dict[str, float] = {
    'mmap_min_addr': 6.0,   # 用户态 NULL 映射禁用 → 大幅降分
    'SMAP': 4.0,            # 内核不能访问用户空间
    'SMEP': 3.0,            # 内核不能执行用户空间代码
    'KPTI': 2.0,            # 页表隔离 → 额外屏障
    'PAN': 4.0,             # ARM Privileged Access Never
    'UMP': 4.0,             # ARM User Mode Prevention
    'ACL': 2.0,             # ARM Access Control Lists
    'guard_page': 3.0,      # NULL 页周围有 guard page
}

@dataclass
class NullDerefScore:
    """空指针解引用利用性评分。"""
    deref_mode: DerefMode
    offset_from_null: int          # 解引用偏移 (NULL + offset)
    is_read: bool
    exploitability: float          # 0-10
    active_mitigations: List[str] = field(default_factory=list)
    primitives_possible: List[str] = field(default_factory=list)
    escalation: str = ''

def _classify_mode(is_kernel: bool, is_write: bool) -> DerefMode:
    if is_kernel:
        return DerefMode.KERNEL_WRITE if is_write else DerefMode.KERNEL_READ
    return DerefMode.USER_WRITE if is_write else DerefMode.USER_READ

def _base_exploitability(mode: DerefMode, offset: int) -> float:
    """
    模式+偏移 → 基准可利用性。

    偏移 0 → 标准 NULL deref。
    偏移 > 0 但 < 4096 → 可能落在其他映射中 → 提高可利用性。
    偏移 >= 4096 → 几乎肯定不是真正的 NULL deref → 降分。
    """
    base_map = {
        DerefMode.USER_READ:   3.0,
        DerefMode.USER_WRITE:  5.0,
        DerefMode.KERNEL_READ: 6.0,
        DerefMode.KERNEL_WRITE: 9.0,  # 内核写 NULL → 最危险
        DerefMode.UNKNOWN:     2.0,
    }
    base = base_map.get(mode, 2.0)

    if 0 < offset < 4096:
        base += 2.0  # 偏移可能落在可控区域
    elif offset >= 4096:
        base -= 2.0  # 大概率不是真正的 NULL deref

    return base

def score_null_deref(
    is_kernel: bool = False,
    is_write: bool = True,
    offset_from_null: int = 0,
    has_mmap_min_addr: bool = True,
    has_smap: bool = False,
    has_smep: bool = False,
    has_kpti: bool = False,
    has_pan: bool = False,
    additional_mitigations: Optional[List[str]] = None,
) -> NullDerefScore:
    """
    评估空指针解引用的利用性。

    用户态 + mmap_min_addr → 几乎不可利用 (无法映射 NULL)。
    内核态 + 无 SMAP → 可能映射 NULL 页 → 提权。
    """
    mode = _classify_mode(is_kernel, is_write)
    base = _base_exploitability(mode, offset_from_null)

    # 收集活动缓解措施
    mitigations = []
    if is_kernel:
        if has_smap: mitigations.append('SMAP')
        if has_smep: mitigations.append('SMEP')
        if has_kpti: mitigations.append('KPTI')
        if has_pan: mitigations.append('PAN')
    else:
        if has_mmap_min_addr: mitigations.append('mmap_min_addr')

    if additional_mitigations:
        mitigations.extend(additional_mitigations)

    # 减去缓解惩罚
    total_penalty = sum(_MITIGATION_PENALTY.get(m, 0.0) for m in mitigations)
    exploitability = round(max(0.0, min(10.0, base - total_penalty)), 1)

    # 可用原语
    prims = []
    if exploitability >= 6.0:
        if is_write and is_kernel:
            prims.append('kernel_arbitrary_write')
            prims.append('privilege_escalation')
        elif is_write:
            prims.append('user_controlled_write')
        elif is_kernel:
            prims.append('kernel_info_leak')

    # 利用路径
    if exploitability >= 7.0:
        esc = ('直接利用: 映射 NULL 页 + 放置 shellcode/ROP chain → '
               '触发解引用 → 代码执行/提权')
    elif exploitability >= 4.0:
        esc = ('部分利用: 需要额外信息泄露来确定 NULL+offset 的映射状态。'
               '考虑 heap spray 或 mmap 布局操控')
    elif exploitability >= 1.0:
        esc = '难利用: 存在多重缓解措施。可能需要绕过 SMAP/SMEP 或竞争窗口'
    else:
        esc = '不可利用: 缓解措施组合完全阻止 NULL 页映射和访问'

    return NullDerefScore(
        deref_mode=mode,
        offset_from_null=offset_from_null,
        is_read=not is_write,
        exploitability=exploitability,
        active_mitigations=mitigations,
        primitives_possible=prims,
        escalation=esc,
    )
