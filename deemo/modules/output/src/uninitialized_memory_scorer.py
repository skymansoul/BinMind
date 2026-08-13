"""
未初始化内存影响评分 — 栈×堆×残存数据类型×流向敏感操作。

问题定义:
  未初始化内存漏洞 (CWE-457/CWE-908) 被报告为统一类别。
  实际影响差异极大:
    - 栈未初始化 → 残存上层函数帧的局部变量 (可能含指针/密钥)
    - 堆未初始化 → 残存前一个 chunk 的元数据或数据
    - 残存值流向比较操作 → 仅信息泄露
    - 残存值流向指针解引用 → 代码执行
    - 残存值流向大小参数 → 内存破坏

  本模块提供第一个未初始化内存影响的量化评分模型。

  CWE-457: Use of Uninitialized Variable
  CWE-908: Use of Uninitialized Resource
  Lu et al.: UniSan — 未初始化内存检测, 不评分影响.
  无现有量化工具.

修改记录:
  2025-05-12 09:42 - 初始版本，残存类型推断×下游影响
"""

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Tuple

class MemoryRegion(Enum):
    STACK = "stack"          # 栈上未初始化局部变量
    HEAP = "heap"            # malloc 返回后未初始化
    BSS = "bss"              # .bss 段 (静态未初始化)
    MMAP = "mmap"            # mmap 映射区域

class ResidualType(Enum):
    POINTER = "pointer"          # 残存地址值 — 最高危
    INTEGER = "integer"          # 残存整数 — 中等
    KEY_MATERIAL = "key"         # 残存密钥/令牌 — 高危 (机密性)
    CHUNK_METADATA = "chunk_metadata"  # 残存堆元数据 — 堆布局泄露
    STRING = "string"            # 残存字符串 — 低危
    ZERO = "zero"                # 残存零值 — 不可利用 (某些 OS 零初始化)
    UNKNOWN = "unknown"

class DownstreamUse(IntEnum):
    COMPARISON = 1     # 仅用于比较/分支
    ARITHMETIC = 2     # 用于算术运算
    INDEX = 3          # 用作数组索引
    SIZE = 4           # 用作大小参数 (malloc/memcpy)
    POINTER_DEREF = 5  # 用作指针解引用
    BRANCH = 6         # 影响控制流分支

# 残存类型 × 下游使用 → 影响分 (0-10)
_IMPACT_MATRIX: Dict[ResidualType, Dict[DownstreamUse, float]] = {
    ResidualType.POINTER: {
        DownstreamUse.POINTER_DEREF: 9.5,  # 残存指针+解引用 → 代码执行
        DownstreamUse.INDEX:         7.0,  # 残存指针作索引 → 越界访问
        DownstreamUse.SIZE:          6.5,
        DownstreamUse.BRANCH:        5.0,
        DownstreamUse.COMPARISON:    3.0,
    },
    ResidualType.KEY_MATERIAL: {
        DownstreamUse.COMPARISON:    8.0,  # 密钥泄露
        DownstreamUse.ARITHMETIC:    6.0,
        DownstreamUse.POINTER_DEREF: 4.0,
    },
    ResidualType.CHUNK_METADATA: {
        DownstreamUse.POINTER_DEREF: 7.5,  # 堆元数据→地址泄露+写原语
        DownstreamUse.SIZE:          8.0,  # 残留 size→精确分配控制
        DownstreamUse.INDEX:         5.0,
    },
    ResidualType.INTEGER: {
        DownstreamUse.INDEX:         5.0,
        DownstreamUse.SIZE:          7.0,
        DownstreamUse.BRANCH:        4.0,
        DownstreamUse.COMPARISON:    2.0,
    },
    ResidualType.STRING: {
        DownstreamUse.COMPARISON:    4.0,  # 信息泄露
    },
}
_DEFAULT_IMPACT = {d: 1.5 for d in DownstreamUse}

@dataclass
class UninitMemoryScore:
    """未初始化内存影响评分。"""
    memory_region: MemoryRegion
    residual_type: ResidualType
    downstream_use: DownstreamUse
    impact_score: float            # 0-10
    confidentiality_impact: bool   # 信息泄露
    integrity_impact: bool         # 内存破坏
    availability_impact: bool      # DoS
    primitives: List[str] = field(default_factory=list)

def _infer_residual(
    region: MemoryRegion,
    function_context: str = '',
    variable_name: str = '',
    variable_size: int = 8,
) -> ResidualType:
    ctx = function_context.lower()
    vname = variable_name.lower()

    # 变量名暗示类型
    if any(kw in vname for kw in ('ptr', 'buf', 'addr', 'ref', 'handle')):
        return ResidualType.POINTER
    if any(kw in vname for kw in ('key', 'secret', 'token', 'pass',
           'cred', 'nonce', 'iv')):
        return ResidualType.KEY_MATERIAL
    if any(kw in vname for kw in ('size', 'len', 'count', 'index',
           'offset', 'n', 'num')):
        return ResidualType.INTEGER
    if any(kw in vname for kw in ('name', 'str', 'msg', 'path',
           'file', 'url')):
        return ResidualType.STRING

    # 区域推断
    if region == MemoryRegion.HEAP:
        return ResidualType.CHUNK_METADATA
    if region == MemoryRegion.STACK:
        # 栈上 8 字节变量 → 大概率是指针
        return ResidualType.POINTER if variable_size >= 8 else ResidualType.INTEGER
    if region == MemoryRegion.BSS:
        return ResidualType.ZERO  # OS loader 通常零初始化 BSS

    return ResidualType.UNKNOWN

def _infer_downstream(
    function_callees: Optional[List[str]] = None,
    context: str = '',
) -> DownstreamUse:
    callees_lower = [c.lower() for c in (function_callees or [])]
    ctx = context.lower()

    if any(kw in callees_lower or kw in ctx for kw in
           ('memcpy', 'memmove', 'malloc', 'calloc', 'realloc')):
        return DownstreamUse.SIZE
    if any(kw in callees_lower or kw in ctx for kw in
           ('array', 'index', '[]', 'offset')):
        return DownstreamUse.INDEX
    if any(kw in ctx for kw in ('*', '->', 'deref', 'load', 'store')):
        return DownstreamUse.POINTER_DEREF
    if any(kw in ctx for kw in ('if', 'switch', 'goto', 'jmp', 'branch')):
        return DownstreamUse.BRANCH
    if any(kw in callees_lower or kw in ctx for kw in
           ('strcmp', 'memcmp', 'compare', '==')):
        return DownstreamUse.COMPARISON

    return DownstreamUse.ARITHMETIC  # 默认假设

def score_uninitialized_memory(
    memory_region: str = 'stack',
    variable_name: str = '',
    variable_size: int = 8,
    function_context: str = '',
    function_callees: Optional[List[str]] = None,
) -> UninitMemoryScore:
    """
    评估未初始化内存漏洞的影响。

    memory_region: stack / heap / bss / mmap
    """
    region = MemoryRegion(memory_region.lower()) if memory_region.lower() in (
        'stack', 'heap', 'bss', 'mmap') else MemoryRegion.STACK

    residual = _infer_residual(region, function_context, variable_name, variable_size)
    downstream = _infer_downstream(function_callees, function_context)

    matrix_row = _IMPACT_MATRIX.get(residual, _DEFAULT_IMPACT)
    impact = matrix_row.get(downstream, 1.5)

    # 堆 + 指针残存 → 额外提升 (堆布局可预测)
    if region == MemoryRegion.HEAP and residual == ResidualType.POINTER:
        impact = min(impact + 1.0, 10.0)
    # BSS + zero → 极低
    if region == MemoryRegion.BSS and residual == ResidualType.ZERO:
        impact = 0.0

    impact = round(min(10.0, max(0.0, impact)), 1)

    prims = []
    if residual == ResidualType.POINTER and downstream in (DownstreamUse.POINTER_DEREF,
                                                             DownstreamUse.SIZE):
        prims.append('arbitrary_access')
    if residual == ResidualType.KEY_MATERIAL:
        prims.append('sensitive_data_leak')
    if residual == ResidualType.CHUNK_METADATA:
        prims.append('heap_layout_disclosure')

    return UninitMemoryScore(
        memory_region=region,
        residual_type=residual,
        downstream_use=downstream,
        impact_score=impact,
        confidentiality_impact=residual in (ResidualType.KEY_MATERIAL, ResidualType.STRING),
        integrity_impact=downstream in (DownstreamUse.SIZE, DownstreamUse.POINTER_DEREF,
                                         DownstreamUse.INDEX),
        availability_impact=downstream in (DownstreamUse.SIZE, DownstreamUse.BRANCH),
        primitives=prims,
    )
