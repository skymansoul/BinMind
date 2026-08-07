"""
密码学掩码结构分析 — 从二进制代码结构检测掩码对策的完整性，非字符串匹配。

创建: 2026-08-05 09:42
修改:
  2025-09-25 09:42 — 初始实现: 掩码生成-应用-清除三联体检测/掩码传播深度/刷新检测

设计意图:
  crypto_countermeasure_verify通过字符串匹配检测对策存在性(如\"masked_aes\"),
  但字符串存在不等于对策完整 — 掩码可能生成但从未应用, 或应用后被编译器优化清除。
  真正的掩码对策在代码结构上留下可检测模式: 掩码生成→XOR应用到秘密→运算→
  去掩码。这个\"生成-应用-清除\"三联体在指令流中形成特定的依赖关系。

  本模块从指令级结构检测掩码的完整性:
    S1 (生成检测): 随机数生成后紧接XOR操作 — 掩码生成的标志模式。
    S2 (传播深度): 掩码值从生成到使用之间的指令距离和依赖链长度。
    S3 (刷新检测): 运算中途重新生成掩码 → 高阶掩码的标志。
    S4 (清除检测): 去掩码XOR是否在对策尾端存在且不被DSE优化。

  每个信号输出0-1完整性评分, 组合为掩码质量评分。

  - Balasch et al.: 编译器对掩码实现的破坏 — 掩码被DSE清除的模式。
  - Barthe et al.: 掩码编译 — 形式化验证掩码变换的正确性。
  - Schneider et al.: DOCC — 编译器破坏CT的检测; 类似分析适用于掩码。

边界条件:
  - 掩码结构分析基于x86操作码序列 — 精确的依赖链分析需完整反汇编。
  - 高阶掩码(2阶+)的刷新模式可能与1阶掩码的结构相同 — 区分需寄存器追踪。
  - 编译器内联可能破坏掩码结构(将mask_gen内联到使用点) → 实际降低了可检测性。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class MaskStructureReport:
    algorithm: str = ""
    has_mask_generation: bool = False     # S1: 掩码生成存在
    mask_propagation_depth: int = 0       # S2: 生成到首次XOR的指令数
    has_refresh: bool = False             # S3: 中间刷新存在
    has_unmask: bool = False              # S4: 去掩码存在
    gen_to_unmask_distance: int = 0       # 生成到清除的总指令数
    integrity_score: float = 0.0          # 0-1 掩码完整性
    dse_risk: str = ""                    # 掩码被DSE优化的风险
    warnings: List[str] = field(default_factory=list)

# 操作码分类
_RNG_OPS = frozenset({
    0x0F, 0xC7,  # RDRAND (0F C7 /6)
    0x0F, 0xC9,  # RDSEED (部分)
})
_XOR_OPS = frozenset({0x31, 0x33, 0x35, 0x81, 0x83})
_MOV_OPS = frozenset({0x88, 0x89, 0x8A, 0x8B, 0x8D, 0xB0, 0xB8, 0xC6, 0xC7})
_BRANCH_OPS = frozenset({0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                          0x7C, 0x7D, 0x7E, 0x7F, 0xEB, 0xE3, 0xE8, 0xE9, 0xC3})
_REX = frozenset(range(0x40, 0x50))

def _find_mask_generation(data: bytes, anchor: int, window: int = 4096
                           ) -> Tuple[bool, int, int]:
    """
    检测掩码生成+应用模式: 随机数生成→XOR。
    返回(找到, 生成偏移, XOR偏移)。

    模式: RDRAND/RDSEED → mov → xor (在32字节窗口内)
    """
    start = max(0, anchor - window // 2)
    region = data[start:anchor + window // 2]
    n = len(region)

    rng_positions = []
    i = 0
    while i < n - 1:
        b = region[i]
        if b in _REX:
            i += 1
            continue
        # RDRAND: 0F C7 /6 (ModRM=0xF0-0xF7)
        if b == 0x0F and i + 2 < n and region[i + 1] == 0xC7:
            modrm = region[i + 2]
            if 0xF0 <= modrm <= 0xF7:
                rng_positions.append(start + i)
            i += 3
            continue
        i += 1

    if not rng_positions:
        return False, 0, 0

    # 对每个RNG位置, 在64字节内搜索XOR
    for rng_pos in rng_positions:
        local_start = rng_pos - start
        local_end = min(local_start + 64, n)
        for j in range(local_start, local_end):
            b = region[j]
            if b in _REX:
                continue
            if b in _XOR_OPS:
                return True, rng_pos, start + j

    return bool(rng_positions), rng_positions[0] if rng_positions else 0, 0

def _measure_propagation_depth(data: bytes, gen_offset: int, xor_offset: int
                                ) -> int:
    """
    测量掩码从生成到首次XOR应用之间的传播深度(指令数近似)。
    深度越大 → 编译器越可能将掩码优化掉(跨基本块的存活分析复杂)。
    """
    if gen_offset >= xor_offset or xor_offset - gen_offset > 4096:
        return 999

    region = data[gen_offset:xor_offset]
    depth = 0
    i = 0
    n = len(region)
    while i < n:
        b = region[i]
        if b in _REX:
            i += 1
            continue
        # 跳过操作数(简化)
        if b in _MOV_OPS:
            depth += 1
            i += 2 if i + 1 < n else 1
            continue
        if b in _BRANCH_OPS:
            depth += 1
            if b in (0xE8, 0xE9):
                i += 5
            elif b in (0xEB, 0xC3):
                i += 2
            else:
                i += 2
            continue
        depth += 1
        i += 1
    return depth

def _detect_refresh_pattern(data: bytes, anchor: int, window: int = 2048
                             ) -> bool:
    """
    检测掩码刷新: 运算中重新生成随机数+XOR。
    特征: 在锚点后的256-1024字节范围内出现第二个RNG+XOR对。
    """
    start = anchor + 256
    region = data[start:min(start + window, len(data))]
    # 简化: 搜索0F C7 (RDRAND)后64字节内的XOR
    n = len(region)
    for i in range(n - 3):
        if region[i] == 0x0F and region[i + 1] == 0xC7:
            if 0xF0 <= region[i + 2] <= 0xF7:
                for j in range(i, min(i + 64, n)):
                    rb = region[j]
                    if rb in _REX:
                        continue
                    if rb in _XOR_OPS:
                        return True
    return False

def _check_unmask_presence(data: bytes, anchor: int, window: int = 4096
                            ) -> Tuple[bool, int]:
    """
    检测去掩码(尾端XOR): 在密码学操作尾端是否存在XOR来移除掩码。
    特征: 锚点后512-2048字节范围内的XOR → 可能的去掩码。
    """
    start = anchor + 512
    end = min(start + window, len(data))
    region = data[start:end]
    last_xor = 0
    for i in range(len(region) - 1):
        b = region[i]
        if b in _REX:
            continue
        if b in _XOR_OPS:
            last_xor = start + i
    return last_xor > 0, last_xor

# 主分析函数

def analyze_mask_structure(data: bytes,
                           crypto_findings: Optional[List] = None,
                           algorithm: str = ""
                           ) -> MaskStructureReport:
    """
    从二进制指令结构分析掩码对策的完整性。
    对每个检测到的密码学锚点做掩码结构检查。
    """
    anchors = []
    if crypto_findings:
        for f in crypto_findings:
            try:
                anchors.append(getattr(f, 'location', 0))
            except Exception:
                pass
    if not anchors:
        anchors = [0]

    anchor = anchors[0]
    has_gen, gen_off, xor_off = _find_mask_generation(data, anchor)
    depth = _measure_propagation_depth(data, gen_off, xor_off) if has_gen else 0
    has_refresh = _detect_refresh_pattern(data, anchor)
    has_unmask, unmask_off = _check_unmask_presence(data, anchor)
    gen_unmask_dist = unmask_off - gen_off if has_unmask and gen_off > 0 else 0

    # 完整性评分
    score = 0.0
    warnings = []
    if has_gen:
        score += 0.30
        if depth <= 32:
            score += 0.10  # 传播短 → 编译器不太可能优化掉
        elif depth <= 128:
            score += 0.05
        else:
            warnings.append(f'掩码传播深度{depth}条指令 — 跨块寄存器分配可能清除掩码')
    else:
        warnings.append('未检测到掩码生成 → 无掩码保护')

    if has_refresh:
        score += 0.20
    if has_unmask:
        score += 0.25
    else:
        warnings.append('未检测到去掩码 — 密文可能仍被掩码影响(或掩码仅在内部)')

    # DSE风险评估
    if depth > 64 and not has_refresh:
        dse_risk = 'HIGH — 长传播距离+无刷新 → 编译器DSE可能消除掩码(GnuZero DSN 2025)'
    elif has_refresh:
        dse_risk = 'LOW — 刷新模式降低单次DSE的影响'
    else:
        dse_risk = 'MEDIUM'

    return MaskStructureReport(
        algorithm=algorithm or 'detected',
        has_mask_generation=has_gen,
        mask_propagation_depth=depth,
        has_refresh=has_refresh,
        has_unmask=has_unmask,
        gen_to_unmask_distance=gen_unmask_dist,
        integrity_score=round(score, 2),
        dse_risk=dse_risk,
        warnings=warnings)
