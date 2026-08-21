# coding: utf-8
"""
Off-by-One 检测 L1-L3 — 检测 write == alloc_usable + 1 并验证利用链.

L1: 分配器感知大小比较 L2: 相邻 chunk 字段判定 (prev_size/size LSB/MSB)
L3: 已知 exploitation technique 匹配 (Null-byte poisoning / prev-size / size inflate)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class OBOField(Enum):
    """被溢出的字节覆盖的字段."""
    USER_DATA = auto()         # 下一 chunk 的用户数据 — 低风险
    PREV_SIZE = auto()          # 下一 chunk 的 prev_size — 低风险
    SIZE_FLAGS_LSB = auto()     # size 字段的最低字节 (含 flags) — 高危
    SIZE_FLAGS_MSB = auto()     # size 字段的高字节 — 高危
    UNKNOWN = auto()


class OBORisk(Enum):
    SAFE = auto()        # 无溢出
    LOW = auto()         # 溢出到用户数据
    MEDIUM = auto()      # 溢出到 prev_size
    HIGH = auto()        # 溢出到 size (MSB)
    CRITICAL = auto()    # 溢出到 size 含 Null-byte 写入


@dataclass
class OBOAnalysis:
    """单次 Off-by-One 分析结果."""
    alloc_addr: int
    alloc_request: int        # malloc(N) 中的 N
    alloc_usable: int         # glibc 实际可用大小
    write_size: int           # 实际写入大小
    is_off_by_one: bool       # 是否恰好多 1 字节
    overflow_field: OBOField   # 溢出的字节影响了哪个字段
    risk: OBORisk
    adjacent_chunk_size: int   # 相邻 chunk 的大小 (若已知)
    exploitability_reason: str


@dataclass
class ChunkLayout:
    """glibc chunk 布局模型."""
    prev_size: int            # 上一 chunk 的 size (若 PREV_INUSE=0)
    size: int                 # 当前 chunk size (含 flags)
    usable: int               # 用户可用大小
    has_prev_inuse: bool = True

    @staticmethod
    def compute_usable(request_size: int, alignment: int = 16,
                       min_chunk: int = 32, metadata: int = 16) -> int:
        """计算 glibc 分配器的用户可用大小."""
        eff = max(request_size + metadata, min_chunk)
        eff = ((eff + alignment - 1) // alignment) * alignment
        return eff - metadata

    @staticmethod
    def compute_chunk_size(request_size: int, alignment: int = 16,
                           min_chunk: int = 32) -> int:
        """计算 glibc 分配的实际 chunk size."""
        return max(request_size + 16, min_chunk)


def detect_off_by_one(
    alloc_size: int, write_size: int,
    alignment: int = 16, min_chunk: int = 32, metadata: int = 16,
    adjacent_alloc: Optional[int] = None,
) -> OBOAnalysis:
    """检测 off-by-one 溢出。

    参数: alloc_size malloc(N) 中的 N, write_size 实际写入大小,
    alignment 对齐 (默认 16), min_chunk 最小 chunk 大小
    (默认 32), metadata chunk 元数据开销 (默认 16 =
    prev_size+size), adjacent_alloc 相邻 chunk 的分配大小
    (若已知); 返回 OBOAnalysis 结果。
    """
    usable = ChunkLayout.compute_usable(alloc_size, alignment, min_chunk, metadata)

    # L1: 大小比较
    if write_size <= usable:
        return OBOAnalysis(
            alloc_addr=0, alloc_request=alloc_size,
            alloc_usable=usable, write_size=write_size,
            is_off_by_one=False, overflow_field=OBOField.USER_DATA,
            risk=OBORisk.SAFE, adjacent_chunk_size=adjacent_alloc or 0,
            exploitability_reason=f'write({write_size}) <= usable({usable})')

    if write_size > usable + 1:
        # 不是 off-by-one, 是常规堆溢出 — 委托给主 heap overflow 管线
        return OBOAnalysis(
            alloc_addr=0, alloc_request=alloc_size,
            alloc_usable=usable, write_size=write_size,
            is_off_by_one=False, overflow_field=OBOField.UNKNOWN,
            risk=OBORisk.CRITICAL,
            adjacent_chunk_size=adjacent_alloc or 0,
            exploitability_reason=(
                f'常规堆溢出: write({write_size}) > usable({usable})+1 → '
                f'越界 {write_size - usable} 字节'))

    # write == usable + 1 → off-by-one
    overflow_field = _determine_overflow_field(alloc_size, write_size,
                                                usable, adjacent_alloc)
    risk = _assess_obo_risk(overflow_field, write_size)

    return OBOAnalysis(
        alloc_addr=0, alloc_request=alloc_size,
        alloc_usable=usable, write_size=write_size,
        is_off_by_one=True, overflow_field=overflow_field,
        risk=risk, adjacent_chunk_size=adjacent_alloc or 0,
        exploitability_reason=_build_obo_reason(
            overflow_field, alloc_size, usable, adjacent_alloc))


def _determine_overflow_field(
    alloc_size: int, write_size: int, usable: int,
    adjacent_alloc: Optional[int],
) -> OBOField:
    """判定溢出字节影响了相邻 chunk 的哪个字段."""
    chunk_size = ChunkLayout.compute_chunk_size(alloc_size)

    if adjacent_alloc is None:
        # 无相邻信息 → 保守假设溢出到 size 字段
        return OBOField.SIZE_FLAGS_LSB

    adj_chunk_size = ChunkLayout.compute_chunk_size(adjacent_alloc)
    # 计算溢出字节在相邻 chunk 中的偏移
    overflow_offset = write_size - usable  # 通常是 1

    if overflow_offset <= 8:
        # 前 8 字节是相邻 chunk 的 prev_size
        return OBOField.PREV_SIZE
    elif overflow_offset <= 16:
        # 9-16 字节是相邻 chunk 的 size 字段 (8 字节 prev_size + 8 字节 size)
        if overflow_offset <= 9:
            return OBOField.SIZE_FLAGS_LSB  # 最低字节含 flags
        else:
            return OBOField.SIZE_FLAGS_MSB
    else:
        return OBOField.USER_DATA


def _assess_obo_risk(field: OBOField, write_size: int) -> OBORisk:
    """评估 off-by-one 的风险等级."""
    if field == OBOField.SIZE_FLAGS_LSB:
        # 覆盖 size 的 LSB (含 PREV_INUSE) → Null-byte poisoning 关键路径
        return OBORisk.CRITICAL
    elif field == OBOField.SIZE_FLAGS_MSB:
        return OBORisk.HIGH
    elif field == OBOField.PREV_SIZE:
        return OBORisk.MEDIUM
    elif field == OBOField.USER_DATA:
        return OBORisk.LOW
    return OBORisk.SAFE


def _build_obo_reason(field: OBOField, alloc_size: int,
                       usable: int, adjacent_alloc: Optional[int]) -> str:
    """构建人类可读解释."""
    reasons = {
        OBOField.SIZE_FLAGS_LSB: f'Null-byte poisoning: malloc({alloc_size})→usable={usable}, 溢出至相邻 chunk size LSB',
        OBOField.SIZE_FLAGS_MSB: f'Size inflation: malloc({alloc_size})→usable={usable}, 溢出至相邻 chunk size MSB',
        OBOField.PREV_SIZE: f'Prev-size 覆写: malloc({alloc_size})→usable={usable}',
        OBOField.USER_DATA: f'用户数据损坏: malloc({alloc_size})→usable={usable}',
        OBOField.UNKNOWN: '溢出字段未知',
    }
    base = reasons.get(field, 'Off-by-one 溢出')
    return f'{base}, adj={adjacent_alloc}' if adjacent_alloc else base


def batch_obo_filter(
    candidates: List[Dict], alignment: int = 16,
    min_chunk: int = 32, metadata: int = 16,
) -> Tuple[List[Dict], List[OBOAnalysis], Dict]:
    """批量 off-by-one 分析.

    过滤候选: 区分常规堆溢出和 off-by-one.
    """
    obo_results = []
    regular = []
    stats = {'total': len(candidates), 'safe': 0, 'off_by_one': 0,
             'regular_overflow': 0, 'critical_obo': 0}

    for c in candidates:
        alloc = c.get('alloc_size', c.get('alloc_request', 0))
        write = c.get('write_size', 0)

        analysis = detect_off_by_one(
            alloc, write, alignment, min_chunk, metadata)

        obo_results.append(analysis)

        if analysis.risk == OBORisk.SAFE:
            stats['safe'] += 1
        elif analysis.is_off_by_one:
            stats['off_by_one'] += 1
            if analysis.risk == OBORisk.CRITICAL:
                stats['critical_obo'] += 1
        else:
            stats['regular_overflow'] += 1
            regular.append(c)

    return regular, obo_results, stats


# L3: 利用链验证

def verify_exploit_chain(analysis: OBOAnalysis,
                          overwrite_byte_value: int = 0,
                          heap_layout_known: bool = False,
                          ) -> Tuple[bool, str, float]:
    """L3: 检查 off-by-one 是否可触发已知 exploitation technique."""
    if not analysis.is_off_by_one:
        return False, '无 off-by-one 溢出', 0.0

    techs = [
        ('Null-byte poisoning', 0.90,
         analysis.overflow_field == OBOField.SIZE_FLAGS_LSB
         and analysis.alloc_request <= 0x100,
         'CRITICAL — PREV_INUSE 翻转 → unlink → 任意写'),
        ('Prev-size poisoning', 0.70,
         analysis.overflow_field == OBOField.PREV_SIZE
         and analysis.adjacent_chunk_size > 0,
         'MEDIUM — 可能触发错误的 chunk 合并'),
        ('Size field inflation', 0.80,
         analysis.overflow_field == OBOField.SIZE_FLAGS_MSB,
         'HIGH — size 扩大 → 相邻 chunk 重叠 → 任意读写'),
        ('User data corruption', 0.30,
         analysis.overflow_field == OBOField.USER_DATA,
         'LOW — 仅损坏用户数据, 不可直接利用'),
    ]
    for name, conf, cond, impact in techs:
        if cond:
            if 'null' in name.lower() and overwrite_byte_value == 0:
                conf += 0.05
            if heap_layout_known:
                conf += 0.05
            return True, f'{name}: {impact}', min(conf, 0.99)
    return False, '无匹配的 exploitation technique', 0.0


def batch_verify_exploit_chain(
    obo_results: List[OBOAnalysis],
    overwrite_values: Dict[int, int] = None,
    heap_layout: bool = False,
) -> List[Dict]:
    """批量 L3 利用链验证."""
    if overwrite_values is None:
        overwrite_values = {}
    return [{
        'index': i, 'is_off_by_one': a.is_off_by_one,
        'risk': a.risk.name,
        'exploitable': (v := verify_exploit_chain(a, overwrite_values.get(i, 0), heap_layout))[0],
        'technique': v[1], 'confidence': round(v[2], 4),
    } for i, a in enumerate(obo_results)]


def demonstrate_null_byte_poisoning() -> Dict:
    """演示经典 Null-byte poisoning 场景.

    glibc < 2.26 中 off-by-one null 可导致:
    1. 分配 A (0x20), B (0x100), C (0x20)
    2. 溢出 A 的 null 字节覆写 B 的 size 从 0x111→0x100
    3. free(B) 时 glibc 认为 B 的大小为 0x100 (实际 0x111)
    4. 分配 0xf0 字节可得到 B 的内存 (仍在 C 使用中)
    5. 重叠分配 → 任意写
    """
    return {
        'technique': 'Null-byte poisoning (House of Einherjar variant)',
        'prerequisites': [
            'glibc < 2.26 (或未启用 tcache)',
            '至少 3 个连续分配的 chunk',
            '中间 chunk 的 size LSB = 0x01 (PREV_INUSE set)',
            'off-by-one 写入 null 字节 (\\x00)',
        ],
        'steps': [
            '1. malloc(24) → A (chunk_size=0x20, usable=24)',
            '2. malloc(248) → B (chunk_size=0x100, usable=248)',
            '3. malloc(24) → C (chunk_size=0x20, usable=24)',
            '4. memset(A, "A", 24) — 溢出 1 个 null 字节 → B.size: 0x101→0x100',
            '5. free(B) — glibc 认为 B 大小为 0x100 而非 0x101',
            '6. malloc(240) → X — 得到 B 的内存，但 C 仍在原位',
            '7. X 与 C 重叠 → 写 X 覆盖 C 的内容 → 任意读/写',
        ],
        'our_detection': (
            '检测: write(25) > usable(24) → off-by-one → '
            '溢出字节覆盖相邻 chunk size LSB → CRITICAL'),
        'fix_glibc_2.26': '引入 size 校验: 检查合并 chunk 的 size 是否一致',
    }
