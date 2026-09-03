"""ACPE 分配容量模型 — ptmalloc2 可用容量 + 符号容量表达式.

用途: ACPE(Allocator-Capacity Provenance Equivalence)的容量侧基础。
      将 malloc 请求大小映射为分配器实际可用容量, 并区分三个概念:
        requested  用户请求字节数
        usable     分配器舍入后用户实际可用的字节数
        slack      usable - requested (编译器 padding/对齐可合法访问的区域)
      全部边界判定以 usable 为界, 而非 requested——现有工具直接对比
      requested 是把编译器合法 padding 访问误报为溢出的根源之一。

设计决策:
  - 为何以 usable 判定: 编译器 padding/对齐访问落在 [requested, usable)
    区间内, 直接对比 requested 会产生误报; 与 fp_filter_v2 Phase 3 一致。
  - 为何符号容量: memcpy 的 size 常为符号表达式(arg*4+8), 与分配容量
    的比较需要先归一化, 直接整数比较会漏掉等价关系(EQUIV判定失效)。
  - 为何最大 slack 取 15: x86-64 下 usable = round_up(requested+16,16)-16,
    usable-requested 恒落在 [0,15]。超出的写入才是确定越界。
"""

from dataclasses import dataclass
from typing import Optional, Tuple

# ptmalloc2 x86-64 常量 (glibc 2.31+)
_HEADER_SIZE = 16      # prev_size(8) + size(8)
_ALIGNMENT = 16        # MALLOC_ALIGNMENT
_MIN_CHUNK = 32        # 最小 chunk 大小
_MMAP_THRESHOLD = 128 * 1024
_PAGE = 4096


@dataclass(frozen=True)
class CapExpr:
    """符号容量表达式.

    kind:
      CONST  value=整数值
      SYM    base=源符号名 (如 'A:1' 表示第1个函数参数)
      ARITH  base=源符号名, offset=有符号常数偏移
      UNKNOWN
    """
    kind: str = 'UNKNOWN'
    value: int = 0
    base: str = ''
    offset: int = 0

    @classmethod
    def const(cls, v: int) -> 'CapExpr':
        return cls('CONST', value=v)

    @classmethod
    def sym(cls, name: str) -> 'CapExpr':
        return cls('SYM', base=name)

    @classmethod
    def arith(cls, base: str, offset: int) -> 'CapExpr':
        return cls('ARITH', base=base, offset=offset)

    @classmethod
    def unknown(cls) -> 'CapExpr':
        return cls('UNKNOWN')

    def is_const(self) -> bool:
        return self.kind == 'CONST'

    def is_symbolic(self) -> bool:
        return self.kind in ('SYM', 'ARITH')

    def canonical(self) -> str:
        """归一化键: 供等价性判定使用.

        CONST(64)  → 'C:64'
        SYM('A:1') → 'A:1'
        ARITH(+0x20) → 'A:1+32'
        """
        if self.kind == 'CONST':
            return f'C:{self.value}'
        if self.kind == 'SYM':
            return self.base
        if self.kind == 'ARITH':
            if self.offset == 0:
                return self.base
            sign = '+' if self.offset > 0 else ''
            return f'{self.base}{sign}{self.offset}'
        return '?'

    def upper_bound(self) -> Optional[int]:
        """符号上界. CONST/SYNM 派生可给出确定值, 其余返回 None."""
        if self.kind == 'CONST':
            return self.value
        return None

    def __repr__(self) -> str:
        return self.canonical()


def usable_size(requested: int) -> int:
    """malloc(n) → 用户实际可用字节数 (ptmalloc2, x86-64).

    公式: usable = round_up(max(n, 0) + 16, 16) - 16
    同时受最小 chunk 约束: malloc(1) 也分配 32 字节 chunk。
    """
    if requested <= 0:
        return 0
    if requested >= _MMAP_THRESHOLD:
        return _round_up(requested + _HEADER_SIZE, _PAGE) - _HEADER_SIZE
    min_data = max(requested, _MIN_CHUNK - _HEADER_SIZE)
    chunk = _round_up(min_data + _HEADER_SIZE, _ALIGNMENT)
    chunk = max(_MIN_CHUNK, chunk)
    return chunk - _HEADER_SIZE


def slack_bytes(requested: int) -> int:
    """usable - requested, 恒 ∈ [0, 15] (非 mmap 路径)."""
    return max(0, usable_size(requested) - requested)


MAX_SLACK = 15  # usable - requested 的最大值 (x86-64, 非 mmap)


def const_relation(alloc: CapExpr, write: CapExpr) -> Tuple[str, str]:
    """两个常数表达式的容量关系.

    返回 (relation, 说明):
      'CONST_LE'   write 常数 ≤ 分配可用容量 → 安全
      'CONST_GT'   write 常数 > 分配可用容量 → 确定溢出
      'UNKNOWN'    分配容量非常数 → 无法静态判定
    """
    av, wv = alloc.upper_bound(), write.upper_bound()
    if av is None or wv is None:
        return 'UNKNOWN', 'non-constant capacity or size'
    if wv <= usable_size(av):
        return 'CONST_LE', f'write {wv}B <= usable {usable_size(av)}B'
    return 'CONST_GT', f'write {wv}B > usable {usable_size(av)}B'


def arith_relation(alloc: CapExpr, write: CapExpr) -> Tuple[str, str]:
    """同一基址的常数偏移关系 (write = alloc.base + offset).

    ARITH_LE     offset ≤ 0 → 写入不超过分配 → 安全
    ARITH_SLACK  0 < offset ≤ MAX_SLACK → 可能落在分配器 slack 区, 存疑
    ARITH_GT     offset > MAX_SLACK → 确定越界
    """
    if write.base != alloc.base:
        return 'UNKNOWN', 'different base'
    off = write.offset
    if off <= 0:
        return 'ARITH_LE', f'write is alloc{off:+d}, within capacity'
    if off <= MAX_SLACK:
        return 'ARITH_SLACK', (f'write is alloc{off:+d}, within allocator '
                               f'slack [{0},{MAX_SLACK}]')
    return 'ARITH_GT', f'write is alloc{off:+d}, exceeds max slack {MAX_SLACK}'


def _round_up(val: int, align: int) -> int:
    return (val + align - 1) & ~(align - 1)


# 自检
def _check():
    assert usable_size(100) == 112, usable_size(100)
    assert usable_size(1) == 16, usable_size(1)
    assert usable_size(64) == 64, usable_size(64)
    assert slack_bytes(100) == 12
    assert 0 <= slack_bytes(0xdead) <= MAX_SLACK
    r, msg = const_relation(CapExpr.const(100), CapExpr.const(112))
    assert r == 'CONST_LE', (r, msg)
    r2, _ = const_relation(CapExpr.const(64), CapExpr.const(128))
    assert r2 == 'CONST_GT'
    r3, _ = arith_relation(CapExpr.sym('A:1'), CapExpr.arith('A:1', 0x20))
    assert r3 == 'ARITH_GT'
    r4, _ = arith_relation(CapExpr.sym('A:1'), CapExpr.arith('A:1', 8))
    assert r4 == 'ARITH_SLACK'
    print('[OK] capacity_model passed')


if __name__ == '__main__':
    _check()
