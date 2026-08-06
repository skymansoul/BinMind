"""
Double-Free 利用性评分 — 分配器版本×tcache/fastbin 检测×合并路径。

问题定义:
  现代分配器的 double-free 检测机制日趋完善，但不同版本的保护力度
  差异巨大。glibc 2.27 的 tcache 无任何检测 (利用 trivial)，
  glibc 2.34+ 有 tcache key (随机 per-chunk) + fastbin 双重释放检测。

  本模块是第一个 double-free 利用性量化模型，考虑了:
    1. 分配器版本和活跃保护
    2. 释放之间是否有分配 (绕过简单的 fastbin 检测)
    3. chunk 大小类别 (tcache vs fastbin vs smallbin)
    4. 合并路径 — chunk 是否可能被 consolidate (触发额外检查)

参考:
  glibc 2.27-2.33: tcache 无 double-free 检测
  glibc 2.34+: tcache key (per-chunk 随机值)
  fastbin: 仅检查链表头 (易绕过, 两次 free 之间插入一次 free 即可)
  CWE-415: Double Free

修改记录:
  2026-08-02 11:34 - 初始版本，分配器版本×保护×大小类×合并路径
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ChunkSizeClass(Enum):
    TCHACHE = "tcache"      # ≤ 1032 bytes (默认 64 tcache bins)
    FASTBIN = "fastbin"     # ≤ 128 bytes (global_max_fast)
    SMALLBIN = "smallbin"   # ≤ 1024 bytes
    LARGEBIN = "largebin"   # > 1024 bytes → 使用 mmap 或 largebin


# 各版本的 double-free 检测状态
# True = 有检测保护, False = 无保护
_TCACHE_PROTECTION: Dict[str, bool] = {
    'glibc_2.23': False, 'glibc_2.27': False, 'glibc_2.31': False,
    'glibc_2.32': False, 'glibc_2.33': False,
    'glibc_2.34': True,  'glibc_2.35': True,
    'glibc_2.37': True,  'glibc_2.39': True,
}

_FASTBIN_TOP_CHECK: Dict[str, bool] = {
    # fastbin 仅检查链表头是否为同一 chunk (易绕过)
    'glibc_2.23': False, 'glibc_2.27': False, 'glibc_2.31': True,
    'glibc_2.34': True, 'glibc_2.35': True,
    'glibc_2.37': True, 'glibc_2.39': True,
}


@dataclass
class DoubleFreeScore:
    """Double-free 利用性评分。"""
    chunk_size_class: ChunkSizeClass
    tcache_protected: bool
    fastbin_top_check: bool
    interleaving_possible: bool     # 两次 free 之间能否插入分配
    consolidation_risk: bool        # chunk 是否可能被合并 (触发检查)
    exploitability: float           # 0-10
    bypass_needed: List[str] = field(default_factory=list)
    technique: str = ''


def _classify_size(size_bytes: int) -> ChunkSizeClass:
    if size_bytes <= 1032:
        return ChunkSizeClass.TCHACHE
    if size_bytes <= 128:  # 通常在 tcache 范围内
        return ChunkSizeClass.TCHACHE
    if size_bytes <= 1024:
        return ChunkSizeClass.SMALLBIN
    return ChunkSizeClass.LARGEBIN


def _detect_glibc_protection(
    libc_version: str = '',
) -> Tuple[bool, bool]:
    ver = libc_version.lower().replace('glibc-', '').replace('glibc_', '')
    # 版本匹配
    for v in ['2.39', '2.37', '2.35', '2.34', '2.33', '2.32', '2.31', '2.27', '2.23']:
        vmaj = v.split('.')[0] + '.' + v.split('.')[1][:2]
        if ver.startswith(v[:3]):
            return _TCACHE_PROTECTION.get(f'glibc_{v}', True), _FASTBIN_TOP_CHECK.get(f'glibc_{v}', True)
    return True, True  # 保守假设有保护


def score_double_free(
    chunk_size: int = 64,
    libc_version: str = '2.35',
    interleaving_possible: bool = False,
    same_allocation_site: bool = True,
    consolidation_risk: bool = False,
) -> DoubleFreeScore:
    """
    评估 double-free 漏洞的利用性。

    interleaving_possible: 攻击者能否在两次 free 之间触发一次 malloc。
      True → 可绕过 fastbin 顶部检查。
    same_allocation_site: 两次 free 是否在同一调用点。
      True → 更可预测, 便于利用。
    consolidation_risk: chunk 是否可能被前后 chunk 合并。
      True → 合并过程中有额外检查, 降低利用性。
    """
    size_class = _classify_size(chunk_size)
    tcache_prot, fastbin_check = _detect_glibc_protection(libc_version)

    # 基准可利用性
    base_score = {
        ChunkSizeClass.TCHACHE: 8.0,
        ChunkSizeClass.FASTBIN: 7.0,
        ChunkSizeClass.SMALLBIN: 4.0,
        ChunkSizeClass.LARGEBIN: 2.0,  # largebin double-free 几乎不可能
    }.get(size_class, 5.0)

    bypasses: List[str] = []
    penalty = 0.0

    # tcache 保护
    if size_class == ChunkSizeClass.TCHACHE and tcache_prot:
        if interleaving_possible:
            base_score -= 1.0
            bypasses.append('tcache key (需要覆盖或泄露 tcache->key)')
        else:
            penalty += 5.0
            bypasses.append('tcache key — 直接 double-free 被阻止; 需要 key 泄露')

    # fastbin 顶部检查
    if size_class == ChunkSizeClass.FASTBIN and fastbin_check:
        if interleaving_possible:
            base_score -= 0.5  # 可绕过 — 两次 free 之间插入不同 chunk 的 free
            bypasses.append('fastbin top check (可通过交错释放绕过)')
        else:
            penalty += 4.0
            bypasses.append('fastbin top check — 直接 double-free 被阻止')

    # 合并风险
    if consolidation_risk:
        penalty += 3.0
        bypasses.append('chunk consolidation — 合并过程包含额外指针校验')

    # 同一调用点 → 利用更可预测
    if not same_allocation_site:
        base_score -= 1.5

    exploitability = round(max(0.0, min(10.0, base_score - penalty)), 1)

    # 技术推荐
    if exploitability >= 7.0:
        tech = ('直接 double-free: tcache poisoning → '
                '覆盖 tcache->next → 任意地址分配 → 任意写入')
    elif exploitability >= 4.0:
        tech = ('需绕过: ' + '; '.join(bypasses[:2]) if bypasses else
                '通过交错分配绕过 fastbin 检测')
    else:
        tech = ('利用难度高 — 多重保护+合并风险。'
                '考虑 UAF 替代 double-free，或寻找 tcache_perthread_struct 破坏路径')

    return DoubleFreeScore(
        chunk_size_class=size_class,
        tcache_protected=tcache_prot,
        fastbin_top_check=fastbin_check,
        interleaving_possible=interleaving_possible,
        consolidation_risk=consolidation_risk,
        exploitability=exploitability,
        bypass_needed=bypasses,
        technique=tech,
    )
