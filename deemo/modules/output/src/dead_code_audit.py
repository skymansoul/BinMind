"""
死代码攻击面审计 — 未使用导入×不可达函数×冗余段的膨胀税。

问题定义:
  二进制常携带不必要的代码: 静态链接但未使用的库函数、遗留的
  调试代码、默认开启但不需要的 feature flag。每段死代码增加:
    1. 直接攻击面 (未使用但存在漏洞的函数仍可被 ROP 利用)
    2. 间接攻击面 (死代码中的 gadget 仍可用于利用链)
    3. 审计噪音 (死漏洞告警分散安全团队的注意力)

  本模块从三个维度量化"膨胀税":
    - 导入膨胀: 导入但从未调用的函数
    - 段膨胀: 非标准段占二进制大小的比例
    - 符号膨胀: 导出但无调用者的函数 (共享库场景)

  无现有工具 — 2026-08 检索确认.
  Bloaty McBloatface (Google): 二进制大小分析，不评分攻击面.
  Ghidra Dead Code Elimination: 函数级, 不量化风险.

修改记录:
  2024-11-05 16:42 - 初始版本，三维膨胀税模型
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# 高风险导入类别 — 即使未使用也会增加 gadget 面
_HIGH_RISK_IMPORT_PATTERNS: Dict[str, float] = {
    'system': 0.9, 'exec': 0.9, 'popen': 0.8,
    'memcpy': 0.3, 'strcpy': 0.5, 'sprintf': 0.5,
    'mprotect': 0.6, 'mmap': 0.4, 'VirtualAlloc': 0.5,
    'dlopen': 0.5, 'dlsym': 0.5,
    'socket': 0.4, 'connect': 0.4, 'bind': 0.3,
}

# 非标准段风险权重
_SECTION_BLOAT_WEIGHTS: Dict[str, float] = {
    '.debug': 0.05, '.comment': 0.02, '.note': 0.03,
    '.eh_frame': 0.1, '.gcc_except_table': 0.05,
    '.init_array': 0.15, '.fini_array': 0.1,
    '.ctors': 0.1, '.dtors': 0.1,
    '.jcr': 0.05, '.got': 0.2, '.plt': 0.25,
    '.tdata': 0.05, '.tbss': 0.02,
}

@dataclass
class BloatAudit:
    """死代码膨胀审计。"""
    binary_name: str
    bloat_score: float              # 0-10, 膨胀税综合评分
    import_bloat: float             # 导入膨胀贡献
    section_bloat: float            # 段膨胀贡献
    symbol_bloat: float             # 符号膨胀贡献
    dead_imports: List[str] = field(default_factory=list)
    estimated_bytes_wasted: int = 0 # 估算的可移除字节数
    top_removal_targets: List[str] = field(default_factory=list)

def _unused_imports(
    imports: List[str],
    called_functions: Set[str],
) -> Tuple[Set[str], float]:
    """检测导入但从未调用的函数 → 死导入。"""
    called_norm = {f.lower().lstrip('_') for f in called_functions}
    unused = set()
    total_risk = 0.0

    for imp in imports:
        norm = imp.lower().lstrip('_').replace('__imp_', '')
        if norm not in called_norm:
            unused.add(imp)
            for pat, weight in _HIGH_RISK_IMPORT_PATTERNS.items():
                if pat in norm:
                    total_risk += weight
                    break

    # 指数衰减防止大量低风险死导入堆积
    bloat = round(1.0 - math.exp(-total_risk * 2.0), 2)
    return unused, bloat

def _section_bloat_ratio(
    section_sizes: Dict[str, int],
    total_size: int,
) -> float:
    """非必要段占比 → 段膨胀因子。"""
    if total_size <= 0:
        return 0.0

    bloat_bytes = 0
    for name, size in section_sizes.items():
        base = name.lstrip('.')
        for pat, weight in _SECTION_BLOAT_WEIGHTS.items():
            p = pat.lstrip('.')
            if p in base or base == p:
                bloat_bytes += int(size * weight)
                break

    ratio = bloat_bytes / total_size
    # sigmoid: 10% bloat → 0.5, 30% → 0.9
    return round(1.0 / (1.0 + math.exp(-8.0 * (ratio - 0.1))), 2)

def _symbol_bloat(
    exported_symbols: List[str],
    internal_callers: Set[str],
) -> float:
    """导出但无内部调用者 → 可移除的外部接口。"""
    if not exported_symbols:
        return 0.0

    callers_norm = {c.lower().lstrip('_') for c in internal_callers}
    dead_exports = 0
    for sym in exported_symbols:
        norm = sym.lower().lstrip('_')
        if norm not in callers_norm:
            dead_exports += 1

    ratio = dead_exports / len(exported_symbols)
    return round(min(ratio * 3.0, 1.0), 2)

def audit_dead_code(
    binary_name: str = '',
    imports: Optional[List[str]] = None,
    called_functions: Optional[Set[str]] = None,
    section_sizes: Optional[Dict[str, int]] = None,
    total_size: int = 0,
    exported_symbols: Optional[List[str]] = None,
    internal_callers: Optional[Set[str]] = None,
) -> BloatAudit:
    """
    审计二进制的死代码膨胀税。

    返回 BloatAudit (0-10)，含三维分解和移除建议。
    """
    imports = imports or []
    called_funcs = called_functions or set()

    dead_imps, imp_bloat = _unused_imports(imports, called_funcs)
    sec_bloat = _section_bloat_ratio(section_sizes or {}, total_size)
    sym_bloat = _symbol_bloat(exported_symbols or [], internal_callers or set())

    # 加权: 导入 40%, 段 35%, 符号 25%
    raw = 0.40 * imp_bloat + 0.35 * sec_bloat + 0.25 * sym_bloat
    bloat_score = round(raw * 10.0, 1)

    # 移除目标: 死导入+可缩减段
    targets = list(dead_imps)[:8]

    # 浪费字节估算
    wasted = 0
    if section_sizes and total_size > 0:
        for name, size in section_sizes.items():
            base = name.lstrip('.')
            for pat in _SECTION_BLOAT_WEIGHTS:
                if pat.lstrip('.') in base or base == pat.lstrip('.'):
                    wasted += size
    # 死导入: 每个约 8-24 bytes (PLT entry + GOT entry)
    wasted += len(dead_imps) * 16

    return BloatAudit(
        binary_name=binary_name or 'unknown',
        bloat_score=bloat_score,
        import_bloat=round(imp_bloat * 10, 1),
        section_bloat=round(sec_bloat * 10, 1),
        symbol_bloat=round(sym_bloat * 10, 1),
        dead_imports=list(dead_imps),
        estimated_bytes_wasted=wasted,
        top_removal_targets=targets,
    )

def bloat_summary(audit: BloatAudit) -> Dict[str, Any]:
    """膨胀审计摘要。"""
    recs = []
    if audit.dead_imports:
        recs.append(f'{len(audit.dead_imports)} 个未使用的导入 — '
                    f'可通过 -Wl,--gc-sections 或 LTO 移除')
    if audit.section_bloat >= 5.0:
        recs.append('段膨胀显著 — 使用 strip --strip-all 移除调试信息')
    if audit.symbol_bloat >= 5.0:
        recs.append('导出符号过多 — 使用 -fvisibility=hidden 减少导出面')

    return {
        'bloat_score': audit.bloat_score,
        'risk_level': ('critical' if audit.bloat_score >= 7.0 else
                       'high' if audit.bloat_score >= 4.5 else
                       'medium' if audit.bloat_score >= 2.5 else 'low'),
        'estimated_bytes_wasted': audit.estimated_bytes_wasted,
        'factors': {
            'unused_imports': audit.import_bloat,
            'section_bloat': audit.section_bloat,
            'exported_symbols': audit.symbol_bloat,
        },
        'top_removal_targets': audit.top_removal_targets[:5],
        'recommendations': recs,
    }
