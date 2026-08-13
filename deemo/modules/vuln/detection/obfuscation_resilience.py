"""
混淆/加壳二进制检测降级策略 — 已知不可靠时主动切换分析路径。

设计决策:
  1. 检测混淆信号 (节熵、导入稀疏度、非标准节名) → 量化"分析可靠度"
  2. 可靠度 < 0.4: 跳过静态分析的确定性结论, 切换到LLM+动态验证路径
  3. 可靠度 < 0.7: 静态分析结论标注"低置信度", 不输出确定判定
  4. 非全局关闭——对未混淆的函数仍用静态分析

为什么不是"先脱壳再分析":
  脱壳依赖特定壳版本的unpacker → 通用性差。
  本策略的"降级而非脱壳"对未知壳/自定义混淆仍有效——只是损失精度,
  而不是完全失败。

修改记录:
  创建 2024-12-09 — 混淆信号检测 + 三级降级策略
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ResilienceTier(Enum):
    FULL_STATIC = "full_static"        # 可靠度 ≥ 0.7 — 全静态分析
    HYBRID_CAUTIOUS = "hybrid_cautious"  # 0.4-0.7 — 静态+LLM混合, 标注低置信度
    DYNAMIC_FALLBACK = "dynamic_fallback"  # < 0.4 — 仅动态+LLM, 静态仅作参考


@dataclass
class ObfuscationSignal:
    entropy_anomaly: float           # 0-1, 节熵异常度
    import_sparsity: float           # 0-1, 导入稀疏度
    section_name_anomaly: float      # 0-1, 非标准节名程度
    entry_point_anomaly: float       # 0-1, 入口点异常度
    overall_reliability: float       # 0-1
    suspected_packer: str = ''


def detect_obfuscation(
    section_entropies: Optional[Dict[str, float]] = None,
    section_names: Optional[List[str]] = None,
    import_count: int = 10,
    total_functions: int = 50,
    entry_section: str = '.text',
) -> ObfuscationSignal:
    """
    检测二进制混淆信号, 返回分析可靠度。

    每项异常度 ∈ [0,1], 取max (最差维度决定下限)。
    """
    entropies = section_entropies or {}
    names = section_names or []

    ent_anom = 0.0
    for name, ent in entropies.items():
        if ent >= 7.2: ent_anom = max(ent_anom, 0.9)
        elif ent >= 6.5: ent_anom = max(ent_anom, 0.5)

    imp_sparse = 0.0
    if total_functions > 10:
        ratio = import_count / total_functions
        if ratio < 0.03: imp_sparse = 0.8
        elif ratio < 0.05: imp_sparse = 0.4

    known_packers = {'.upx', 'UPX0', 'UPX1', '.aspack', '.themida', '.vmp', '.vmp0',
                     '.enigma', '.mpress', '.petite', '.yoda'}
    name_anom = 0.0
    unknown = 0
    for n in names:
        if n in known_packers: name_anom = max(name_anom, 0.9)
        elif n not in ('.text','.data','.bss','.rdata','.rodata','.reloc','.plt','.got',
                       '.init','.fini','.eh_frame'): unknown += 1
    name_anom = max(name_anom, min(unknown * 0.3, 0.8))

    ep_anom = 0.0 if entry_section in ('.text', 'CODE') else 0.7

    worst = max(ent_anom, imp_sparse, name_anom, ep_anom)
    reliability = round(1.0 - worst, 2)

    packer = ''
    for n in names:
        for pk in known_packers:
            if pk.lower() in n.lower():
                packer = pk.lstrip('.')
                break

    return ObfuscationSignal(
        entropy_anomaly=ent_anom, import_sparsity=imp_sparse,
        section_name_anomaly=name_anom, entry_point_anomaly=ep_anom,
        overall_reliability=reliability, suspected_packer=packer)


def get_analysis_strategy(
    signal: ObfuscationSignal,
    per_function_reliability: Optional[Dict[str, float]] = None,
) -> Tuple[ResilienceTier, Dict[str, ResilienceTier]]:
    """
    根据混淆信号确定分析策略。

    返回 (全局策略, {函数名: 函数级策略})。
    函数级策略允许对未混淆函数保留静态分析。
    """
    rel = signal.overall_reliability
    if rel >= 0.7:
        global_tier = ResilienceTier.FULL_STATIC
    elif rel >= 0.4:
        global_tier = ResilienceTier.HYBRID_CAUTIOUS
    else:
        global_tier = ResilienceTier.DYNAMIC_FALLBACK

    per_func = {}
    if per_function_reliability:
        for fname, frel in per_function_reliability.items():
            if frel >= 0.7: per_func[fname] = ResilienceTier.FULL_STATIC
            elif frel >= 0.4: per_func[fname] = ResilienceTier.HYBRID_CAUTIOUS
            else: per_func[fname] = ResilienceTier.DYNAMIC_FALLBACK

    return global_tier, per_func
