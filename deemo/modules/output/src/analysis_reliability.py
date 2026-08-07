"""
分析可靠度评分 — 混淆/加壳/损坏对自动化分析结果的置信度折扣。

问题定义:
  自动化漏洞分析工具对加壳/混淆/损坏的二进制产生不可靠结果。
  攻击者可以故意加壳来降低被检测的概率 (arXiv 2025.12 证实了
  内联优化可武器化以规避 ML 分析)。现有工具 (Detect It Easy, PEiD)
  检测壳但报告二进制标签，不提供量化的 "分析结果可信度" 折扣。

  本模块从四个维度量化分析可靠度:
    1. 节熵异常 — 高熵节暗示加密/压缩 (加壳标志)
    2. 导入表稀疏度 — 过少的导入暗示 IAT 混淆或运行时解析
    3. 节名异常 — 非标准节名暗示自定义壳
    4. 入口点异常 — 入口在非标准节中暗示壳入口

  可靠度 = 1 - max(各维度的不确定性贡献)
  R=1.0 → 分析结果完全可信；R<0.3 → 结果大概率不可靠。

  无现有量化模型.
  Detect It Easy, PEiD, Exeinfo PE: 检测但不量化.
  arXiv 2025.12: 编译器优化可故意削弱 ML 分析.

修改记录:
  2026-08-03 09:45 - 初始版本，四维异常检测 + 可靠度映射
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# 已知壳的标准节名模式
_KNOWN_PACKER_SECTIONS = frozenset({
    '.upx', 'UPX0', 'UPX1', '.aspack', '.petite', '.mackt',
    '.yoda', '.y0da', '.mpress', '.themida', '.enigma',
    '.vmp', '.vmp0', '.vmp1', '.taggant', '.seau',
    '.icode', '.pdata', '.rsrc',  # 非壳但非标准
})

# 标准编译器产生的节名
_STANDARD_SECTIONS = frozenset({
    '.text', '.data', '.bss', '.rdata', '.rodata', '.edata',
    '.idata', '.xdata', '.pdata', '.reloc', '.tls', '.rsrc',
    '.init', '.fini', '.ctors', '.dtors', '.got', '.plt',
    '.got.plt', '.eh_frame', '.eh_frame_hdr', '.note', '.debug',
    '__text', '__data', '__bss', '__const', '__cstring',
    '__objc_classlist', '__objc_protolist', '__objc_methname',
    'CODE', 'DATA', 'BSS', '.itext', '.itext0',
})

@dataclass
class ReliabilityScore:
    """二进制分析可靠度。"""
    binary_name: str
    entropy_anomaly: float         # 0-1, 节熵异常度
    import_sparsity: float         # 0-1, 导入稀疏度
    section_name_anomaly: float    # 0-1, 节名异常度
    entry_point_anomaly: float     # 0-1, 入口点异常度
    overall_reliability: float     # 0-1, 综合可靠度
    packer_suspected: str = ''     # 推测的壳类型
    recommendation: str = ''

def _section_entropy_anomaly(
    section_entropies: Dict[str, float],
    section_sizes: Dict[str, int],
) -> float:
    """
    节熵异常 — 高熵在 .text 中暗示加密/压缩代码。

    Shannon 熵 > 7.0 在可执行节 → 几乎确定加密。
    熵 > 6.5 且在非资源节 → 高度可疑。
    """
    anomaly = 0.0
    text_sections = {'.text', '__text', 'CODE', '.itext', '.itext0'}

    for name, ent in section_entropies.items():
        size = section_sizes.get(name, 0)
        if size <= 0:
            continue  # 空节不计

        if ent >= 7.2:
            anomaly = max(anomaly, 0.9)
        elif ent >= 6.8:
            anomaly = max(anomaly, 0.6)
        elif ent >= 6.2 and name in text_sections:
            anomaly = max(anomaly, 0.3)

    return round(min(anomaly, 1.0), 2)

def _import_sparsity(import_count: int, total_functions: int) -> float:
    """
    导入表稀疏度 — 导入过少暗示 IAT 混淆或运行时动态解析。

    大型二进制 (>100 函数) 仅 1-3 个导入 → IAT 混淆标志。
    """
    if total_functions <= 5:  # 小型二进制不计
        return 0.0
    if import_count == 0:
        return 0.85
    if import_count <= 2 and total_functions > 50:
        return 0.7
    ratio = import_count / total_functions
    if ratio < 0.02:
        return round(0.6 - ratio * 20, 2)  # 越稀疏越可疑
    return 0.0

def _section_name_anomaly(section_names: List[str]) -> float:
    """
    节名异常 — 非标准节名暗示自定义壳。

    存在已知壳节名 → 0.9 (高置信度)。
    存在未知节名 (不在标准列表) → 0.4/节, 上限 0.8。
    """
    unknown_count = 0
    has_packer_section = False

    for name in section_names:
        if name in _KNOWN_PACKER_SECTIONS:
            has_packer_section = True
        elif name not in _STANDARD_SECTIONS:
            unknown_count += 1

    if has_packer_section:
        return 0.9
    return round(min(unknown_count * 0.4, 0.8), 2)

def _entry_point_anomaly(
    entry_section: str,
    section_names: List[str],
    section_flags: Optional[Dict[str, str]] = None,
) -> float:
    """
    入口点异常 — 入口在不寻常的节中。

    正常: .text / CODE — 异常度 0。
    可疑: .rsrc / .data / 非标准节 — 异常度 0.6-0.8。
    """
    text_sections = {'.text', '__text', 'CODE', '.itext', '.itext0'}
    if entry_section in text_sections:
        return 0.0
    if entry_section in ('.rsrc', '.data', '__data', 'DATA'):
        return 0.7
    if entry_section not in _STANDARD_SECTIONS:
        return 0.8
    # 可写+可执行节中 (W^X 违反)
    if section_flags:
        flags = section_flags.get(entry_section, '')
        if 'w' in flags.lower() and 'x' in flags.lower():
            return 0.75
    return 0.3

def _detect_packer(section_names: List[str]) -> str:
    """从节名推测壳类型。"""
    sn_set = {s.lower() for s in section_names}
    if any('upx' in s for s in sn_set):
        return 'UPX'
    if any('aspack' in s for s in sn_set):
        return 'ASPack'
    if any('petite' in s for s in sn_set):
        return 'Petite'
    if any('themida' in s for s in sn_set):
        return 'Themida'
    if any('vmp' in s for s in sn_set) or any('enigma' in s for s in sn_set):
        return 'VMProtect/Themida/Enigma'
    if any('mpress' in s for s in sn_set):
        return 'MPRESS'
    return 'unknown'

def assess_reliability(
    binary_name: str = '',
    section_entropies: Optional[Dict[str, float]] = None,
    section_sizes: Optional[Dict[str, int]] = None,
    section_names: Optional[List[str]] = None,
    section_flags: Optional[Dict[str, str]] = None,
    entry_section: str = '.text',
    import_count: int = 0,
    total_functions: int = 0,
) -> ReliabilityScore:
    """
    评估二进制分析可靠度。

    返回 ReliabilityScore, overall_reliability = 1 - max(四维异常度)。
    """
    section_entropies = section_entropies or {}
    section_sizes = section_sizes or {}
    section_names = section_names or []

    ent_anom = _section_entropy_anomaly(section_entropies, section_sizes)
    imp_sparse = _import_sparsity(import_count, total_functions)
    name_anom = _section_name_anomaly(section_names)
    ep_anom = _entry_point_anomaly(entry_section, section_names, section_flags)

    worst = max(ent_anom, imp_sparse, name_anom, ep_anom)
    reliability = round(1.0 - worst, 2)

    packer = _detect_packer(section_names) if worst >= 0.5 else ''

    # 推荐操作
    if reliability < 0.3:
        rec = ('分析结果高度不可靠。建议: 1) 尝试自动脱壳; '
               '2) 使用动态分析替代静态分析; 3) 标注此二进制为高不确定性')
    elif reliability < 0.6:
        rec = ('分析结果中等可靠。建议: 在报告中标注 "受混淆/加壳影响"，'
               '结合动态分析验证关键发现')
    elif reliability < 0.85:
        rec = '分析结果基本可靠。部分发现可能受轻微混淆影响'
    else:
        rec = '分析结果高度可靠'

    return ReliabilityScore(
        binary_name=binary_name or 'unknown',
        entropy_anomaly=ent_anom,
        import_sparsity=imp_sparse,
        section_name_anomaly=name_anom,
        entry_point_anomaly=ep_anom,
        overall_reliability=reliability,
        packer_suspected=packer,
        recommendation=rec,
    )
