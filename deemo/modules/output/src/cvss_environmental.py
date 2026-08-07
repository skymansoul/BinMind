"""
CVSS 3.1 环境评分计算 — 公式引擎。

依据:
  CVSS v3.1 Environmental Metric Group (FIRST.org)
    - Security Requirements: CR/IR/AR 权重 → Modified Impact 调整
    - Modified Base Metrics: MAV/MAC/MPR/MUI/MS/MC/MI/MA
    - EnvironmentalScore = 套用 Modified 度量重算 Exploitability + Impact

推断规则已独立为 checksec_to_cvss.py:
  - infer_modified_metrics(): checksec → Modified Base
  - infer_security_requirements(): checksec + imports → CR/IR/AR

本模块仅包含评分公式 — 将推断结果代入 CVSS 3.1 规范计算。

  - CVSS v3.1 User Guide §6 (Environmental Score)
  - FIRST CVSS v3.1 Specification Document, §2.4

修改记录:
  2025-07-22 11:27 - 增加 FORTIFY_SOURCE 对 Modified AC 的影响权重
  2025-07-24 09:53 - CR/IR/AR 推断拆分至 checksec_to_cvss.py
  2025-07-24 15:22 - 重构: 本模块仅保留评分公式，推断规则外移
"""

import logging
from math import ceil
from typing import Any, Dict

from modules.output.src.checksec_to_cvss import (
    infer_modified_metrics,
    infer_security_requirements,
)

_log = logging.getLogger(__name__)

def compute_environmental_score(
    base_score: float,
    temporal_score: float,
    checksec: Dict[str, Any],
    base_metrics: Dict[str, str],
    imports: list = None,
    binary_type: str = ''
) -> Dict[str, Any]:
    """
    从二进制加固状态计算 CVSS 3.1 完整环境评分。

    流程:
      1. checksec → infer_modified_metrics() → Modified Base Metrics
      2. checksec + imports → infer_security_requirements() → CR/IR/AR
      3. 套用 CVSS 3.1 §2.4 环境评分公式
      4. 返回 环境评分 + Modified 度量 + Modified 向量后缀

    评分公式 (简化):
      ModifiedExploitability = 8.22 × MAV_weight × MAC_weight × MPR_weight × MUI_weight
      ModifiedISC = 1 - [ (1-MC×CR) × (1-MI×IR) × (1-MA×AR) ]
      ModifiedImpact = 6.42 × ModifiedISC  (scope=U) 或
                       7.52×(ModifiedISC-0.029) - 3.25×(ModifiedISC-0.02)^15  (scope=C)
      Environmental = ModifiedImpact + ModifiedExploitability  (scope=U) 或
                       1.08×(ModifiedImpact + ModifiedExploitability)  (scope=C)
      上限 10，>0 时 round_up。

    返回:
      {
        'environmental_score': float,
        'modified_metrics': {MAV, MAC, MPR, MUI, MS, MC, MI, MA},
        'security_requirements': {CR, IR, AR},
        'modified_vector_suffix': str,
      }
    """
    modified = infer_modified_metrics(checksec, base_metrics)
    reqs = infer_security_requirements(checksec, imports, binary_type)

# Modified Exploitability
    _av_w = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
    _ac_w = {'L': 0.77, 'H': 0.44}
    _pr_w_u = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    _pr_w_c = {'N': 0.85, 'L': 0.68, 'H': 0.50}
    _ui_w = {'N': 0.85, 'R': 0.62}

    mav = _av_w.get(modified.get('MAV', base_metrics.get('AV', 'N')), 0.55)
    mac = _ac_w.get(modified.get('MAC', base_metrics.get('AC', 'L')), 0.77)
    mpr_k = modified.get('MPR', base_metrics.get('PR', 'N'))
    mui = _ui_w.get(modified.get('MUI', base_metrics.get('UI', 'N')), 0.85)
    ms = modified.get('MS', base_metrics.get('S', 'U'))

    mpr = (_pr_w_c if ms == 'C' else _pr_w_u).get(mpr_k, 0.85)
    modified_expl = 8.22 * mav * mac * mpr * mui

# Modified Impact
    _cia = {'N': 0.0, 'L': 0.22, 'H': 0.56}
    _req_w = {'N': 1.0, 'L': 0.5, 'M': 1.0, 'H': 1.5}

    mc = _cia.get(modified.get('MC', base_metrics.get('C', 'N')), 0)
    mi_v = _cia.get(modified.get('MI', base_metrics.get('I', 'N')), 0)
    ma_v = _cia.get(modified.get('MA', base_metrics.get('A', 'N')), 0)
    cr = _req_w.get(reqs.get('CR', 'M'), 1.0)
    ir = _req_w.get(reqs.get('IR', 'M'), 1.0)
    ar = _req_w.get(reqs.get('AR', 'M'), 1.0)

    isc_mod = 1 - ((1 - mc * cr) * (1 - mi_v * ir) * (1 - ma_v * ar))
    isc_mod = min(isc_mod, 0.915)

    if ms == 'U':
        mod_impact = 6.42 * isc_mod
    else:
        mod_impact = 7.52 * (isc_mod - 0.029) - 3.25 * ((isc_mod - 0.02) ** 15)

# Environmental Score
    if mod_impact <= 0:
        env_score = 0.0
    elif ms == 'U':
        env_score = min(mod_impact + modified_expl, 10)
    else:
        env_score = min(1.08 * (mod_impact + modified_expl), 10)

    if env_score > 0:
        env_score = ceil(env_score * 10) / 10.0

# Modified 向量后缀
    parts = []
    for key in ('MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'):
        if key in modified:
            parts.append(f'{key}:{modified[key]}')
    parts.append(f'CR:{reqs["CR"]}')
    parts.append(f'IR:{reqs["IR"]}')
    parts.append(f'AR:{reqs["AR"]}')

    result = {
        'environmental_score': env_score,
        'modified_metrics': modified,
        'security_requirements': reqs,
        'modified_vector_suffix': '/' + '/'.join(parts),
    }

    hardening_count = (
        sum(checksec.get(k, False) for k in ('NX', 'PIE', 'Canary')) +
        ('full' in checksec.get('RELRO', '').lower()) +
        checksec.get('FORTIFY', False)
    )
    _log.info(
        "[CVSS] 环境评分: %.1f (基础: %.1f, 时间: %.1f, 加固: %d/5)",
        env_score, base_score, temporal_score, hardening_count
    )
    return result
