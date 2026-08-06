# Created: 2025-07-23 09:27:32
#
# evidence_fusion — Dempster-Shafer 证据融合引擎
# 将异构静态分析信号（API匹配/字符串/熵/段特征）作为独立证据体，
# 用 DST 组合规则融合为统一威胁置信度，量化冲突与不确定性。
# 区别于 Galdames et al. (MDPI 2025): 该文献融合 ML 分类器输出，本模块直接融合原始分析信号。

import math
from typing import Dict, List, Tuple, Optional


def _mass_from_api_signal(
    api_match_ratio: float,
    total_imports: int,
    dangerous_imports: int,
) -> Tuple[float, float, float]:
    """API 导入信号 → 基本概率分配 (threat, benign, unknown)。
    api_match_ratio: 匹配的危险 API 比例
    total_imports: 总导入函数数
    dangerous_imports: 危险导入函数数
    """
    if total_imports == 0:
        return (0.0, 0.0, 1.0)

    # 危险函数占比的 sigmoid 映射
    _danger_ratio = dangerous_imports / max(total_imports, 1)
    _threat_raw = 1.0 / (1.0 + math.exp(-10 * (_danger_ratio - 0.08)))

    # 单一危险函数不足以支持高置信度
    if dangerous_imports == 1 and _danger_ratio < 0.02:
        _threat_raw *= 0.4

    _threat = min(_threat_raw * api_match_ratio, 0.85)
    _benign = (1.0 - _threat_raw) * 0.6 if dangerous_imports == 0 else 0.0
    _unknown = max(0.05, 1.0 - _threat - _benign)

    return (round(_threat, 4), round(_benign, 4), round(_unknown, 4))


def _mass_from_string_signal(
    suspicious_string_count: int,
    total_strings: int,
    specific_matches: int,
) -> Tuple[float, float, float]:
    """字符串信号 → 基本概率分配。
    specific_matches: 高特异性模式命中数（如 mimikatz, cobaltstrike, 已知 C2 域名）
    """
    if total_strings == 0:
        return (0.0, 0.0, 1.0)

    # 高特异性匹配直接给强信号
    if specific_matches >= 2:
        _threat = 0.70 + 0.05 * specific_matches
    elif specific_matches == 1:
        _threat = 0.45
    else:
        _ratio = suspicious_string_count / max(total_strings, 1)
        _threat = 1.0 / (1.0 + math.exp(-12 * (_ratio - 0.02)))

    _threat = min(_threat, 0.90)
    _benign = 0.05 if suspicious_string_count == 0 else 0.0
    _unknown = max(0.05, 1.0 - _threat - _benign)

    return (round(_threat, 4), round(_benign, 4), round(_unknown, 4))


def _mass_from_entropy_signal(
    high_entropy_ratio: float,
    layout_anomaly: float,
) -> Tuple[float, float, float]:
    """熵异常信号 → 基本概率分配。
    高 entropy_ratio 与 layout_anomaly 的组合指示打包/混淆。
    单独高熵可能是压缩资源，未必恶意。需与段布局异常联合判定。
    """
    # 仅高熵无布局异常 → 弱信号（可能是压缩数据段）
    # 高熵 + 布局异常 → 强信号（打包器/加密器特征）
    if layout_anomaly > 0.5:
        _threat = 0.40 + 0.35 * min(high_entropy_ratio, 1.0) * layout_anomaly
    elif high_entropy_ratio > 0.3:
        _threat = 0.10 * high_entropy_ratio
    else:
        _threat = 0.0

    _threat = min(_threat, 0.80)
    _benign = 0.15 if (high_entropy_ratio < 0.1 and layout_anomaly < 0.2) else 0.0
    _unknown = max(0.05, 1.0 - _threat - _benign)

    return (round(_threat, 4), round(_benign, 4), round(_unknown, 4))


def _mass_from_section_signal(
    rwx_sections: int,
    exec_sections: int,
    total_sections: int,
) -> Tuple[float, float, float]:
    """段特征信号 → 基本概率分配。
    RWX 段 = 明确的恶意信号。但需考虑 JIT 编译器（正常场景）。
    """
    if total_sections == 0:
        return (0.0, 0.0, 1.0)

    if rwx_sections > 0:
        # 多个 RWX 段比单个更可疑
        _threat = 0.55 + 0.15 * min(rwx_sections - 1, 3)
        _threat = min(_threat, 0.90)
        _benign = 0.0
    elif exec_sections > total_sections * 0.6:
        # 过高比例的可执行段 → 异常，但不能排除特殊编译器
        _threat = 0.15
        _benign = 0.10
    else:
        _threat = 0.0
        _benign = 0.20

    _unknown = max(0.05, 1.0 - _threat - _benign)
    return (round(_threat, 4), round(_benign, 4), round(_unknown, 4))


def dempster_combine(m1: Tuple[float, float, float],
                     m2: Tuple[float, float, float]) -> Tuple[float, float, float]:
    """Dempster 组合规则: m12(A) = sum(m1(X)*m2(Y) for X∩Y=A) / (1-K)
    K = 冲突系数 = sum(m1(X)*m2(Y) for X∩Y=∅)
    """
    t1, b1, u1 = m1
    t2, b2, u2 = m2

    # 冲突 K: threat∩benign + benign∩threat
    K = t1 * b2 + b1 * t2

    # 组合 mass
    _threat = (t1 * t2 + t1 * u2 + u1 * t2)
    _benign = (b1 * b2 + b1 * u2 + u1 * b2)
    _unknown = u1 * u2

    if K >= 0.999:
        # 极端冲突：证据完全矛盾，回退到保守估计
        return (0.25, 0.25, 0.50)

    _norm = 1.0 / (1.0 - K)
    return (
        round(_threat * _norm, 4),
        round(_benign * _norm, 4),
        round(_unknown * _norm, 4),
    )


def fuse_evidence(
    api_match_ratio: float = 0.0,
    total_imports: int = 0,
    dangerous_imports: int = 0,
    suspicious_string_count: int = 0,
    total_strings: int = 0,
    specific_string_matches: int = 0,
    high_entropy_ratio: float = 0.0,
    layout_anomaly: float = 0.0,
    rwx_sections: int = 0,
    exec_sections: int = 0,
    total_sections: int = 0,
) -> Dict:
    """异构静态证据融合主入口。
    输入各检测维度的原始计数/比率，输出融合后的信念/似然/冲突。
    调用方无需理解 DST 内部机制，只需提供各维度的标量指标。
    """
    _masses = []
    _labels = []

    _m_api = _mass_from_api_signal(api_match_ratio, total_imports, dangerous_imports)
    _masses.append(_m_api)
    _labels.append("api_imports")

    _m_str = _mass_from_string_signal(
        suspicious_string_count, total_strings, specific_string_matches)
    _masses.append(_m_str)
    _labels.append("strings")

    _m_ent = _mass_from_entropy_signal(high_entropy_ratio, layout_anomaly)
    _masses.append(_m_ent)
    _labels.append("entropy")

    _m_sec = _mass_from_section_signal(rwx_sections, exec_sections, total_sections)
    _masses.append(_m_sec)
    _labels.append("sections")

    # 顺序组合：按信号强度降序，强信号先组合减少冲突放大
    _sorted = sorted(
        zip(_masses, _labels),
        key=lambda x: x[0][0],
        reverse=True,
    )

    _combined = _sorted[0][0]
    _fusion_steps = [{"step": 0, "source": _sorted[0][1],
                      "mass": list(_combined), "conflict": 0.0}]

    for _i, (_mass, _label) in enumerate(_sorted[1:], 1):
        _t1, _b1, _u1 = _combined
        _t2, _b2, _u2 = _mass
        _K = _t1 * _b2 + _b1 * _t2
        _combined = dempster_combine(_combined, _mass)
        _fusion_steps.append({
            "step": _i, "source": _label,
            "mass": list(_combined), "conflict": round(_K, 4),
        })

    _belief = _combined[0]
    _plausibility = _combined[0] + _combined[2]
    _final_conflict = _fusion_steps[-1]["conflict"]

    # 决策映射
    if _belief > 0.70:
        _verdict = "MALICIOUS"
    elif _plausibility > 0.60 and _belief > 0.30:
        _verdict = "SUSPICIOUS"
    elif _plausibility > 0.30:
        _verdict = "INCONCLUSIVE"
    else:
        _verdict = "BENIGN"

    return {
        "belief": round(_belief, 4),
        "plausibility": round(_plausibility, 4),
        "uncertainty": round(_combined[2], 4),
        "conflict": round(_final_conflict, 4),
        "verdict": _verdict,
        "individual_masses": dict(zip(_labels, [
            {"threat": m[0], "benign": m[1], "unknown": m[2]}
            for m in [_m_api, _m_str, _m_ent, _m_sec]
        ])),
        "fusion_steps": _fusion_steps,
    }


def quick_fuse_from_detection_results(
    detection_results: Dict[str, Dict],
    entropy_info: Dict = None,
    section_info: Dict = None,
) -> Dict:
    """便捷入口：直接从各检测器的 detect_all() 结果中提取信号并融合。
    自动计算各维度指标，调用方无需手动统计。
    """
    _api_ratio = 0.0
    _total_imp = 0
    _danger_imp = 0
    _susp_str = 0
    _total_str = 0
    _specific = 0
    _rwx = 0
    _exec = 0
    _total_sec = 0

    for _detector_name, _result in detection_results.items():
        if not isinstance(_result, dict):
            continue
        _findings = _result.get("findings", {})
        if isinstance(_findings, dict):
            for _tech_name, _tech_result in _findings.items():
                if not isinstance(_tech_result, dict):
                    continue
                if _tech_result.get("detected"):
                    _api_ratio += _tech_result.get("confidence", 0.0)
                    _susp_str += _tech_result.get("str_matches", 0)
                    _specific += 1 if _tech_result.get("confidence", 0) > 0.7 else 0

    _api_ratio = min(_api_ratio / max(len(detection_results), 1), 1.0) if detection_results else 0.0

    if entropy_info:
        _high_ent = entropy_info.get("high_window_ratio", 0.0)
        _layout = entropy_info.get("layout_anomaly_score", 0.0)
    else:
        _high_ent = 0.0
        _layout = 0.0

    if section_info:
        _rwx = section_info.get("rwx_sections", 0)
        _exec = section_info.get("exec_sections", 0)
        _total_sec = section_info.get("total_sections", 0)

    return fuse_evidence(
        api_match_ratio=_api_ratio,
        total_imports=max(_total_imp, 1),
        dangerous_imports=_danger_imp,
        suspicious_string_count=_susp_str,
        total_strings=max(_total_str, 1),
        specific_string_matches=_specific,
        high_entropy_ratio=_high_ent,
        layout_anomaly=_layout,
        rwx_sections=_rwx,
        exec_sections=_exec,
        total_sections=max(_total_sec, 1),
    )
