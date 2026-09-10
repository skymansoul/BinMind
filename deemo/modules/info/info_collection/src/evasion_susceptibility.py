# evasion_susceptibility — 对抗逃逸易感性评分
# 量化各静态检测信号对常见逃逸技术的抵抗能力。
# 不依赖 ML 模型，直接从信号间不一致性推断被隐藏的恶意指标。
#
# 相关工作:
#   - Koch & Begoli: 综述 PE 对抗样本生成，聚焦攻击侧
#   - Jafari & Shameli-Sendi: 评估 ML 检测器防御鲁棒性
# 本模块不生成对抗样本也不评估分类器, 而是从静态信号间的统计不一致性推断
#     "这个二进制用了哪些逃逸技术来隐藏恶意指标"。属于事前逃逸检测。
#
# 检测的逃逸技术信号:
#   1. 字符串-API 不一致: API 检测 > 0.5 但字符串检测 = 0 → 字符串可能被加密
#   2. 导入表异常: API 哈希化迹象 (短/无语义导入名)
#   3. 段熵异常 + 低字符串密度: 高熵段中无可打印字符串 → 字符串被加密
#   4. 控制流平坦化迹象: 异常高的 basic block 数量 / 函数数比
#   5. 反静态分析: detect_api_hashing + detect_xor 同时命中

import math
from typing import Dict, List, Tuple, Optional


def _signal_gap_score(
    api_confidence: float,
    string_confidence: float,
) -> Tuple[float, str]:
    """API 信号与字符串信号不一致性评分。
    高 API 匹配置信度 + 低字符串匹配置信度 = 疑似字符串逃逸。
    """
    _gap = api_confidence - string_confidence
    if _gap > 0.5:
        return (0.70 + (_gap - 0.5) * 0.5, "high_string_evasion_likely")
    if _gap > 0.3:
        return (0.40 + (_gap - 0.3) * 1.5, "moderate_string_evasion_possible")
    if _gap > 0.15:
        return (0.15 + (_gap - 0.15), "minor_discrepancy")
    return (0.0, "consistent")


def _import_anomaly_score(import_anomaly: Dict) -> Tuple[float, str]:
    """导入表异常 → 逃逸评分。"""
    if not import_anomaly:
        return (0.0, "normal_imports")
    _likely = import_anomaly.get("likely_hashed_imports", False)
    _count = import_anomaly.get("anomalous_count", 0)
    if _likely and _count > 10:
        return (0.80, "api_hashing_confirmed")
    if _likely:
        return (0.50, "api_hashing_suspected")
    if _count > 3:
        return (0.20, "minor_import_anomalies")
    return (0.0, "normal_imports")


def _entropy_string_mismatch(
    entropy_profile: Dict,
    string_density: float,
    layout_anomaly: float,
) -> Tuple[float, str]:
    """高熵段中低字符串密度 → 字符串可能被加密存储。"""
    _high_ent = entropy_profile.get("high_window_ratio", 0.0) if entropy_profile else 0.0
    _mean_ent = entropy_profile.get("mean_entropy", 0.0) if entropy_profile else 0.0

    # 正常: 高熵段自然含有不可打印数据，可打印字符串集中在低熵段
    # 异常: 整体高熵 (>6.5) 且几乎无字符串 → 编译级的字符串加密
    if _mean_ent > 6.5 and string_density < 0.01:
        return (0.85, "full_string_encryption_likely")
    if _mean_ent > 5.5 and string_density < 0.02 and layout_anomaly > 0.4:
        return (0.60, "partial_string_obfuscation")
    if _high_ent > 0.5 and string_density < 0.03:
        return (0.35, "entropy_string_mismatch")
    return (0.0, "consistent")


def _control_flow_anomaly_score(
    function_count: int,
    total_sections: int,
    code_section_ratio: float,
) -> Tuple[float, str]:
    """控制流平坦化 / 代码膨胀迹象。
    异常高的代码段比例 + 大量小函数 → 可能的控制流混淆。
    """
    if function_count < 10 or total_sections == 0:
        return (0.0, "insufficient_data")

    # 每段的平均函数数。正常 < 200，混淆器通常 > 500
    _func_per_section = function_count / max(total_sections, 1)

    if _func_per_section > 800 and code_section_ratio > 0.6:
        return (0.65, "control_flow_flattening_suspected")
    if _func_per_section > 400:
        return (0.30, "elevated_function_density")
    return (0.0, "normal")


def _anti_analysis_score(
    api_hashing: Dict,
    xor_obfuscation: Dict,
    shellcode: Dict,
) -> Tuple[float, str]:
    """反静态分析技术联合评分。"""
    _score = 0.0
    _signals = []

    if api_hashing.get("likely_api_hashing"):
        _score += 0.30
        _signals.append("api_hashing")
    if xor_obfuscation.get("xor_obfuscation_likely"):
        _score += 0.25
        _signals.append("xor_obfuscation")
    if shellcode.get("pattern_count", 0) >= 2:
        _score += 0.15
        _signals.append("shellcode_patterns")

    if _score >= 0.55:
        return (_score, f"multi_technique_anti_analysis:{'+'.join(_signals)}")
    if _score >= 0.25:
        return (_score, f"single_technique:{'+'.join(_signals)}")
    return (_score, "no_anti_analysis_detected" if not _signals else f"minor:{'+'.join(_signals)}")


def assess_evasion_susceptibility(
    api_detection_confidence: float = 0.0,
    string_detection_confidence: float = 0.0,
    import_anomaly: Dict = None,
    entropy_profile: Dict = None,
    string_density: float = 0.0,
    layout_anomaly: float = 0.0,
    function_count: int = 0,
    total_sections: int = 0,
    code_section_ratio: float = 0.0,
    api_hashing: Dict = None,
    xor_obfuscation: Dict = None,
    shellcode: Dict = None,
) -> Dict:
    """对抗逃逸易感性评估主入口。

    返回:
    - evasion_score: 综合逃逸易感性 (0-1, 高=更可能使用了逃逸技术)
    - evasion_techniques: 推断的逃逸技术列表
    - signal_gaps: 各维度的信号不一致性详情
    - overall_assessment: HIGH_EVASION / MODERATE / LOW / NONE
    """
    _results = {}

    _gap_score, _gap_label = _signal_gap_score(
        api_detection_confidence, string_detection_confidence)
    _results["string_api_gap"] = {
        "score": round(_gap_score, 4),
        "label": _gap_label,
        "api_confidence": api_detection_confidence,
        "string_confidence": string_detection_confidence,
    }

    _import_score, _import_label = _import_anomaly_score(import_anomaly or {})
    _results["import_anomaly"] = {
        "score": round(_import_score, 4),
        "label": _import_label,
    }

    _ent_score, _ent_label = _entropy_string_mismatch(
        entropy_profile or {}, string_density, layout_anomaly)
    _results["entropy_string_mismatch"] = {
        "score": round(_ent_score, 4),
        "label": _ent_label,
        "mean_entropy": entropy_profile.get("mean_entropy", 0.0) if entropy_profile else 0.0,
        "string_density": string_density,
    }

    _cfg_score, _cfg_label = _control_flow_anomaly_score(
        function_count, total_sections, code_section_ratio)
    _results["control_flow_anomaly"] = {
        "score": round(_cfg_score, 4),
        "label": _cfg_label,
    }

    _aa_score, _aa_label = _anti_analysis_score(
        api_hashing or {}, xor_obfuscation or {}, shellcode or {})
    _results["anti_analysis"] = {
        "score": round(_aa_score, 4),
        "label": _aa_label,
    }

    # 加权合成总分
    _weights = {
        "string_api_gap": 0.30,
        "import_anomaly": 0.20,
        "entropy_string_mismatch": 0.25,
        "control_flow_anomaly": 0.15,
        "anti_analysis": 0.10,
    }

    _total = sum(
        _results[k]["score"] * w
        for k, w in _weights.items()
    )

    # 推断的具体逃逸技术
    _techniques = []
    if _gap_score > 0.4:
        _techniques.append("string_encryption")
    if _import_score > 0.4:
        _techniques.append("api_hashing")
    if _ent_score > 0.5:
        _techniques.append("full_payload_encryption")
    if _cfg_score > 0.4:
        _techniques.append("control_flow_flattening")
    if _aa_score > 0.3:
        if api_hashing and api_hashing.get("likely_api_hashing"):
            _techniques.append("resolve_by_hash")
        if xor_obfuscation and xor_obfuscation.get("xor_obfuscation_likely"):
            _techniques.append("xor_encoding")

    if _total >= 0.55:
        _assessment = "HIGH_EVASION"
    elif _total >= 0.30:
        _assessment = "MODERATE_EVASION"
    elif _total >= 0.15:
        _assessment = "LOW_EVASION"
    else:
        _assessment = "NO_EVASION_DETECTED"

    return {
        "evasion_score": round(_total, 4),
        "assessment": _assessment,
        "inferred_techniques": _techniques,
        "technique_count": len(_techniques),
        "signal_details": _results,
    }


def quick_assess_from_binary_info(binary_info: Dict) -> Dict:
    """便捷入口：从 binary_info 字典中自动提取所有信号并评估。
    适合集成到现有分析管线中。
    """
    _imports = binary_info.get("imports", {})
    _dangerous = []
    if isinstance(_imports, dict):
        _dangerous = _imports.get("dangerous_functions", [])
        _all_imps = _imports.get("all_imports", _imports)

    _total_imp = sum(len(v) for v in _all_imps.values()) if isinstance(_all_imps, dict) else 0
    _api_conf = min(len(_dangerous) / max(_total_imp, 1) * 5.0, 1.0) if _total_imp > 0 else 0.0

    _strings = binary_info.get("key_strings", binary_info.get("strings", []))
    _total_str = len(_strings)
    _key_str = sum(1 for s in _strings if isinstance(s, str) and len(s) > 4)
    _str_conf = min(_key_str / max(_total_str, 1) * 3.0, 1.0) if _total_str > 0 else 0.0

    _entropy = binary_info.get("entropy", {})
    _layout_anomaly = binary_info.get("suspicious_packing", False)
    _layout_score = 0.6 if _layout_anomaly else 0.1

    _functions = binary_info.get("functions", [])
    _sections = binary_info.get("sections", [])
    _code_sz = sum(s.get("size", s.get("vmsize", 0))
                   for s in _sections
                   if s.get("name", "") in (".text", "CODE", "__TEXT"))
    _total_sz = sum(s.get("size", s.get("vmsize", 0)) for s in _sections)

    _api_hash = binary_info.get("api_hashing", {})
    _xor = binary_info.get("xor_obfuscation", {})
    _sc = binary_info.get("shellcode_analysis", {})

    return assess_evasion_susceptibility(
        api_detection_confidence=_api_conf,
        string_detection_confidence=_str_conf,
        import_anomaly=binary_info.get("import_anomaly"),
        entropy_profile=_entropy,
        string_density=_key_str / max(binary_info.get("size", 1), 1),
        layout_anomaly=_layout_score,
        function_count=len(_functions),
        total_sections=len(_sections),
        code_section_ratio=_code_sz / max(_total_sz, 1),
        api_hashing=_api_hash,
        xor_obfuscation=_xor,
        shellcode=_sc,
    )
