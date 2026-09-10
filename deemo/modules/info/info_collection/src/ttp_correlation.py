# ttp_correlation — TTP 杀链关联与贝叶斯置信传播
# 将独立检测到的各 TTP 映射到 MITRE ATT&CK 杀链阶段，
# 利用阶段内条件概率表进行置信增强：同一阶段多 TTP 共存 → 单个 TTP 置信度上调。
#
# 现有杀链方案从 CTI 文本推断 (偏重语义理解); 本模块从二进制静态特征推断。
# GNN 归因用图神经网络做 APT 归因; 本模块用轻量贝叶斯网络, 零训练数据,
# 仅需 ATT&CK 共现统计先验。
#
# 流程:
#   1. TTP→杀链阶段映射（基于 MITRE ATT&CK 标准）
#   2. 同阶段 TTP 间的条件增强（若 A 和 B 同属 Execution 阶段且 A 被检出，
#      B 的置信度按条件概率 P(B|A) 上调）
#   3. 跨阶段顺序一致性加分（Recon→Resource→Execution→Persistence→C2→Exfil
#      的正向序列比孤立 Detection 阶段命中更可信）

import math
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict


# MITRE ATT&CK 杀链阶段 (简化 7 阶段)
_KILL_CHAIN_PHASES = [
    "reconnaissance",
    "resource_development",
    "execution",
    "persistence",
    "defense_evasion",
    "lateral_movement",
    "exfiltration",
]


# TTP → 杀链阶段映射（从 ATT&CK 技术 ID 推导）
# 一个 TTP 可能属于多个阶段（如 process_hollowing 既是 execution 也是 defense_evasion）
_TTP_PHASE_MAP: Dict[str, List[str]] = {
    # 注入技术 → Execution + Defense Evasion
    "pe_injection": ["execution", "defense_evasion"],
    "process_hollowing": ["execution", "defense_evasion"],
    "reflective_dll": ["execution", "defense_evasion"],
    "apc_injection": ["execution", "defense_evasion"],
    "thread_hijacking": ["execution", "defense_evasion"],
    "atom_bombing": ["execution", "defense_evasion"],
    "process_doppelganging": ["execution", "defense_evasion"],
    "early_bird_apc": ["execution", "defense_evasion"],
    "setwindowshookex": ["execution"],
    "extra_window_memory": ["execution", "defense_evasion"],

    # 持久化
    "registry_run_key": ["persistence"],
    "service_persistence": ["persistence"],
    "scheduled_task": ["persistence", "execution"],
    "wmi_event_subscription": ["persistence"],
    "startup_folder": ["persistence"],
    "com_hijacking": ["persistence", "defense_evasion"],
    "cron_persistence": ["persistence"],
    "systemd_persistence": ["persistence"],
    "rc_script_persistence": ["persistence"],
    "shell_rc_modification": ["persistence"],
    "ld_preload": ["persistence", "defense_evasion"],
    "launchd_persistence": ["persistence"],

    # 横向移动
    "wmi": ["lateral_movement", "execution"],
    "psexec": ["lateral_movement", "execution"],
    "schtasks": ["lateral_movement", "execution"],
    "winrm": ["lateral_movement", "execution"],
    "dcom": ["lateral_movement", "execution"],
    "rdp": ["lateral_movement"],
    "smb": ["lateral_movement"],
    "ssh": ["lateral_movement"],
    "passthehash": ["lateral_movement", "defense_evasion"],

    # 凭据访问
    "credential_dumping": ["defense_evasion"],
    "token_manipulation": ["defense_evasion", "execution"],

    # 伪装
    "ppid_spoofing": ["defense_evasion"],
    "runpe": ["execution", "defense_evasion"],
    "parent_child_anomaly": ["execution"],
}


# 同阶段 TTP 条件概率增强矩阵 (P(B_detected | A_detected))
# 值基于 APT 报告中的共现频率估计，范围 [0.0, 1.0]
# 仅存储 P > 0.3 的非平凡关系
_CORRELATION_BOOST: Dict[Tuple[str, str], float] = {
    # Execution 阶段内的共现
    ("process_hollowing", "pe_injection"): 0.45,
    ("pe_injection", "process_hollowing"): 0.40,
    ("apc_injection", "early_bird_apc"): 0.55,
    ("early_bird_apc", "apc_injection"): 0.50,
    ("reflective_dll", "process_hollowing"): 0.38,
    ("process_hollowing", "reflective_dll"): 0.35,

    # Persistence ↔ Execution (持久化常与执行技术配对)
    ("service_persistence", "pe_injection"): 0.42,
    ("scheduled_task", "process_hollowing"): 0.38,
    ("wmi_event_subscription", "wmi"): 0.52,
    ("registry_run_key", "process_hollowing"): 0.32,

    # Lateral Movement 共现
    ("psexec", "smb"): 0.65,
    ("smb", "psexec"): 0.60,
    ("wmi", "psexec"): 0.48,
    ("winrm", "wmi"): 0.35,

    # Credential Dumping 与其他
    ("credential_dumping", "passthehash"): 0.70,
    ("passthehash", "credential_dumping"): 0.65,
    ("credential_dumping", "token_manipulation"): 0.55,
    ("token_manipulation", "credential_dumping"): 0.50,
}


def _bayesian_boost(
    base_confidence: float,
    correlated_confidence: float,
    boost_factor: float,
) -> float:
    """条件概率贝叶斯增强: P(A|B) = P(A) + (1-P(A)) * P(B|A) * P(B)
    boost_factor 对应 P(B|A)，correlated_confidence 对应 P(B)。
    当关联 TTP 的置信度低时增强幅度自动衰减。
    """
    if base_confidence >= 0.95:
        return base_confidence
    _boost = (1.0 - base_confidence) * boost_factor * correlated_confidence
    return min(base_confidence + _boost * 0.5, 0.95)


def correlate_ttps(
    detection_results: Dict[str, Dict],
    top_n: int = 5,
) -> Dict:
    """对多个检测器的输出做 TTP 关联分析。
    detection_results: {detector_name: {findings: {tech_name: {detected, confidence, ...}}}}
    或扁平的 {tech_name: {detected, confidence, ...}}

    输出:
    - enhanced_findings: 贝叶斯增强后的各 TTP 置信度
    - phase_distribution: 各杀链阶段被命中的 TTP 数量与加权置信度
    - kill_chain_completeness: 杀链覆盖完整度评分 (0-1)
    - sequential_consistency: 跨阶段序列一致性加分
    - correlated_pairs: 实际触发的关联对
    """
    # 归一化输入格式
    _flat: Dict[str, Dict] = {}
    for _key, _val in detection_results.items():
        if isinstance(_val, dict):
            if "findings" in _val:
                for _tname, _tres in _val["findings"].items():
                    if isinstance(_tres, dict):
                        _flat[_tname] = _tres
            elif "detected" in _val or "confidence" in _val:
                _flat[_key] = _val

    _detected = {
        name: res for name, res in _flat.items()
        if res.get("detected") and res.get("confidence", 0) > 0.15
    }

    if not _detected:
        return {
            "enhanced_findings": {},
            "phase_distribution": {},
            "kill_chain_completeness": 0.0,
            "sequential_consistency": 0.0,
            "correlated_pairs": [],
            "verdict": "no_detections",
        }

    # 杀链阶段分布
    _phase_hits: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
    for _tname, _tres in _detected.items():
        _phases = _TTP_PHASE_MAP.get(_tname, ["unknown"])
        for _ph in _phases:
            _phase_hits[_ph].append((_tname, _tres.get("confidence", 0.3)))

    # 贝叶斯增强：遍历所有 TTP 对
    _enhanced = {}
    for _tname, _tres in _detected.items():
        _enhanced[_tname] = dict(_tres)
        _enhanced[_tname]["original_confidence"] = _tres.get("confidence", 0.3)

    _correlated_pairs = []
    _tech_names = list(_detected.keys())
    for _i, _ta in enumerate(_tech_names):
        for _tb in _tech_names[_i + 1:]:
            _boost_ab = _CORRELATION_BOOST.get((_ta, _tb), 0.0)
            _boost_ba = _CORRELATION_BOOST.get((_tb, _ta), 0.0)
            if _boost_ab > 0.25 or _boost_ba > 0.25:
                _conf_a = _detected[_ta].get("confidence", 0.3)
                _conf_b = _detected[_tb].get("confidence", 0.3)

                _new_a = _bayesian_boost(_conf_a, _conf_b, max(_boost_ab, _boost_ba))
                _new_b = _bayesian_boost(_conf_b, _conf_a, max(_boost_ab, _boost_ba))

                if abs(_new_a - _conf_a) > 0.02 or abs(_new_b - _conf_b) > 0.02:
                    _correlated_pairs.append({
                        "ttp_a": _ta, "ttp_b": _tb,
                        "boost_ab": _boost_ab, "boost_ba": _boost_ba,
                        "confidence_a_before": round(_conf_a, 3),
                        "confidence_a_after": round(_new_a, 3),
                        "confidence_b_before": round(_conf_b, 3),
                        "confidence_b_after": round(_new_b, 3),
                    })
                    _enhanced[_ta]["confidence"] = _new_a
                    _enhanced[_tb]["confidence"] = _new_b

    # 杀链完整度：被命中的阶段数 / 总阶段数
    _covered_phases = set(_phase_hits.keys()) - {"unknown"}
    _completeness = len(_covered_phases) / len(_KILL_CHAIN_PHASES)

    # 跨阶段序列一致性
    _seq_score = _compute_sequence_consistency(_phase_hits)

    # 阶段分布摘要
    _phase_dist = {}
    for _ph in _KILL_CHAIN_PHASES:
        _hits = _phase_hits.get(_ph, [])
        if _hits:
            _phase_dist[_ph] = {
                "ttp_count": len(_hits),
                "weighted_confidence": round(
                    sum(c for _, c in _hits) / len(_hits), 3),
                "ttps": [t for t, _ in _hits],
            }

    # 综合判定
    _total_boosted = sum(
        e.get("confidence", e.get("original_confidence", 0.3))
        for e in _enhanced.values()
    )
    _total_original = sum(
        e.get("original_confidence", e.get("confidence", 0.3))
        for e in _enhanced.values()
    )
    _avg_boost = (_total_boosted - _total_original) / max(len(_enhanced), 1)

    if _completeness >= 0.5 and _avg_boost > 0.05:
        _verdict = "MULTI_STAGE_CAMPAIGN"
    elif _completeness >= 0.3 and _avg_boost > 0.03:
        _verdict = "COORDINATED_ATTACK"
    elif len(_detected) >= 3:
        _verdict = "MULTIPLE_TTPS_DETECTED"
    else:
        _verdict = "ISOLATED_TTP"

    return {
        "enhanced_findings": _enhanced,
        "phase_distribution": _phase_dist,
        "kill_chain_completeness": round(_completeness, 4),
        "sequential_consistency": round(_seq_score, 4),
        "correlated_pairs": _correlated_pairs,
        "average_confidence_boost": round(_avg_boost, 4),
        "boosted_ttp_count": len(_correlated_pairs),
        "verdict": _verdict,
    }


def _compute_sequence_consistency(phase_hits: Dict[str, List]) -> float:
    """计算命中阶段的序列一致性。
    Recon→Resource→Execution→Persistence→C2→Exfil 顺序命中比乱序更可信。
    用相邻命中阶段的顺序匹配率作为评分。
    """
    _hit_phases = [p for p in _KILL_CHAIN_PHASES if p in phase_hits]
    if len(_hit_phases) < 2:
        return 0.0

    _ordered_pairs = 0
    _total_pairs = 0
    for _i, _p1 in enumerate(_hit_phases):
        for _p2 in _hit_phases[_i + 1:]:
            _total_pairs += 1
            _idx1 = _KILL_CHAIN_PHASES.index(_p1)
            _idx2 = _KILL_CHAIN_PHASES.index(_p2)
            if _idx1 < _idx2:
                _ordered_pairs += 1

    return _ordered_pairs / max(_total_pairs, 1)
