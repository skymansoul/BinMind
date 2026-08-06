# Created: 2025-07-27 11:19:42
#
# binary_cti_bridge — 二进制→CTI 威胁 actor 多模态匹配
# TTP重叠(加权) + 结构指纹相似 + 工具链/部门匹配三模态融合
# 解决: 仅34% APT组有独特TTP签名 (Kitten or Panda? 2025)
# 区别于 IEEE TPS-ISA 2024 (仅TTP) 和 ADAPT (文件聚类)

import math
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict


# 已知 APT 组档案 (简化版，生产环境应接入 MITRE ATT&CK STIX / Malpedia)
# 每项: {group_id, aliases, primary_tactics, known_ttps, toolchain_hints, target_sectors}
_ACTOR_PROFILES: List[Dict] = [
    {
        "group_id": "G0007", "name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Sednit"],
        "primary_tactics": ["execution", "persistence", "defense_evasion", "credential_access"],
        "known_ttps": ["T1059.001", "T1059.003", "T1086", "T1055", "T1003", "T1027",
                       "T1566.001", "T1204.002", "T1071.001", "T1105"],
        "toolchain_hints": ["msvc", "gcc_mingw", "custom_packer"],
        "target_sectors": ["government", "military", "defense"],
    },
    {
        "group_id": "G0016", "name": "APT29", "aliases": ["Cozy Bear", "The Dukes"],
        "primary_tactics": ["execution", "persistence", "defense_evasion", "exfiltration"],
        "known_ttps": ["T1059.001", "T1505.003", "T1071.001", "T1041", "T1027",
                       "T1566.001", "T1190", "T1133", "T1090"],
        "toolchain_hints": ["msvc", "csharp", "powershell"],
        "target_sectors": ["government", "diplomatic", "think_tank"],
    },
    {
        "group_id": "G0032", "name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Zinc"],
        "primary_tactics": ["execution", "persistence", "lateral_movement", "exfiltration"],
        "known_ttps": ["T1059.001", "T1055", "T1021.001", "T1021.002", "T1003",
                       "T1486", "T1071.001", "T1203", "T1566.001"],
        "toolchain_hints": ["msvc", "delphi", "custom_crypter"],
        "target_sectors": ["finance", "government", "crypto"],
    },
    {
        "group_id": "G0134", "name": "Mustang Panda", "aliases": ["Bronze President"],
        "primary_tactics": ["execution", "persistence", "defense_evasion"],
        "known_ttps": ["T1059.003", "T1059.001", "T1204.002", "T1055", "T1566.001",
                       "T1071.001", "T1105"],
        "toolchain_hints": ["msvc", "vba", "plugin_loader"],
        "target_sectors": ["government", "ngo", "telecom"],
    },
    {
        "group_id": "G0119", "name": "FIN7", "aliases": ["Carbanak"],
        "primary_tactics": ["execution", "defense_evasion", "exfiltration"],
        "known_ttps": ["T1059.001", "T1218", "T1055", "T1027", "T1071.001",
                       "T1204.002", "T1105", "T1003"],
        "toolchain_hints": ["msvc", "csharp", "obfuscated_js"],
        "target_sectors": ["finance", "hospitality", "retail"],
    },
]


def _jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    if not set_a and not set_b:
        return 0.0
    _intersection = len(set_a & set_b)
    _union = len(set_a | set_b)
    return _intersection / _union if _union > 0 else 0.0


def _weighted_ttp_overlap(
    binary_ttps: Dict[str, float],
    actor_ttps: List[str],
) -> float:
    """加权 TTP 重叠度：每个 TTP 按其检测置信度加权。
    binary_ttps: {technique_name: confidence} — 来自 detector detect_all()
    actor_ttps: 已知 actor 使用的 ATT&CK 技术 ID 列表
    自动通过 _TTP_NAME_TO_ID 做名称→ID 映射。
    """
    if not binary_ttps or not actor_ttps:
        return 0.0
    _actor_set = set(actor_ttps)
    _total_conf = sum(binary_ttps.values())
    if _total_conf == 0:
        return 0.0
    _weighted_overlap = 0.0
    for _tech_name, _conf in binary_ttps.items():
        _tid = _TTP_NAME_TO_ID.get(_tech_name.lower(), "")
        if _tid and _tid in _actor_set:
            _weighted_overlap += _conf
    # 若名称映射失败，直接检查是否与已知 TTP 子串匹配
    if _weighted_overlap == 0.0:
        for _tech_name, _conf in binary_ttps.items():
            for _tid in _actor_set:
                if _tech_name.lower().replace("_", "") in _tid.lower().replace(".", ""):
                    _weighted_overlap += _conf * 0.7
                    break
    return _weighted_overlap / _total_conf


# 检测器技术名 → ATT&CK 技术 ID
_TTP_NAME_TO_ID: Dict[str, str] = {
    "pe_injection": "T1055", "process_hollowing": "T1055.012",
    "reflective_dll": "T1055.001", "apc_injection": "T1055.004",
    "thread_hijacking": "T1055.003", "atom_bombing": "T1055.012",
    "process_doppelganging": "T1055.013", "early_bird_apc": "T1055.004",
    "setwindowshookex": "T1056.004", "extra_window_memory": "T1055.011",
    "runpe": "T1055", "ppid_spoofing": "T1055.012",
    "token_manipulation": "T1134", "parent_child_anomaly": "T1055",
    "wmi": "T1047", "psexec": "T1021.002", "schtasks": "T1053.005",
    "winrm": "T1021.006", "dcom": "T1021.003", "rdp": "T1021.001",
    "smb": "T1021.002", "ssh": "T1021.004",
    "passthehash": "T1550.002", "credential_dumping": "T1003",
    "registry_run_key": "T1547.001", "service_persistence": "T1543.003",
    "scheduled_task": "T1053.005", "wmi_event_subscription": "T1546.003",
    "cron_persistence": "T1053.003", "systemd_persistence": "T1543.002",
    "ld_preload": "T1574.006", "launchd_persistence": "T1543.004",
    "com_hijacking": "T1546.015", "shell_rc_modification": "T1546.004",
}


def _structural_similarity(
    binary_fingerprint: Dict,
    actor_toolchain: List[str],
) -> float:
    """结构指纹与已知工具链的间接相似度。
    不直接比较指纹（因为无 actor 的结构指纹数据库），而是通过
    工具链提示推断相似度：若 binary 的 entropy profile 与
    actor 使用的编译器/打包器特征一致，提升相似度。
    """
    if not binary_fingerprint or not actor_toolchain:
        return 0.0

    _score = 0.0
    _composite = binary_fingerprint.get("composite_score", 0.0)
    _layout_anomaly = binary_fingerprint.get("section_entropy", {}).get(
        "layout_anomaly_score", 0.0)

    # 打包器特征: high layout_anomaly → actor 使用 custom_packer/crypter
    if "custom_packer" in actor_toolchain or "custom_crypter" in actor_toolchain:
        if _layout_anomaly > 0.5:
            _score += 0.30
        elif _layout_anomaly > 0.3:
            _score += 0.15

    # MSVC 特征: 中等的 composite_score + 低 layout_anomaly
    if "msvc" in actor_toolchain:
        if 0.3 < _composite < 0.8 and _layout_anomaly < 0.4:
            _score += 0.20

    # Delphi/C# 特征: 特定的 function entropy 范围
    if "delphi" in actor_toolchain or "csharp" in actor_toolchain:
        _func_ent = binary_fingerprint.get("function_entropy", {}).get(
            "entropy_normalized", 0.0)
        if 0.4 < _func_ent < 0.8:
            _score += 0.20

    return min(_score, 0.50)


def _sector_similarity(
    binary_strings: List[str],
    actor_sectors: List[str],
) -> float:
    """目标部门匹配：binary 字符串中的行业关键词 → actor 目标部门。"""
    if not binary_strings or not actor_sectors:
        return 0.0
    _sector_keywords = {
        "government": ["gov", "政府", "ministry", "federal"],
        "military": ["mil", "army", "defense", "军事", "navy"],
        "finance": ["bank", "finance", "swift", "financial", "银行"],
        "crypto": ["bitcoin", "ethereum", "wallet", "crypto", "区块"],
        "telecom": ["telecom", "5g", "mobile", "通信"],
        "energy": ["oil", "gas", "energy", "power", "石油"],
        "healthcare": ["hospital", "pharma", "health", "医院"],
        "diplomatic": ["embassy", "大使馆", "foreign", "外交"],
    }
    _text = " ".join(str(s).lower() for s in binary_strings)
    _matches = 0
    for _sector in actor_sectors:
        _kws = _sector_keywords.get(_sector, [])
        if any(kw in _text for kw in _kws):
            _matches += 1
    return _matches / max(len(actor_sectors), 1) * 0.20


def match_actors(
    binary_ttps: Dict[str, float],
    binary_fingerprint: Dict = None,
    binary_strings: List[str] = None,
    min_score: float = 0.10,
) -> Dict:
    """多模态 actor 匹配主入口。

    binary_ttps: {TTP_name: confidence} — 来自 ttp_correlation 或 detector detect_all()
    binary_fingerprint: cfg_entropy_fingerprint.compute_cfg_fingerprint() 输出
    binary_strings: 二进制文件中提取的字符串列表

    返回:
    - matches: 按综合得分降序的匹配列表
    - top_match: 最佳匹配 (得分 >= min_score)
    - attribution_confidence: 归因置信度 (综合信号强度)
    - modality_breakdown: 各模态得分明细
    """
    _fingerprint = binary_fingerprint or {}
    _strings = binary_strings or []

    _matches = []
    for _actor in _ACTOR_PROFILES:
        _ttp_score = _weighted_ttp_overlap(binary_ttps, _actor["known_ttps"])
        _struct_score = _structural_similarity(_fingerprint, _actor["toolchain_hints"])
        _sector_score = _sector_similarity(_strings, _actor["target_sectors"])

        # primary_tactics 命中加分
        _tactic_bonus = 0.0
        _binary_tactics = set()
        for _tech in binary_ttps:
            # 从 TTP 名推断 tactic (简化: 按 ATT&CK 映射)
            for _tactic in _actor["primary_tactics"]:
                _tactic_kw = {
                    "execution": ["injection", "exec", "hollowing", "apc", "runpe"],
                    "persistence": ["registry", "service", "cron", "systemd", "launchd"],
                    "defense_evasion": ["hollowing", "doppelganging", "spoofing", "token"],
                    "credential_access": ["credential", "dump", "mimikatz", "passthehash"],
                    "lateral_movement": ["wmi", "psexec", "smb", "ssh", "rdp"],
                    "exfiltration": ["exfil", "c2", "beacon", "tunnel"],
                }
                if any(kw in _tech.lower() for kw in _tactic_kw.get(_tactic, [])):
                    _binary_tactics.add(_tactic)
        _tactic_overlap = _binary_tactics & set(_actor["primary_tactics"])
        if _tactic_overlap:
            _tactic_bonus = len(_tactic_overlap) / max(
                len(_actor["primary_tactics"]), 1) * 0.10

        # 融合: TTP 40%, 结构 30%, 部门 15%, 战术 15%
        _combined = (
            _ttp_score * 0.40 +
            _struct_score * 0.30 +
            _sector_score * 0.15 +
            _tactic_bonus * 0.15
        )

        _matches.append({
            "group_id": _actor["group_id"],
            "name": _actor["name"],
            "aliases": _actor["aliases"],
            "combined_score": round(_combined, 4),
            "ttp_score": round(_ttp_score, 4),
            "structural_score": round(_struct_score, 4),
            "sector_score": round(_sector_score, 4),
            "tactic_bonus": round(_tactic_bonus, 4),
        })

    _matches.sort(key=lambda x: x["combined_score"], reverse=True)

    _top = _matches[0] if _matches else None
    _conf = min(1.0, (_top["combined_score"] * 1.5 if _top and _top["combined_score"] >= min_score else 0.0))

    # 若 top match 与第二名差距 < 0.05，归因置信度降低
    if len(_matches) >= 2 and _top:
        _gap = _top["combined_score"] - _matches[1]["combined_score"]
        if _gap < 0.05:
            _conf *= 0.7
        elif _gap < 0.10:
            _conf *= 0.85

    return {
        "matches": _matches[:5],
        "top_match": _top if (_top and _top["combined_score"] >= min_score) else None,
        "attribution_confidence": round(_conf, 4),
        "verdict": ("HIGH_CONFIDENCE" if _conf > 0.70 else
                    "MODERATE_CONFIDENCE" if _conf > 0.40 else
                    "LOW_CONFIDENCE" if _conf > 0.15 else
                    "INSUFFICIENT_EVIDENCE"),
    }


def quick_match_from_detection_results(
    detection_results: Dict[str, Dict],
    cfg_fingerprint: Dict = None,
    binary_strings: List[str] = None,
) -> Dict:
    """便捷入口：从 detect_all() 输出 + CFG 指纹 + 字符串直接匹配。
    detection_results: 各检测器的 detect_all() 输出字典
    """
    _binary_ttps: Dict[str, float] = {}

    for _dname, _dresult in detection_results.items():
        if not isinstance(_dresult, dict):
            continue
        _findings = _dresult.get("findings", {})
        if isinstance(_findings, dict):
            for _tname, _tres in _findings.items():
                if isinstance(_tres, dict) and _tres.get("detected"):
                    _confidence = _tres.get("confidence", 0.3)
                    _binary_ttps[_tname] = _confidence

    return match_actors(
        binary_ttps=_binary_ttps,
        binary_fingerprint=cfg_fingerprint,
        binary_strings=binary_strings,
    )
