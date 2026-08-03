# posture_pipeline — 态势分析管线胶水层
# 将 protection_interaction / segment_risk / security_posture 串联到 binary_info 输出
# 职责仅限数据流转发，不含分析逻辑

from typing import Dict, Any, Optional

from . import protection_interaction as pi
from . import segment_risk as sr
from . import security_posture as sp


def extract_protections_from_checksec(checksec: Dict[str, Any], fmt: str) -> Dict[str, bool]:
    """异构 checksec 字典 → 标准化布尔保护映射。
    兼容 ELF (nx/pie/relro/canary)、PE (characteristics)、Mach-O (load command flags)。
    """
    _prot: Dict[str, bool] = {}
    if fmt == "ELF":
        _prot["NX"] = checksec.get("nx", False) is True
        _prot["PIE"] = checksec.get("pie", False) is True
        _prot["CANARY"] = checksec.get("canary", False) is True
        _relro = str(checksec.get("relro", "")).lower()
        _prot["RELRO_FULL"] = _relro in ("full", "full relro")
        _prot["RELRO_PART"] = _relro in ("partial", "partial relro")
        _prot["FORTIFY"] = checksec.get("fortify", False) is True
        _prot["NOEXECSTACK"] = checksec.get("noexecstack", True) is True
    elif fmt == "PE":
        _prot["DEP"] = checksec.get("nx", checksec.get("dep", False)) is True
        _prot["ASLR"] = checksec.get("aslr", checksec.get("pie", False)) is True
        _prot["CFG"] = checksec.get("cfg", False) is True
        _prot["GS"] = checksec.get("gs", checksec.get("canary", False)) is True
        _prot["SAFESEH"] = checksec.get("safeseh", False) is True
        _prot["HIGHENTROPYVA"] = checksec.get("highentropyva", False) is True
    elif fmt == "MACHO":
        _prot["MACHO_NX"] = checksec.get("nx", True) is True
        _prot["MACHO_PIE"] = checksec.get("pie", False) is True
        _prot["MACHO_CANARY"] = checksec.get("canary", False) is True
        _prot["MACHO_ARC"] = checksec.get("arc", False) is True
        _prot["MACHO_ENCRYPTED"] = checksec.get("encrypted", False) is True

    return _prot


def run_posture_analysis(binary_info: Dict[str, Any]) -> Dict[str, Any]:
    """对 binary_info 输出执行完整态势分析。
    依次调用保护交互/段风险/态势向量三个模块，聚合到 posture 键。
    任一模块失败则静默替换为 error 字典，不中断整体流程。
    """
    _fmt = binary_info.get("format", "UNKNOWN")
    if _fmt not in ("ELF", "PE", "MACHO"):
        return {"posture_analysis": {"error": f"unsupported_format:{_fmt}"}}

    _checksec = binary_info.get("checksec", {})
    _sections = binary_info.get("sections", [])
    _subsystem = binary_info.get("subsystem")

    _protections = extract_protections_from_checksec(_checksec, _fmt)

    try:
        _interaction = pi.compute_interaction_score(_protections, _fmt)
    except Exception:
        _interaction = {"error": "protection_interaction_failed"}

    try:
        _seg_risk = sr.compute_segment_risk(
            _sections, _fmt,
            image_base=binary_info.get("image_base", 0),
        )
    except Exception:
        _seg_risk = {"error": "segment_risk_analysis_failed"}

    try:
        _posture = sp.compute_posture_vector(
            _protections, _fmt, subsystem=_subsystem,
        )
    except Exception:
        _posture = {"error": "posture_vector_failed"}

    return {
        "protection_interaction": _interaction,
        "segment_risk": _seg_risk,
        "security_posture": _posture,
    }
