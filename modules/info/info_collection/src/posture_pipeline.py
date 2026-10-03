# posture_pipeline — 态势分析管线胶水层
# 将 protection_interaction / segment_risk / security_posture 串联到 binary_info 输出
# 职责仅限数据流转发，不含分析逻辑
#
# v2 扩展: 集成四个专利级分析模块
# cfg_entropy_fingerprint: 多尺度 CFG 结构熵指纹
#   - exploit_chain_inference: Markov 链 exploit 路径推断
# posture_regression: 跨版本安全态势退化检测
# entropy_gradient_profiler: 字节级熵梯度多层混淆检测

from typing import Dict, Any, Optional, List

from . import protection_interaction as pi
from . import segment_risk as sr
from . import security_posture as sp
from . import cfg_entropy_fingerprint as cef
from . import exploit_chain_inference as eci
from . import entropy_gradient_profiler as egp
from . import posture_regression as pr


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


def run_extended_analysis(
    binary_info: Dict[str, Any],
    binary_path: str = "",
    functions: List[Dict] = None,
) -> Dict[str, Any]:
    """扩展分析：CFG 指纹 + exploit 链推断 + 熵梯度分析。
    在 run_posture_analysis 基础上叠加专利级创新模块。
    binary_path 用于需要直接读文件的模块（熵梯度）。
    """
    _result: Dict[str, Any] = {}

    # 1. CFG 结构熵指纹
    try:
        _result["cfg_fingerprint"] = cef.compute_cfg_fingerprint(
            binary_info,
            functions=functions,
            imports=binary_info.get("imports"),
            sections=binary_info.get("sections"),
        )
    except Exception:
        _result["cfg_fingerprint"] = {"error": "cfg_fingerprint_failed"}

    # 2. exploit 原语链推断 — 依赖 protection_interaction 和 segment_risk
    #    先就地计算所需子结果，不假设调用方已运行 run_posture_analysis
    _fmt = binary_info.get("format", "UNKNOWN")
    _checksec = binary_info.get("checksec", {})
    _sections = binary_info.get("sections", [])

    try:
        _protections = extract_protections_from_checksec(_checksec, _fmt)
        _interaction = pi.compute_interaction_score(_protections, _fmt)
        _seg_risk = sr.compute_segment_risk(_sections, _fmt)
    except Exception:
        _interaction = {}
        _seg_risk = {}

    try:
        _result["exploit_chain"] = eci.infer_exploit_chain(
            binary_info,
            interaction_score=_interaction,
            segment_risk=_seg_risk,
        )
    except Exception:
        _result["exploit_chain"] = {"error": "exploit_chain_inference_failed"}

    # 3. 熵梯度混淆检测 — 需要直接读文件
    if binary_path:
        try:
            _result["entropy_gradient"] = egp.profile_entropy_gradient(binary_path)
        except Exception:
            _result["entropy_gradient"] = {"error": "entropy_gradient_analysis_failed"}
    else:
        _result["entropy_gradient"] = {"skipped": "no_binary_path_provided"}

    # 聚合扩展评分
    _result["extended_summary"] = _build_extended_summary(_result)

    return _result


def run_regression_analysis(
    prev_binary_info: Dict[str, Any],
    curr_binary_info: Dict[str, Any],
    prev_functions: List[Dict] = None,
    curr_functions: List[Dict] = None,
) -> Dict[str, Any]:
    """跨版本安全态势退化检测。
    对两个版本分别运行完整分析管线后比较结果。
    """
    # 分别计算扩展分析
    _prev_ext = run_extended_analysis(prev_binary_info, functions=prev_functions)
    _curr_ext = run_extended_analysis(curr_binary_info, functions=curr_functions)

    # 段风险分析
    _fmt = prev_binary_info.get("format", "UNKNOWN")
    try:
        _prev_checksec = prev_binary_info.get("checksec", {})
        _curr_checksec = curr_binary_info.get("checksec", {})
        _prev_prot = extract_protections_from_checksec(_prev_checksec, _fmt)
        _curr_prot = extract_protections_from_checksec(_curr_checksec, _fmt)
        _prev_seg = sr.compute_segment_risk(prev_binary_info.get("sections", []), _fmt)
        _curr_seg = sr.compute_segment_risk(curr_binary_info.get("sections", []), _fmt)
    except Exception:
        _prev_seg = {}
        _curr_seg = {}

    try:
        _regression = pr.detect_posture_regression(
            prev_binary_info,
            curr_binary_info,
            prev_segment_risk=_prev_seg,
            curr_segment_risk=_curr_seg,
            prev_cfg_fingerprint=_prev_ext.get("cfg_fingerprint"),
            curr_cfg_fingerprint=_curr_ext.get("cfg_fingerprint"),
        )
    except Exception:
        _regression = {"error": "regression_detection_failed"}

    return {
        "regression": _regression,
        "previous_version_extended": _prev_ext,
        "current_version_extended": _curr_ext,
    }


def _build_extended_summary(extended: Dict[str, Any]) -> Dict[str, Any]:
    """从扩展分析结果中提取关键指标，用于快速概览。"""
    _summary: Dict[str, Any] = {}

    _cfp = extended.get("cfg_fingerprint", {})
    if "error" not in _cfp:
        _summary["fingerprint_id"] = _cfp.get("fingerprint_id")
        _summary["composite_score"] = _cfp.get("composite_score")
        _summary["layout_anomaly"] = (
            _cfp.get("section_entropy", {}).get("layout_anomaly_score")
        )

    _ec = extended.get("exploit_chain", {})
    if "error" not in _ec:
        _summary["exploitability_index"] = _ec.get("exploitability_index")
        _summary["reachable_state"] = _ec.get("reachable_state")
        _summary["shortest_path_steps"] = (
            _ec.get("shortest_path_to_code_execution", {}).get("steps")
        )

    _eg = extended.get("entropy_gradient", {})
    if "error" not in _eg and "skipped" not in _eg:
        _summary["obfuscation_confidence"] = _eg.get("obfuscation_confidence")
        _summary["layer_count_estimate"] = (
            _eg.get("coarse_analysis", {}).get("layer_count_estimate")
        )
        _summary["obfuscation_type"] = _eg.get("obfuscation_type")

    return _summary
