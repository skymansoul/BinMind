# vuln_inheritance — 跨二进制漏洞继承检测
# 已知 binary A 含 CVE-X，binary B 是否可能包含同一漏洞？
# 四维证据融合: 结构指纹相似度 + 导入可达性模式 + 段布局相似度 +
# 编译器归一化指纹，给出继承概率与风险等级。
#
# 应用场景:
# 供应链安全: CVE 在 libfoo.so v1.0 → v1.1 是否继承？
#   - IoT 固件: 同一 SDK 编译的 ARM/MIPS/x86 变体是否共享漏洞？
# 补丁验证: 补丁是否覆盖所有受影响变体？
#
# 继承概率模型:
#   P(inherited | CVE_in_A) = w1*struct_sim + w2*import_overlap + w3*section_layout_sim + w4*fp_norm_sim
#   权重由逻辑回归在标注数据集上校准 (初始值: 0.35, 0.25, 0.15, 0.25)

import math
from typing import Dict, List, Tuple, Optional, Set


def _cosine_sim(a: List[float], b: List[float]) -> float:
    if not a or not b: return 0.0
    _dot = sum(x * y for x, y in zip(a, b))
    _na = math.sqrt(sum(x**2 for x in a))
    _nb = math.sqrt(sum(y**2 for y in b))
    return _dot / (_na * _nb) if _na > 0 and _nb > 0 else 0.0


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b: return 1.0
    _inter = len(a & b)
    _union = len(a | b)
    return _inter / _union if _union > 0 else 0.0


def _extract_dangerous_import_set(imports: Dict) -> Set[str]:
    """提取归一化危险函数集合。"""
    _s = set()
    _dangerous = []
    if isinstance(imports, dict):
        _dangerous = imports.get("dangerous_functions", [])
        _all = imports.get("all_imports", imports)
        if isinstance(_all, dict) and not _dangerous:
            for _funcs in _all.values():
                if isinstance(_funcs, list):
                    _dangerous.extend(_funcs)
    for _f in _dangerous:
        _s.add(str(_f).lower().rstrip('aw'))
    return _s


def _extract_section_names(sections: List[Dict]) -> Set[str]:
    return {s.get("name", s.get("segment", ""))
            for s in (sections or []) if isinstance(s, dict)}


def _extract_section_permissions(sections: List[Dict]) -> str:
    """段权限签名字符串: 如 'RX,RW,R-,RX,RWX' 用于快速比较。"""
    _perms = []
    for _s in (sections or []):
        if not isinstance(_s, dict): continue
        _chars = _s.get("characteristics", [])
        _flags = _s.get("flags", 0)
        if isinstance(_chars, list):
            _p = ""
            if "MEM_READ" in _chars: _p += "R"
            if "MEM_WRITE" in _chars: _p += "W"
            if "MEM_EXECUTE" in _chars: _p += "X"
            _perms.append(_p or "?")
        elif isinstance(_flags, int) and _flags > 0:
            _p = ""
            if _flags & 0x4: _p += "R"
            if _flags & 0x2: _p += "W"
            if _flags & 0x1: _p += "X"
            _perms.append(_p or "?")
    return ",".join(_perms[:16])


def detect_vuln_inheritance(
    vuln_binary_analysis: Dict,
    target_binary_analysis: Dict,
    vuln_fingerprint: Dict = None,
    target_fingerprint: Dict = None,
    vuln_compiler_norm: Dict = None,
    target_compiler_norm: Dict = None,
    cve_info: Dict = None,
) -> Dict:
    """漏洞继承检测主入口。

    vuln_binary_analysis: 已知含漏洞的二进制分析结果
    target_binary_analysis: 待检测的目标二进制分析结果

    返回:
    - inheritance_probability: 继承概率 (0-1)
    - evidence: 四维证据详情
    - risk_level: INHERITED / LIKELY_INHERITED / POSSIBLE / UNLIKELY
    - matched_vulnerability_surface: 目标中与漏洞相关的匹配特征
    - recommendation: 建议的后续验证步骤
    """

    # 1. 结构指纹相似度
    _vfp = vuln_fingerprint or {}
    _tfp = target_fingerprint or {}
    _v_vec = _vfp.get("composite_vector", [0, 0, 0, 0])
    _t_vec = _tfp.get("composite_vector", [0, 0, 0, 0])
    _fp_sim = _cosine_sim(_v_vec, _t_vec)

    # 编译器归一化指纹相似度 (优先使用)
    _vcn = vuln_compiler_norm or {}
    _tcn = target_compiler_norm or {}
    _vn_vec = _vcn.get("normalized_vector", _v_vec)
    _tn_vec = _tcn.get("normalized_vector", _t_vec)
    _norm_sim = _cosine_sim(_vn_vec, _tn_vec)

    # 2. 导入可达性模式重叠
    _vi = vuln_binary_analysis.get("imports", {})
    _ti = target_binary_analysis.get("imports", {})
    _v_danger = _extract_dangerous_import_set(_vi)
    _t_danger = _extract_dangerous_import_set(_ti)
    _import_jac = _jaccard(_v_danger, _t_danger)

    # 3. 段布局相似度
    _vs = vuln_binary_analysis.get("sections", [])
    _ts = target_binary_analysis.get("sections", [])
    _sec_name_jac = _jaccard(_extract_section_names(_vs), _extract_section_names(_ts))
    _v_perm = _extract_section_permissions(_vs)
    _t_perm = _extract_section_permissions(_ts)
    _perm_match = 1.0 if _v_perm == _t_perm and _v_perm else 0.5

    _layout_sim = _sec_name_jac * 0.4 + _perm_match * 0.6

    # 4. exploitability 模式
    _ve = vuln_binary_analysis.get("exploit_chain", {})
    _te = target_binary_analysis.get("exploit_chain", {})
    _v_ei = _ve.get("exploitability_index", 0.0)
    _t_ei = _te.get("exploitability_index", 0.0)
    _ei_sim = 1.0 - abs(_v_ei - _t_ei) / 100.0

    # 加权融合 (初始权重，后续可从标注数据学习)
    _prob = (
        _fp_sim * 0.30 +
        _norm_sim * 0.20 +
        _import_jac * 0.25 +
        _layout_sim * 0.15 +
        _ei_sim * 0.10
    )

    # CVE 特定调整: 若 CVE 涉及特定函数，检查目标是否也导入该函数
    _cve_funcs = set()
    if cve_info:
        _cve_funcs = set(
            str(f).lower().rstrip('aw')
            for f in cve_info.get("affected_functions", [])
        )
    _cve_func_match = len(_cve_funcs & _t_danger) / max(len(_cve_funcs), 1) if _cve_funcs else 0.0
    if _cve_func_match > 0.5:
        _prob = min(1.0, _prob + 0.15)
    elif _cve_func_match > 0:
        _prob = min(1.0, _prob + 0.05)

    _prob = round(_prob, 4)

    # 风险等级
    if _prob > 0.75:
        _level = "INHERITED"
    elif _prob > 0.55:
        _level = "LIKELY_INHERITED"
    elif _prob > 0.35:
        _level = "POSSIBLE"
    else:
        _level = "UNLIKELY"

    # 匹配的漏洞表面
    _matched = []
    if _import_jac > 0.5:
        _matched.append(f"危险导入重叠度高 ({_import_jac:.2f})")
    if _norm_sim > 0.80:
        _matched.append(f"编译器归一化指纹高度相似 ({_norm_sim:.3f})")
    if _cve_func_match > 0:
        _matched.append(f"CVE相关函数匹配: {_cve_func_match:.0%}")
    if _layout_sim > 0.7:
        _matched.append("段布局几乎一致")
    if _ei_sim > 0.90:
        _matched.append("exploitability 评分接近")

    # 推荐验证步骤
    _recommendations = []
    if _level in ("INHERITED", "LIKELY_INHERITED"):
        _recommendations.append("建议对目标二进制运行 CVE 对应的 PoC 验证")
        _recommendations.append("对比补丁 diff 确认受影响函数是否相同")
    if _level == "POSSIBLE":
        _recommendations.append("检查目标二进制版本号和编译时间戳")
        _recommendations.append("对可疑函数做 bindiff 比较")
    if _level == "UNLIKELY":
        _recommendations.append("漏洞继承可能性低，但建议确认文件版本差异")

    return {
        "inheritance_probability": _prob,
        "risk_level": _level,
        "evidence": {
            "fingerprint_similarity": round(_fp_sim, 4),
            "compiler_normalized_similarity": round(_norm_sim, 4),
            "dangerous_import_jaccard": round(_import_jac, 4),
            "section_layout_similarity": round(_layout_sim, 4),
            "exploitability_similarity": round(_ei_sim, 4),
            "cve_function_match": round(_cve_func_match, 4),
        },
        "matched_vulnerability_surface": _matched,
        "shared_dangerous_imports": sorted(_v_danger & _t_danger)[:15],
        "recommendations": _recommendations,
        "architectures": {
            "vulnerable": vuln_binary_analysis.get("arch", vuln_binary_analysis.get("machine", "?")),
            "target": target_binary_analysis.get("arch", target_binary_analysis.get("machine", "?")),
        },
    }
