# Created: 2026-05-13 08:47:24
#
# knowledge_transfer — 跨二进制结构知识迁移
# 将已充分分析的参考二进制的后验置信度按结构相似度比例迁移到目标二进制，
# 加速目标的分析收敛 (bootstrap prior → 减少假阴性)。
#
# 核心原理: 若 binary A 和 B 在多维结构空间中高度相似，
# 则 A 的分析结论 (TTP、风险、角色等) 对 B 有预测价值。
# 迁移量 = 参考置信度 × 结构相似度 × 领域衰减因子。
#
# 区别于:
#   - ML embedding transfer (需训练): 本模块使用已构建的结构指纹直接计算相似度
# 独立分析: 每个 binary 从头分析，忽略已知信息
# 签名匹配: 仅 hash 匹配，无法处理变体
#
# 可迁移的知识域:
#   1. TTP 标签 (参考检测到的 TTP → 提升目标同类 TTP 的检测先验)
#   2. 风险评分 (参考的综合风险 → 调整目标的先验风险)
#   3. 角色标签 (参考的 binary_role → 为目标角色推断提供先验)
#   4. 编译器/优化级 (参考的 compiler family/opt → 固定目标的编译器检测)
#   5. 混淆技术 (参考的 obfuscation → 目标也可能使用相同混淆)

import math
from typing import Dict, List, Tuple, Optional


def _compute_structural_similarity(
    ref_analysis: Dict,
    tgt_analysis: Dict,
) -> Tuple[float, Dict]:
    """计算参考与目标的多维结构相似度。返回 (融合相似度, 明细)。"""
    _details = {}

    # CFG fingerprint similarity
    _rfp = ref_analysis.get("cfg_fingerprint", {})
    _tfp = tgt_analysis.get("cfg_fingerprint", {})
    _rv = _rfp.get("composite_vector", [0, 0, 0, 0])
    _tv = _tfp.get("composite_vector", [0, 0, 0, 0])
    _dot = sum(a * b for a, b in zip(_rv, _tv))
    _na = math.sqrt(sum(x**2 for x in _rv))
    _nb = math.sqrt(sum(y**2 for y in _tv))
    _fp_sim = _dot / (_na * _nb) if _na > 0 and _nb > 0 else 0.0
    _details["fingerprint"] = round(_fp_sim, 4)

    # Import topology similarity (Jaccard on normalized function names)
    def _func_set(imps):
        s = set()
        src = imps.get("all_imports", imps) if isinstance(imps, dict) else {}
        for funcs in (src.values() if isinstance(src, dict) else []):
            if isinstance(funcs, list):
                s.update(f.lower().rstrip('aw') for f in funcs)
        return s

    _rf = _func_set(ref_analysis.get("imports", {}))
    _tf = _func_set(tgt_analysis.get("imports", {}))
    _all = len(_rf | _tf)
    _imp_sim = len(_rf & _tf) / _all if _all > 0 else 0.0
    _details["imports"] = round(_imp_sim, 4)

    # Format/arch match (binary compatibility)
    _fmt_match = ref_analysis.get("format") == tgt_analysis.get("format")
    _arch_match = ref_analysis.get("arch") == tgt_analysis.get("arch")
    _plat_sim = (0.6 if _fmt_match else 0.0) + (0.4 if _arch_match else 0.0)
    _details["platform"] = round(_plat_sim, 4)

    # Compiler-normalized similarity (prefer over raw fingerprint)
    _rcn = ref_analysis.get("compiler_normalized", {})
    _tcn = tgt_analysis.get("compiler_normalized", {})
    if _rcn and _tcn:
        _rnv = _rcn.get("normalized_vector", _rv)
        _tnv = _tcn.get("normalized_vector", _tv)
        _dot_n = sum(a * b for a, b in zip(_rnv, _tnv))
        _na_n = math.sqrt(sum(x**2 for x in _rnv))
        _nb_n = math.sqrt(sum(y**2 for y in _tnv))
        _cn_sim = _dot_n / (_na_n * _nb_n) if _na_n > 0 and _nb_n > 0 else 0.0
        _details["compiler_normalized"] = round(_cn_sim, 4)
        _fp_sim = _cn_sim * 0.7 + _fp_sim * 0.3  # 编译器归一化权重更高

    # 融合: 结构 40% + 导入 30% + 平台 15% + 指纹微调 15%
    _fused = (_fp_sim * 0.40 + _imp_sim * 0.30 + _plat_sim * 0.15 +
              _fp_sim * 0.15)
    _details["fused"] = round(_fused, 4)

    return (round(_fused, 4), _details)


def _decay_factor(domain: str, similarity: float) -> float:
    """领域衰减: 不同知识域对相似度的敏感度不同。
    TTP 标签衰减快 (行为易变异), 编译器标签衰减慢 (编译工具链稳定)。
    """
    _decay_rates = {
        "ttp_labels": 0.85,
        "risk_score": 0.75,
        "binary_role": 0.70,
        "compiler": 0.95,
        "obfuscation": 0.65,
    }
    _rate = _decay_rates.get(domain, 0.75)
    return similarity ** (1.0 / max(_rate, 0.1))


def transfer_knowledge(
    reference_analysis: Dict,
    target_analysis: Dict,
    transfer_domains: List[str] = None,
    min_similarity: float = 0.30,
) -> Dict:
    """跨二进制知识迁移主入口。

    reference_analysis: 已充分分析的参考二进制 (含置信度较高的结论)
    target_analysis: 待分析的目标二进制 (可从初步分析开始)
    transfer_domains: 要迁移的知识域列表，默认全部

    返回:
    - transferred_knowledge: 迁移到目标的知识 (可直接 merge 到目标分析中)
    - structural_similarity: 参考-目标结构相似度
    - transfer_confidence: 迁移操作的整体置信度
    - domain_transfers: 各知识域的迁移详情
    """

    _sim, _sim_details = _compute_structural_similarity(
        reference_analysis, target_analysis)

    if _sim < min_similarity:
        return {
            "transferred_knowledge": {},
            "structural_similarity": _sim,
            "similarity_details": _sim_details,
            "transfer_confidence": 0.0,
            "verdict": "insufficient_similarity",
            "explanation": f"结构相似度 {_sim:.3f} < 阈值 {min_similarity}，知识迁移不可靠",
            "domain_transfers": [],
        }

    _domains = transfer_domains or [
        "ttp_labels", "risk_score", "binary_role", "compiler", "obfuscation"]
    _transferred = {}
    _domain_results = []

    for _dom in _domains:
        _decay = _decay_factor(_dom, _sim)
        _transfer = _transfer_domain(_dom, reference_analysis, target_analysis,
                                      _sim, _decay)
        if _transfer:
            _transferred[_dom] = _transfer["data"]
            _domain_results.append(_transfer)

    _conf = _sim * sum(d["confidence"] for d in _domain_results) / max(
        len(_domain_results), 1)

    return {
        "transferred_knowledge": _transferred,
        "structural_similarity": _sim,
        "similarity_details": _sim_details,
        "transfer_confidence": round(_conf, 4),
        "verdict": ("HIGH_CONFIDENCE" if _conf > 0.70 else
                    "MODERATE_CONFIDENCE" if _conf > 0.40 else "LOW_CONFIDENCE"),
        "explanation": _build_transfer_explanation(_domain_results, _sim),
        "domain_transfers": _domain_results,
    }


def _transfer_domain(
    domain: str,
    ref: Dict,
    tgt: Dict,
    similarity: float,
    decay: float,
) -> Optional[Dict]:
    """单知识域迁移。返回 {data, confidence, description} 或 None。"""
    _conf = similarity * decay

    if domain == "ttp_labels":
        _ref_ttp = ref.get("ttp_profile", {})
        ref_findings = _ref_ttp.get("enhanced_findings", {})
        _phase_dist = _ref_ttp.get("phase_distribution", {})
        if not ref_findings and not _phase_dist:
            return None
        # 迁移: 将参考的 TTP 标签以降低的置信度注入目标
        _boosted = {}
        for _tname, _tinfo in (ref_findings.items() if isinstance(ref_findings, dict) else []):
            if not isinstance(_tinfo, dict): continue
            _orig_conf = _tinfo.get("confidence", _tinfo.get("original_confidence", 0.3))
            _boosted[_tname] = {
                "transferred_confidence": round(_orig_conf * _conf, 4),
                "original_confidence": _orig_conf,
                "source": "knowledge_transfer",
            }
        return {
            "data": {"boosted_ttp_labels": _boosted, "phase_distribution": _phase_dist},
            "confidence": round(_conf, 4),
            "description": f"TTP标签迁移 ({len(_boosted)} 标签, 衰减={decay:.2f})",
        }

    if domain == "risk_score":
        _ref_risk = ref.get("unified_risk", ref.get("risk_synthesis", {}))
        _risk = _ref_risk.get("overall_risk", 0.0)
        if _risk == 0.0:
            return None
        return {
            "data": {"prior_risk": round(_risk * _conf, 4),
                     "source_risk": _risk},
            "confidence": round(_conf, 4),
            "description": f"风险先验迁移 (源风险={_risk:.2f} → 先验={_risk*_conf:.3f})",
        }

    if domain == "binary_role":
        _ref_role = ref.get("capability", {}).get("binary_role", "")
        _ref_role_conf = ref.get("capability", {}).get("role_confidence", 0.0)
        if not _ref_role:
            return None
        return {
            "data": {"prior_role": _ref_role,
                     "prior_role_confidence": round(_ref_role_conf * _conf, 4)},
            "confidence": round(_conf, 4),
            "description": f"角色先验: {_ref_role} (置信度={_ref_role_conf*_conf:.2f})",
        }

    if domain == "compiler":
        _ref_comp = ref.get("compiler_normalized", {})
        _family = _ref_comp.get("compiler_family", "")
        _opt = _ref_comp.get("opt_level", "")
        if not _family or _family == "unknown":
            return None
        return {
            "data": {"prior_compiler_family": _family,
                     "prior_opt_level": _opt},
            "confidence": round(_conf, 4),
            "description": f"编译器先验: {_family} {_opt} (支持目标编译器检测)",
        }

    if domain == "obfuscation":
        _ref_obf = ref.get("obfuscation", {})
        _top = _ref_obf.get("top_match") if isinstance(_ref_obf, dict) else None
        if not _top:
            return None
        return {
            "data": {"prior_obfuscation": _top.get("technique", ""),
                     "prior_obfuscation_confidence": round(
                         _top.get("confidence", 0.0) * _conf, 4)},
            "confidence": round(_conf, 4),
            "description": f"混淆先验: {_top.get('technique','?')}",
        }

    return None


def _build_transfer_explanation(transfers: List[Dict], sim: float) -> str:
    if not transfers:
        return f"无知识可迁移 (相似度={sim:.3f})"
    _parts = [f"结构相似度 {sim:.2%}"]
    for t in transfers:
        _parts.append(t["description"])
    return "; ".join(_parts)
