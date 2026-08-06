# Created: 2025-07-23 11:13:16
#
# cross_arch_equivalence — 跨架构二进制语义等价性估计
# 使用编译器归一化指纹 + 导入拓扑 + 段密度分布，估计两个不同架构的
# 二进制是否来自同一源码。无需反汇编或动态分析。
#
# 问题场景:
#   - IoT 固件分析: 同一 malware 同时有 ARM/MIPS/x86 变体
#   - 供应链验证: 验证 x86 binary 与 ARM64 binary 是否同源
#   - Rosetta/ARM64EC 验证: 确认转译后的二进制保留了安全属性
#
# 等价性度量:
#   1. 编译器归一化指纹相似度 (40%) — 剥离架构差异后的结构指纹
#   2. 导入拓扑相似度 (25%) — 外部依赖模式应跨架构一致
#   3. 段密度分布相似度 (20%) — CODE/DATA/RODATA 比例应相近
#   4. 函数数量比例 (15%) — 同一源码产生的函数数有稳定比例关系
#
# 基线: 同一源码 GCC -O2 x86 vs ARM64 → 归一化指纹余弦相似度约 0.85-0.95
#       不同源码 → 通常 < 0.50

import math
from typing import Dict, List, Tuple, Optional


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b: return 0.0
    _dot = sum(x * y for x, y in zip(a, b))
    _na = math.sqrt(sum(x ** 2 for x in a))
    _nb = math.sqrt(sum(y ** 2 for y in b))
    if _na < 1e-9 or _nb < 1e-9: return 0.0
    return _dot / (_na * _nb)


def _js_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
    """Jensen-Shannon 散度: 对称化的 KL 散度，范围 [0, ln2]。"""
    _all_keys = set(p.keys()) | set(q.keys())
    if not _all_keys: return 0.0
    _m = {}
    for _k in _all_keys:
        _m[_k] = (p.get(_k, 0.0) + q.get(_k, 0.0)) / 2.0

    def _kl(a, b):
        _s = 0.0
        for _k in _all_keys:
            _pa = max(a.get(_k, 1e-9), 1e-9)
            _pb = max(b.get(_k, 1e-9), 1e-9)
            _s += _pa * math.log(_pa / _pb)
        return _s

    _js = (_kl(p, _m) + _kl(q, _m)) / 2.0
    return _js


def _compute_import_topology_similarity(
    imports_a: Dict,
    imports_b: Dict,
) -> float:
    """跨架构导入拓扑相似度: 比较使用的 DLL/库集合和函数集合。"""
    if not imports_a or not imports_b:
        return 0.0

    def _lib_names(imps):
        if isinstance(imps, dict) and "all_imports" in imps:
            return set(imps["all_imports"].keys())
        return set(imps.keys())

    def _func_names(imps):
        _f = set()
        _src = imps.get("all_imports", imps) if isinstance(imps, dict) else {}
        for _funcs in _src.values():
            if isinstance(_funcs, list):
                _f.update(f.lower().rstrip('aw') for f in _funcs)
        return _f

    _libs_a = _lib_names(imports_a)
    _libs_b = _lib_names(imports_b)
    _funcs_a = _func_names(imports_a)
    _funcs_b = _func_names(imports_b)

    if not _libs_a and not _libs_b:
        return 0.5
    if not _funcs_a and not _funcs_b:
        return 0.5

    _lib_jaccard = len(_libs_a & _libs_b) / max(len(_libs_a | _libs_b), 1)
    _func_jaccard = len(_funcs_a & _funcs_b) / max(len(_funcs_a | _funcs_b), 1)

    return _lib_jaccard * 0.35 + _func_jaccard * 0.65


def _compute_section_distribution_similarity(
    sections_a: List[Dict],
    sections_b: List[Dict],
) -> float:
    """段密度分布相似度: 比较 CODE/DATA/RODATA/BSS 类型比例。"""

    def _classify(sec: Dict) -> str:
        _n = sec.get("name", sec.get("segment", "")).lower().lstrip("._")
        if _n in ("text", "code", "itext"): return "CODE"
        if _n in ("rodata", "const", "rdata"): return "RODATA"
        if _n in ("data", "idata"): return "DATA"
        if _n in ("bss",): return "BSS"
        _chars = sec.get("characteristics", [])
        if isinstance(_chars, list) and "MEM_EXECUTE" in _chars: return "CODE"
        return "OTHER"

    def _distribution(sections):
        _dist: Dict[str, float] = {}
        _total = sum(s.get("size", s.get("vmsize", s.get("filesz", 0)))
                    for s in sections if isinstance(s, dict))
        if _total == 0: return _dist
        for _s in sections:
            if not isinstance(_s, dict): continue
            _type = _classify(_s)
            _sz = _s.get("size", _s.get("vmsize", _s.get("filesz", 0)))
            _dist[_type] = _dist.get(_type, 0.0) + _sz / _total
        return _dist

    _da = _distribution(sections_a)
    _db = _distribution(sections_b)
    if not _da or not _db: return 0.0

    _js = _js_divergence(_da, _db)
    return max(0.0, 1.0 - _js / 0.693)


def estimate_equivalence(
    analysis_a: Dict,
    analysis_b: Dict,
    compiler_normalized_a: Dict = None,
    compiler_normalized_b: Dict = None,
    fingerprint_a: Dict = None,
    fingerprint_b: Dict = None,
) -> Dict:
    """跨架构语义等价性估计主入口。

    analysis_a/b: 两个二进制的完整分析结果
      应包含: imports, sections, functions, format, arch

    返回:
    - equivalence_score: 等价性综合评分 (0-1, >0.80 → 高度可能同源)
    - fingerprint_similarity: 编译器归一化指纹余弦相似度
    - import_similarity: 导入拓扑相似度
    - section_similarity: 段密度分布相似度
    - function_count_ratio: 函数数比与期望比的偏离度
    - verdict: LIKELY_SAME_SOURCE / POSSIBLY_RELATED / DIFFERENT_SOURCE
    - confidence: 评估置信度 (0-1)
    """

    # 编译器归一化指纹相似度
    _cfp_a = compiler_normalized_a or fingerprint_a or {}
    _cfp_b = compiler_normalized_b or fingerprint_b or {}

    _vec_a = _cfp_a.get("normalized_vector",
                        _cfp_a.get("composite_vector", [0.0, 0.0, 0.0, 0.0]))
    _vec_b = _cfp_b.get("normalized_vector",
                        _cfp_b.get("composite_vector", [0.0, 0.0, 0.0, 0.0]))
    _fp_sim = _cosine_similarity(_vec_a, _vec_b)

    # 导入拓扑相似度
    _imports_a = analysis_a.get("imports", {})
    _imports_b = analysis_b.get("imports", {})
    _imp_sim = _compute_import_topology_similarity(_imports_a, _imports_b)

    # 段密度分布相似度
    _sec_a = analysis_a.get("sections", [])
    _sec_b = analysis_b.get("sections", [])
    _sec_sim = _compute_section_distribution_similarity(_sec_a, _sec_b)

    # 函数数量比
    _funcs_a = len(analysis_a.get("functions", []))
    _funcs_b = len(analysis_b.get("functions", []))
    if _funcs_a > 0 and _funcs_b > 0:
        _fratio = min(_funcs_a, _funcs_b) / max(_funcs_a, _funcs_b)
        # 同一源码跨架构: 函数数比通常在 0.70-1.0
        _func_score = max(0.0, 1.0 - abs(_fratio - 0.85) * 2.5)
    else:
        _func_score = 0.3

    # 加权合成
    _equiv = (
        _fp_sim * 0.40 +
        _imp_sim * 0.25 +
        _sec_sim * 0.20 +
        _func_score * 0.15
    )

    # 置信度: 有多少信号参与计算 (>0)
    _signals_used = sum(1 for x in [_fp_sim, _imp_sim, _sec_sim, _func_score] if x > 0.01)
    _conf = min(1.0, _signals_used / 4.0 + _equiv * 0.3)

    if _equiv > 0.80:
        _verdict = "LIKELY_SAME_SOURCE"
    elif _equiv > 0.55:
        _verdict = "POSSIBLY_RELATED"
    elif _equiv > 0.30:
        _verdict = "UNCERTAIN"
    else:
        _verdict = "DIFFERENT_SOURCE"

    _arch_a = analysis_a.get("arch", analysis_a.get("machine", "unknown"))
    _arch_b = analysis_b.get("arch", analysis_b.get("machine", "unknown"))

    return {
        "equivalence_score": round(_equiv, 4),
        "fingerprint_similarity": round(_fp_sim, 4),
        "import_similarity": round(_imp_sim, 4),
        "section_similarity": round(_sec_sim, 4),
        "function_count_similarity": round(_func_score, 4),
        "verdict": _verdict,
        "confidence": round(_conf, 4),
        "architecture_a": _arch_a,
        "architecture_b": _arch_b,
        "cross_architecture": _arch_a != _arch_b,
    }
