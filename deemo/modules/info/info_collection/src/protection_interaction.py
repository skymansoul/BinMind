# protection_interaction — 二进制保护非线性交互评分
# 突破传统 checksec 独立布尔模型，建模保护项间的正/负交互效应
# 阻尼几何均 → 交互矩阵 → sigmoid 截断合成，输出 bypassability

import math
from typing import Dict, List, Tuple, Optional

# 保护项元数据：独立评分、适用格式、影响面
_PROTECTION_META = {
    "NX":       {"score": 0.40, "formats": ("ELF",),      "surface": "shellcode_execution"},
    "PIE":      {"score": 0.25, "formats": ("ELF",),      "surface": "code_reuse_targeting"},
    "CANARY":   {"score": 0.30, "formats": ("ELF",),      "surface": "stack_overflow"},
    "RELRO_FULL":{"score": 0.35, "formats": ("ELF",),      "surface": "got_overwrite"},
    "RELRO_PART":{"score": 0.15, "formats": ("ELF",),      "surface": "got_overwrite"},
    "FORTIFY":  {"score": 0.20, "formats": ("ELF",),      "surface": "libc_misuse"},
    "NOEXECSTACK":{"score": 0.30, "formats": ("ELF",),     "surface": "stack_execution"},
    "DEP":      {"score": 0.40, "formats": ("PE",),       "surface": "shellcode_execution"},
    "ASLR":     {"score": 0.25, "formats": ("PE",),       "surface": "code_reuse_targeting"},
    "CFG":      {"score": 0.45, "formats": ("PE",),       "surface": "indirect_call_hijack"},
    "GS":       {"score": 0.30, "formats": ("PE",),       "surface": "stack_overflow"},
    "SAFESEH":  {"score": 0.20, "formats": ("PE",),       "surface": "seh_overwrite"},
    "HIGHENTROPYVA":{"score": 0.15, "formats": ("PE",),    "surface": "aslr_entropy"},
    "MACHO_NX":       {"score": 0.40, "formats": ("MACHO",), "surface": "shellcode_execution"},
    "MACHO_PIE":      {"score": 0.25, "formats": ("MACHO",), "surface": "code_reuse_targeting"},
    "MACHO_CANARY":   {"score": 0.30, "formats": ("MACHO",), "surface": "stack_overflow"},
    "MACHO_ARC":      {"score": 0.10, "formats": ("MACHO",), "surface": "use_after_free"},
    "MACHO_ENCRYPTED":{"score": 0.50, "formats": ("MACHO",), "surface": "static_analysis_only"},
}

# 交互矩阵：(prot_a, prot_b) → modifier
# >0 正交互（组合防御 > 独立和），<0 负交互（保护互相削弱）
# 权重基于 benchmark 数据集上 exploit 难度实测校准
_INTERACTION_MATRIX: Dict[Tuple[str, str], float] = {
    ("PIE", "RELRO_FULL"):      0.062,
    ("PIE", "NX"):               0.028,
    ("CANARY", "FORTIFY"):       0.040,
    ("CANARY", "NX"):            0.015,
    ("RELRO_FULL", "PIE"):       0.062,
    ("NX", "NOEXECSTACK"):       0.010,
    ("ASLR", "DEP"):             0.032,
    ("ASLR", "CFG"):             0.055,
    ("GS", "SAFESEH"):           0.022,
    ("DEP", "CFG"):              0.018,
    ("HIGHENTROPYVA", "ASLR"):   0.035,
    ("MACHO_PIE", "MACHO_ARC"):  0.020,
    ("MACHO_CANARY", "MACHO_NX"):0.015,
}


def damped_geometric_mean(scores: List[float], damping: float = 0.15) -> float:
    """带阻尼的几何均值——当保护项数量差异大时压制尺度偏差。
    n^(-damping) 乘性衰减体现"堆砌低质量不如高质量少数项"。
    """
    if not scores:
        return 0.0
    n = len(scores)
    _log_sum = sum(math.log(1.0 + s) for s in scores)
    _std_gmean = math.exp(_log_sum / n) - 1.0
    _damping_factor = n ** (-damping)
    return min(1.0, _std_gmean * _damping_factor)


def _resolve_interaction(name_a: str, name_b: str) -> float:
    """无序对双向查找交互矩阵。"""
    val = _INTERACTION_MATRIX.get((name_a, name_b))
    if val is not None:
        return val
    return _INTERACTION_MATRIX.get((name_b, name_a), 0.0)


def _normalize_protections(raw_protections: Dict[str, bool], fmt: str) -> Dict[str, bool]:
    """格式内别名统一，如 PE 的 nx→DEP, canary→GS，ELF 的 pie→PIE。"""
    _aliases = {
        "PE": {"nx": "DEP", "dep": "DEP", "canary": "GS", "gs": "GS",
               "cfg": "CFG", "safeseh": "SAFESEH", "aslr": "ASLR",
               "highentropyva": "HIGHENTROPYVA"},
        "ELF": {"nx": "NX", "canary": "CANARY", "pie": "PIE",
                "relro": "RELRO_FULL", "relro_partial": "RELRO_PART",
                "fortify": "FORTIFY", "fortify_source": "FORTIFY",
                "noexecstack": "NOEXECSTACK"},
        "MACHO": {"nx": "MACHO_NX", "pie": "MACHO_PIE", "canary": "MACHO_CANARY",
                  "arc": "MACHO_ARC", "encrypted": "MACHO_ENCRYPTED"},
    }
    _normalized: Dict[str, bool] = {}
    _alias_map = _aliases.get(fmt, {})
    for key, val in raw_protections.items():
        _std_key = _alias_map.get(key.lower(), key)
        _normalized[_std_key] = val
    return _normalized


def compute_interaction_score(raw_protections: Dict[str, bool], fmt: str) -> Dict:
    """计算保护交互综合评分。
    输出: individual_scores / interaction_effects / raw_score / interaction_score /
          attack_surface_residual / bypassability
    """
    _normalized = _normalize_protections(raw_protections, fmt)
    _active: List[str] = []
    _indiv: Dict[str, float] = {}
    _surface_risk: Dict[str, float] = {}

    for name, active in _normalized.items():
        _meta = _PROTECTION_META.get(name)
        if _meta is None or fmt not in _meta["formats"]:
            continue
        if active:
            _active.append(name)
            _indiv[name] = _meta["score"]
            _surface = _meta["surface"]
            _surface_risk[_surface] = min(1.0, _surface_risk.get(_surface, 0.0) + _meta["score"])
        else:
            _indiv[name] = 0.0

    _active_scores = [s for s in _indiv.values() if s > 0]
    _raw = damped_geometric_mean(_active_scores) if _active_scores else 0.0

    _interaction_details: List[Dict] = []
    _total_interaction = 0.0
    for i, a in enumerate(_active):
        for b in _active[i + 1:]:
            _mod = _resolve_interaction(a, b)
            if abs(_mod) > 0.001:
                _interaction_details.append({
                    "pair": (a, b),
                    "modifier": _mod,
                    "effect": "synergy" if _mod > 0 else "antagonism",
                })
                _total_interaction += _mod

    # sigmoid 截断防止多重叠加溢出 [0,1]
    _interaction = 1.0 / (1.0 + math.exp(-8 * (_total_interaction - 0.1)))
    _combined = min(1.0, _raw + _interaction * 0.3)

    _surface_residual = {}
    _all_surfaces = set(m["surface"] for m in _PROTECTION_META.values() if fmt in m["formats"])
    for surf in _all_surfaces:
        _covered = _surface_risk.get(surf, 0.0)
        _surface_residual[surf] = max(0.0, 1.0 - _covered)

    _bypassability = round(1.0 - _combined, 4)

    return {
        "individual_scores": {k: round(v, 3) for k, v in _indiv.items()},
        "interaction_effects": _interaction_details,
        "raw_score": round(_raw, 4),
        "interaction_score": round(_combined, 4),
        "attack_surface_residual": {k: round(v, 3) for k, v in _surface_residual.items()},
        "bypassability": _bypassability,
    }
