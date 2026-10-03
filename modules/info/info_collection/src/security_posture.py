# security_posture — 跨格式归一化安全态势向量
# 将不同格式的保护项映射到 7 维攻击面向量，实现 ELF/PE/Mach-O 间可比
# 归一化策略：按攻击面语义归类，sigmoid 平滑，子系统调整

from typing import Dict, List, Optional, Union
import math


# 7 维攻击面（跨格式统一语义）
_POSTURE_DIMENSIONS = [
    "stack_protection",
    "code_reuse_defense",
    "heap_integrity",
    "got_plt_integrity",
    "wxorx_enforcement",
    "type_safety",
    "binary_integrity",
]

# 维度映射：(dimension, format) → [(保护名, 权重, 方向)]
# 方向 1=存在加分，方向不变（缺失保护时天然为 0）
_DIMENSION_MAPPING: Dict[str, Dict[str, List[tuple]]] = {
    "stack_protection": {
        "ELF":   [("CANARY", 0.70, 1), ("FORTIFY", 0.30, 1)],
        "PE":    [("GS", 0.65, 1), ("SAFESEH", 0.20, 1)],
        "MACHO": [("MACHO_CANARY", 0.60, 1)],
    },
    "code_reuse_defense": {
        "ELF":   [("PIE", 0.45, 1), ("RELRO_FULL", 0.15, 1)],
        "PE":    [("ASLR", 0.40, 1), ("CFG", 0.45, 1), ("HIGHENTROPYVA", 0.10, 1)],
        "MACHO": [("MACHO_PIE", 0.40, 1)],
    },
    "heap_integrity": {
        "ELF":   [],
        "PE":    [("DEP", 0.15, 1)],
        "MACHO": [],
    },
    "got_plt_integrity": {
        "ELF":   [("RELRO_FULL", 0.80, 1), ("RELRO_PART", 0.25, 1)],
        "PE":    [],
        "MACHO": [],
    },
    "wxorx_enforcement": {
        "ELF":   [("NX", 0.75, 1), ("NOEXECSTACK", 0.20, 1)],
        "PE":    [("DEP", 0.75, 1)],
        "MACHO": [("MACHO_NX", 0.70, 1)],
    },
    "type_safety": {
        "ELF":   [],
        "PE":    [("CFG", 0.25, 1)],
        "MACHO": [("MACHO_ARC", 0.50, 1)],
    },
    "binary_integrity": {
        "ELF":   [],
        "PE":    [],
        "MACHO": [("MACHO_ENCRYPTED", 0.40, 1)],
    },
}

# PE 子系统对特定维度的增强（如 boot application 天然二进制完整性更高）
_SUBSYSTEM_ADJUSTMENTS = {
    "PE": {
        "WINDOWS_BOOT_APPLICATION": {"binary_integrity": 0.40},
        "EFI_APPLICATION": {"binary_integrity": 0.30},
        "EFI_BOOT_SERVICE_DRIVER": {"binary_integrity": 0.30},
        "NATIVE": {"wxorx_enforcement": 0.10},
    }
}


def _sigmoid_normalize(raw: float, k: float = 8.0, midpoint: float = 0.5) -> float:
    """累积权重 sigmoid 映射到 [0,1]。k=8 时约 2-3 项强保护即可趋近 1。"""
    return 1.0 / (1.0 + math.exp(-k * (raw - midpoint)))


def compute_posture_vector(
    raw_protections: Dict[str, bool],
    fmt: str,
    subsystem: Optional[str] = None,
) -> Dict:
    """计算 7 维跨格式态势向量。
    输出: dimensions / effective_dimensions / posture_score / posture_grade /
          weakest_surface / cross_format_comparable
    """
    _dims: Dict[str, Optional[float]] = {}
    _values_for_avg: List[float] = []

    for _dim in _POSTURE_DIMENSIONS:
        _mapping = _DIMENSION_MAPPING.get(_dim, {}).get(fmt, [])
        if not _mapping:
            _dims[_dim] = None
            continue

        _raw = 0.0
        for _prot_name, _weight, _direction in _mapping:
            _present = raw_protections.get(_prot_name, False)
            if _present:
                _raw += _weight * _direction

        _normed = _sigmoid_normalize(_raw)
        _dims[_dim] = round(_normed, 4)
        _values_for_avg.append(_normed)

    if subsystem and fmt in _SUBSYSTEM_ADJUSTMENTS:
        _adj = _SUBSYSTEM_ADJUSTMENTS[fmt].get(subsystem, {})
        for _dim, _bonus in _adj.items():
            if _dims.get(_dim) is not None:
                _dims[_dim] = round(min(1.0, _dims[_dim] + _bonus), 4)

    _effective = sum(1 for v in _dims.values() if v is not None)
    _posture_score = (sum(_values_for_avg) / len(_values_for_avg)) if _values_for_avg else 0.0
    _posture_score = round(_posture_score, 4)

    _grade = _score_to_grade(_posture_score)

    _weakest = "none"
    _min_val = 1.0
    for _dim, _val in _dims.items():
        if _val is not None and _val < _min_val:
            _min_val = _val
            _weakest = _dim

    return {
        "dimensions": _dims,
        "effective_dimensions": _effective,
        "posture_score": _posture_score,
        "posture_grade": _grade,
        "weakest_surface": _weakest,
        "cross_format_comparable": True,
    }


def _score_to_grade(score: float) -> str:
    if score >= 0.85: return "A+"
    if score >= 0.75: return "A"
    if score >= 0.65: return "B+"
    if score >= 0.55: return "B"
    if score >= 0.40: return "C"
    if score >= 0.25: return "D"
    return "F"


def compare_postures(posture_a: Dict, posture_b: Dict) -> Dict:
    """比较两个任意格式二进制文件的态势向量。
    逐维度对 delta，汇总为 a_wins/b_wins/verdict。
    """
    _dims_a = posture_a.get("dimensions", {})
    _dims_b = posture_b.get("dimensions", {})

    _diffs = {}
    _a_wins = 0
    _b_wins = 0

    for _dim in _POSTURE_DIMENSIONS:
        _va = _dims_a.get(_dim)
        _vb = _dims_b.get(_dim)
        if _va is None and _vb is None:
            _diffs[_dim] = {"status": "both_na"}
            continue
        if _va is None:
            _diffs[_dim] = {"status": "a_na", "b_value": _vb}
            continue
        if _vb is None:
            _diffs[_dim] = {"status": "b_na", "a_value": _va}
            continue

        _delta = round(_va - _vb, 4)
        _diffs[_dim] = {
            "a_value": _va,
            "b_value": _vb,
            "delta": _delta,
            "advantage": "a" if _delta > 0.01 else "b" if _delta < -0.01 else "tie",
        }
        if _delta > 0.01:
            _a_wins += 1
        elif _delta < -0.01:
            _b_wins += 1

    return {
        "dimension_diffs": _diffs,
        "a_wins": _a_wins,
        "b_wins": _b_wins,
        "verdict": "a_stronger" if _a_wins > _b_wins else "b_stronger" if _b_wins > _a_wins else "comparable",
    }
