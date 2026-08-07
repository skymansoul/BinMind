# Created: 2026-08-01 19:22:25
#
# entropy_gradient_profiler — 字节级熵梯度分析与多层混淆检测
# 双尺度滑动窗口 Shannon 熵 → 一阶梯度 → 峰检测 → 层边界推断。
# 区别于 GView (可视化+阈值) 和 ESNH (需要训练): 仅用熵梯度拓扑，零训练数据。
# 核心假设: 正常编译器熵平滑；打包器边界处熵突变产生梯度峰；多层打包呈多峰分布。

import math
import os
import struct
from typing import Dict, List, Tuple, Optional
from collections import Counter


def _shannon_byte_entropy(data: bytes) -> float:
    """单窗口字节级 Shannon 熵 (bits)，最大 8.0。"""
    if not data:
        return 0.0
    _cnt = Counter(data)
    _n = len(data)
    _ent = 0.0
    _inv = 1.0 / _n
    for _c in _cnt.values():
        _p = _c * _inv
        _ent -= _p * math.log2(_p)
    return _ent


def _sliding_entropy_series(
    data: bytes,
    window_size: int = 4096,
    step: int = 2048,
) -> List[Tuple[int, float]]:
    """滑动窗口熵序列。
    返回 [(起始偏移, 熵值), ...]，窗口向右滑动 step 字节。
    末尾不足 window_size 的窗口丢弃。
    """
    _series = []
    _end = len(data) - window_size
    for _off in range(0, _end + 1, step):
        _win = data[_off:_off + window_size]
        _ent = _shannon_byte_entropy(_win)
        _series.append((_off, round(_ent, 6)))
    return _series


def _compute_gradient(
    series: List[Tuple[int, float]],
    smoothing: int = 1,
) -> List[Tuple[int, float]]:
    """熵序列的一阶离散梯度。
    smoothing > 1 时使用中心差分近似，压制采样噪声。
    """
    if len(series) < 2:
        return []

    _grad = []
    for _i in range(smoothing, len(series) - smoothing):
        _off = series[_i][0]
        _prev = series[_i - smoothing][1]
        _next = series[_i + smoothing][1]
        _dx = series[_i + smoothing][0] - series[_i - smoothing][0]
        if _dx > 0:
            _g = (_next - _prev) / _dx
        else:
            _g = 0.0
        _grad.append((_off, round(_g, 8)))

    return _grad


def _detect_peaks(
    grad_series: List[Tuple[int, float]],
    threshold: float = 0.0003,
    min_distance: int = 4096,
) -> List[Dict]:
    """对梯度序列做峰值检测，提取显著边界点。
    threshold: 梯度绝对值超过此值视为潜在边界。
    min_distance: 两个边界间的最小距离（字节），合并过近的峰。
    """
    if not grad_series:
        return []

    # 提取绝对值超过阈值的点
    _candidates = [
        (off, gv) for off, gv in grad_series
        if abs(gv) > threshold
    ]
    if not _candidates:
        return []

    # 按绝对值降序排列，贪心选择，保证最小距离约束
    _candidates.sort(key=lambda x: abs(x[1]), reverse=True)
    _selected: List[Tuple[int, float]] = []

    for _off, _gv in _candidates:
        _too_close = any(abs(_off - s[0]) < min_distance for s in _selected)
        if not _too_close:
            _selected.append((_off, _gv))

    # 按偏移排序
    _selected.sort(key=lambda x: x[0])

    return [
        {
            "offset": _off,
            "gradient": _gv,
            "direction": "entropy_increase" if _gv > 0 else "entropy_decrease",
            "offset_hex": f"0x{_off:x}",
        }
        for _off, _gv in _selected
    ]


def _classify_layer(ent_before: float, ent_after: float, ent_max: float) -> str:
    """边界前后熵变化 → 层类型标签。"""
    _delta = ent_after - ent_before
    if ent_before > 6.5 and ent_after > 6.5:
        return "obfuscation_layer_transition"
    if _delta > 2.0: return "clear_to_encrypted"
    if _delta < -2.0: return "encrypted_to_clear"
    if ent_before < 4.0 and ent_after > 6.0: return "native_to_packed"
    if ent_before > 6.0 and ent_after < 4.0: return "packed_to_native"
    if abs(_delta) < 1.0 and ent_before > 6.5: return "within_encrypted_variation"
    return f"minor_transition(delta={_delta:.2f})"


def profile_entropy_gradient(
    filepath: str,
    coarse_window: int = 4096, fine_window: int = 256,
    step_ratio: float = 0.5,
) -> Dict:
    """双尺度熵梯度分析主入口。粗窗口(默认4KB)检测大边界，细窗口(256B)检测局部异常。
    返回: global_entropy / coarse_analysis / fine_analysis / layer_boundaries /
          obfuscation_confidence / obfuscation_type
    """
    if not os.path.isfile(filepath):
        return {"error": "file_not_found", "filepath": filepath}

    _fsize = os.path.getsize(filepath)
    if _fsize < coarse_window:
        return {
            "file_size": _fsize,
            "global_entropy": 0.0,
            "error": "file_too_small",
        }

    with open(filepath, "rb") as _fh:
        _data = _fh.read()

    _global_ent = _shannon_byte_entropy(_data)

    # 粗尺度：检测主要层边界
    _coarse_step = max(256, int(coarse_window * step_ratio))
    _coarse_series = _sliding_entropy_series(_data, coarse_window, _coarse_step)
    _coarse_grad = _compute_gradient(_coarse_series, smoothing=2)
    _coarse_boundaries = _detect_peaks(
        _coarse_grad,
        threshold=0.0002,
        min_distance=coarse_window,
    )

    # 细尺度：检测局部异常
    _fine_step = max(64, int(fine_window * step_ratio))
    _fine_series = _sliding_entropy_series(_data, fine_window, _fine_step)
    _fine_grad = _compute_gradient(_fine_series, smoothing=1)
    _fine_anomalies = _detect_peaks(
        _fine_grad,
        threshold=0.001,
        min_distance=fine_window * 2,
    )

    # 层计数估计：粗尺度边界数 + 1
    _layer_estimate = len(_coarse_boundaries) + 1 if _coarse_boundaries else 1

    # 混淆置信度：由多个信号合成
    _obf_confidence = _estimate_obfuscation_confidence(
        _global_ent, _coarse_series, _fine_anomalies,
        len(_coarse_boundaries), _fsize,
    )

    _obf_type = _infer_obfuscation_type(
        _global_ent, _coarse_boundaries, _coarse_series, _fsize,
    )

    # 综合边界：从粗尺度边界回溯对应熵值
    _combined_boundaries = []
    _coarse_lookup = {off: ent for off, ent in _coarse_series}
    for _b in _coarse_boundaries:
        _off = _b["offset"]
        _ent_before = _coarse_lookup.get(_off - coarse_window, _global_ent)
        _ent_after = _coarse_lookup.get(_off, _global_ent)
        _b["entropy_before"] = round(_ent_before, 4)
        _b["entropy_after"] = round(_ent_after, 4)
        _b["layer_type"] = _classify_layer(_ent_before, _ent_after, _global_ent)
        _combined_boundaries.append(_b)

    return {
        "file_size": _fsize,
        "global_entropy": round(_global_ent, 4),
        "coarse_analysis": {
            "window_size": coarse_window,
            "series_length": len(_coarse_series),
            "boundary_count": len(_coarse_boundaries),
            "layer_count_estimate": _layer_estimate,
            "entropy_range": (
                round(min(e for _, e in _coarse_series), 4) if _coarse_series else 0.0,
                round(max(e for _, e in _coarse_series), 4) if _coarse_series else 0.0,
            ),
        },
        "fine_analysis": {
            "window_size": fine_window,
            "anomaly_count": len(_fine_anomalies),
            "anomalies": _fine_anomalies[:8],
        },
        "layer_boundaries": _combined_boundaries,
        "obfuscation_confidence": round(_obf_confidence, 4),
        "obfuscation_type": _obf_type,
    }


def _estimate_obfuscation_confidence(
    global_ent: float, coarse_series: List[Tuple[int, float]],
    fine_anomalies: List[Dict], boundary_count: int, file_size: int,
) -> float:
    """多信号合成混淆置信度: 全局熵(35%) + 熵方差(20%) + 边界数(25%) + 异常密度(20%)。"""
    _s1 = max(0.0, min(1.0, (global_ent - 5.0) / 2.5))
    if len(coarse_series) > 1:
        _ents = [e for _, e in coarse_series]
        _mean = sum(_ents) / len(_ents)
        _std = math.sqrt(sum((e - _mean) ** 2 for e in _ents) / len(_ents))
        _s2 = min(1.0, _std / 1.5)
    else:
        _s2 = 0.0
    _s3 = min(1.0, boundary_count / 5.0)
    _anomaly_density = len(fine_anomalies) / max(1, file_size / (256 * 256))
    _s4 = min(1.0, _anomaly_density * 5.0)
    return _s1 * 0.35 + _s2 * 0.20 + _s3 * 0.25 + _s4 * 0.20


def _infer_obfuscation_type(
    global_ent: float, boundaries: List[Dict],
    coarse_series: List[Tuple[int, float]], file_size: int,
) -> str:
    """熵模式 → 混淆类型标签。"""
    if global_ent < 5.5 and len(boundaries) == 0:
        return "likely_native_or_unpacked"
    _n = len(boundaries) + 1
    if global_ent > 7.2:
        return ("multi_layer_encryption" if _n >= 3 else
                "single_layer_encryption" if _n == 2 else
                "high_entropy_uniform(full_encryption_suspected)")
    if 6.0 < global_ent <= 7.2:
        return ("standard_packer(upx-like)" if _n >= 2 else
                "partial_encryption_or_compressed")
    if global_ent <= 6.0 and len(boundaries) >= 2:
        return "selective_encryption_mixed_payload"
    if global_ent < 6.0:
        _hi = sum(1 for _, ent in coarse_series if ent > 6.5)
        if 1 <= _hi <= len(coarse_series) * 0.3:
            return "suspected_code_cave_injection"
    return "inconclusive"
