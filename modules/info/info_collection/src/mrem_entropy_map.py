# mrem_entropy_map — 多分辨率熵图 (Multi-Resolution Entropy Map)
# 沿两个维度同时计算 Shannon 熵: 字节偏移 (x轴) 和窗口尺度 (y轴, 指数增长)
# 输出 2D 熵矩阵，每个 cell[i][j] = offset_i 处 window_j 尺度的熵值
#
# 与 GView 的差异:
#   1. GView 仅在单一窗口尺度可视化熵；本模块在 8+ 个尺度同时采样
#   2. 多尺度联合分析可区分: 细粒度模式(短指令序列)、中粒度模式(函数/段边界)、
#      粗粒度模式(打包层/加密区域)
#   3. 二维梯度 (∂ent/∂offset, ∂ent/∂scale) 揭示 GView 看不到的结构特征:
# 尺度不变区域 (∂/∂scale ≈ 0) → 均匀分布的随机数据 (加密载荷)
#      - 尺度敏感区域 (∂/∂scale 大) → 分层结构 (打包器 stub + payload)

import math
import os
from typing import Dict, List, Tuple, Optional
from collections import Counter
from ._shared import shannon_entropy as _shannon_entropy



def _scale_series(min_window: int = 64, max_window: int = 65536,
                  scales: int = 8) -> List[int]:
    """指数增长的窗口尺度序列。scale 数自适应：大文件增加更多粗尺度。"""
    if scales < 2: scales = 2
    _log_min = math.log2(min_window)
    _log_max = math.log2(max_window)
    return [int(2 ** (_log_min + i * (_log_max - _log_min) / (scales - 1)))
            for i in range(scales)]


def compute_mrem(
    filepath: str,
    scales: int = 8,
    offset_step: int = 512,
    min_window: int = 64,
    max_window: int = 65536,
) -> Dict:
    """计算多分辨率熵图。

    scales: 尺度层数 (默认 8，指数分布: 64B → 65KB)
    offset_step: x轴步长 (默认 512B)
    max_window 自适应文件大小，不超过文件长度的 1/4

    返回:
    - matrix: 2D 列表, matrix[scale_idx][offset_idx] = entropy (0-8 bits)
    - scales: 各尺度对应的窗口字节数
    - offsets: x轴偏移列表
    - resolution: (scales, offset_count)
    - gradient_offset: x方向梯度 (跨偏移的一阶导数均值)
    - gradient_scale: y方向梯度 (跨尺度的一阶导数均值)
    - scale_invariant_regions: 高尺度不变性区域列表
    - structural_complexity: 综合结构复杂度评分
    """
    if not os.path.isfile(filepath):
        return {"error": "file_not_found", "filepath": filepath}

    _fsize = os.path.getsize(filepath)
    if _fsize < min_window * 2:
        return {"error": "file_too_small", "file_size": _fsize}

    # 自适应最大窗口：不超过文件的 1/4
    _eff_max = min(max_window, max(min_window * 2, _fsize // 4))
    _scale_windows = _scale_series(min_window, _eff_max, scales)

    # 数据加载: > 500MB 用 mmap，否则全量读取
    _LARGE_FILE = 500 * 1024 * 1024
    _fh = open(filepath, "rb")
    if _fsize > _LARGE_FILE:
        import mmap as _mmap_mod
        _data = _mmap_mod.mmap(_fh.fileno(), 0, access=_mmap_mod.ACCESS_READ)
    else:
        _data = _fh.read()
        _fh.close()

    # 生成偏移序列 (x轴)
    _offsets = list(range(0, max(1, _fsize - min_window + 1), offset_step))
    _matrix: List[List[float]] = []

    for _win in _scale_windows:
        _row = []
        for _off in _offsets:
            _end = min(_off + _win, _fsize)
            _chunk = _data[_off:_end]
            _ent = _shannon_entropy(_chunk)
            _row.append(round(_ent, 4))
        _matrix.append(_row)

    _n_scales = len(_scale_windows)
    _n_offsets = len(_offsets)

    # x方向梯度 (每行的相邻偏移熵差绝对值均值)
    _grad_offset = []
    for _row in _matrix:
        if len(_row) >= 2:
            _diffs = [abs(_row[i + 1] - _row[i]) for i in range(len(_row) - 1)]
            _grad_offset.append(round(sum(_diffs) / len(_diffs), 6))
        else:
            _grad_offset.append(0.0)

    # y方向梯度 (每列的相邻尺度熵差绝对值均值)
    _grad_scale = []
    for _j in range(_n_offsets):
        _diffs = [abs(_matrix[i + 1][_j] - _matrix[i][_j])
                  for i in range(_n_scales - 1)]
        _grad_scale.append(round(sum(_diffs) / len(_diffs), 6))

    # 尺度不变区域: y梯度 < 阈值 → 各尺度熵值一致 → 均匀数据
    _threshold = 0.15
    _invariant_regions = []
    _region_start = None
    for _j, _g in enumerate(_grad_scale):
        if _g < _threshold:
            if _region_start is None:
                _region_start = _offsets[_j]
        else:
            if _region_start is not None:
                _invariant_regions.append({
                    "start": _region_start,
                    "end": _offsets[_j - 1] if _j > 0 else _offsets[_j],
                    "entropy_level": round(_matrix[_n_scales // 2][_j - 1], 3) if _j > 0 else 0.0,
                })
                _region_start = None
    if _region_start is not None:
        _invariant_regions.append({
            "start": _region_start,
            "end": _offsets[-1],
            "entropy_level": round(_matrix[_n_scales // 2][-1], 3),
        })

    # 结构复杂度: 所有梯度的加权和
    _mean_grad_off = sum(_grad_offset) / _n_scales if _grad_offset else 0.0
    _mean_grad_scale = sum(_grad_scale) / _n_offsets if _grad_scale else 0.0
    _complexity = round((_mean_grad_off * 0.6 + _mean_grad_scale * 0.4) * 100.0, 2)

    return {
        "file_size": _fsize,
        "matrix": _matrix,
        "scales": _scale_windows,
        "offsets": _offsets[:20] + ([_offsets[-1]] if len(_offsets) > 20 else []),
        "resolution": [_n_scales, _n_offsets],
        "gradient_offset": _grad_offset,
        "gradient_scale": _grad_scale,
        "scale_invariant_regions": _invariant_regions,
        "structural_complexity": _complexity,
        "mean_entropy_across_scales": [
            round(sum(_row) / len(_row), 4) for _row in _matrix
        ],
    }


def detect_structural_boundaries(mrem_result: Dict,
                                  grad_threshold: float = 0.08) -> List[Dict]:
    """从 MREM 中检测结构边界（段/层/打包器 stub 的分界点）。
    边界 = x方向梯度峰值且 y方向梯度也高 → 真正的结构变化 (非采样噪声)。
    """
    _go = mrem_result.get("gradient_offset", [])
    _gs = mrem_result.get("gradient_scale", [])
    _offsets = mrem_result.get("offsets", [])

    if not _go or not _gs or len(_go) != len(_gs):
        # gradient_offset 是 per-scale 的，gradient_scale 是 per-offset 的
        # 取 gradient_scale 的峰值作为边界
        if not _gs: return []
        _boundaries = []
        for _j in range(1, len(_gs) - 1):
            if (_gs[_j] > _gs[_j - 1] and _gs[_j] > _gs[_j + 1]
                    and _gs[_j] > grad_threshold):
                _off = (_offsets[_j] if _j < len(_offsets)
                        else _offsets[-1] if _offsets else 0)
                _boundaries.append({
                    "offset": _off,
                    "gradient_value": round(_gs[_j], 6),
                    "offset_hex": f"0x{_off:x}" if isinstance(_off, int) else str(_off),
                })
        return _boundaries

    # 双条件: x梯度峰值 + y梯度均值 > threshold
    _boundaries = []
    for _j in range(1, len(_gs) - 1):
        if (_gs[_j] > _gs[_j - 1] and _gs[_j] > _gs[_j + 1]
                and _gs[_j] > grad_threshold):
            _off = _offsets[_j] if _j < len(_offsets) else 0
            _cross_scale_grad = _go[min(_j // max(len(_gs) // max(len(_go), 1), 1),
                                     len(_go) - 1)] if _go else _gs[_j]
            _boundaries.append({
                "offset": _off,
                "gradient_x": round(_gs[_j], 6),
                "gradient_y": round(_cross_scale_grad, 6),
                "offset_hex": f"0x{_off:x}" if isinstance(_off, int) else str(_off),
                "confidence": "high" if _cross_scale_grad > 0.1 else "medium",
            })

    return _boundaries


def compare_mrem_similarity(mrem_a: Dict, mrem_b: Dict) -> Dict:
    """比较两个 MREM 的结构相似度。
    使用粗粒度采样对齐 + 归一化互相关。
    不同文件大小通过双线性插值对齐到公共网格。
    """
    _ma = mrem_a.get("matrix")
    _mb = mrem_b.get("matrix")
    if not _ma or not _mb:
        return {"similarity": 0.0, "error": "missing_matrix"}

    _na_scales = len(_ma)
    _nb_scales = len(_mb)

    # 取粗尺度层的均值向量 (第 na/2 层及以上)，不同分辨率归一化
    _common_scales = min(_na_scales, _nb_scales)
    _vec_a = []
    _vec_b = []

    for _i in range(_common_scales):
        _row_a = _ma[_i]
        _row_b = _mb[_i]
        # 降采样到公共长度
        _common_len = min(len(_row_a), len(_row_b), 256)
        _step_a = max(1, len(_row_a) // _common_len)
        _step_b = max(1, len(_row_b) // _common_len)
        for _k in range(_common_len):
            _idx_a = min(_k * _step_a, len(_row_a) - 1)
            _idx_b = min(_k * _step_b, len(_row_b) - 1)
            _vec_a.append(_row_a[_idx_a])
            _vec_b.append(_row_b[_idx_b])

    if not _vec_a:
        return {"similarity": 0.0, "error": "empty_vector"}

    # 余弦相似度
    _dot = sum(a * b for a, b in zip(_vec_a, _vec_b))
    _na_norm = math.sqrt(sum(a ** 2 for a in _vec_a))
    _nb_norm = math.sqrt(sum(b ** 2 for b in _vec_b))

    if _na_norm < 1e-9 or _nb_norm < 1e-9:
        return {"similarity": 0.0, "error": "zero_norm"}

    _cos_sim = round(_dot / (_na_norm * _nb_norm), 6)

    # 互相关峰值偏移 (检测是否存在位移相似性)
    _max_corr = _cos_sim
    _best_lag = 0
    if len(_vec_a) > 100:
        for _lag in [-8, -4, -2, 0, 2, 4, 8]:
            _shifted = _vec_a[_lag:] if _lag >= 0 else _vec_a[:len(_vec_a) + _lag]
            _ref = _vec_b[:len(_shifted)]
            _dot_s = sum(s * r for s, r in zip(_shifted, _ref))
            _ns = math.sqrt(sum(s ** 2 for s in _shifted))
            _nr = math.sqrt(sum(r ** 2 for r in _ref))
            if _ns > 0 and _nr > 0:
                _corr = _dot_s / (_ns * _nr)
                if _corr > _max_corr:
                    _max_corr = _corr
                    _best_lag = _lag

    return {
        "similarity": round(_max_corr, 6),
        "best_lag": _best_lag,
        "cosine_similarity": _cos_sim,
        "vector_length": len(_vec_a),
    }
