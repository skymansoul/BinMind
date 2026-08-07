"""网络取证——信标检测。"""
from statistics import mean, stdev
from typing import List, Dict, Any

from ._nf_types import FlowRecord, BEACON_JITTER_RATIO, BEACON_MIN_INTERVALS


def beacon_score(flow_intervals: List[float]) -> float:
    """计算信标评分：抖动比 = std(intervals)/mean(intervals)。

    抖动比<0.12表示机器般规律性（C2信标特征）。合法流量通常抖动比>0.3。
    """
    if len(flow_intervals) < BEACON_MIN_INTERVALS:
        return 0.0
    _m = mean(flow_intervals)
    if _m <= 0:
        return 0.0
    try:
        _s = stdev(flow_intervals)
    except Exception:
        return 0.0
    _jitter = _s / _m
    # 将抖动比映射为0-1信标评分
    if _jitter < BEACON_JITTER_RATIO:
        return 1.0
    elif _jitter < 0.3:
        return 1.0 - (_jitter - BEACON_JITTER_RATIO) / (0.3 - BEACON_JITTER_RATIO)
    else:
        return 0.0


def check_beacon_timing(flow: FlowRecord) -> Dict[str, Any]:
    """滑动窗口分析流内包间隔，检测信标行为。

    将流划分为多个窗口，每窗口独立计算beacon_score，
    若多数窗口得分>0.7则判定为信标。
    """
    _intervals = flow._intervals
    _n = len(_intervals)
    if _n < BEACON_MIN_INTERVALS:
        return {"is_beacon": False, "score": 0.0, "consistency": 0}

    # 全序列评分
    _score = beacon_score(_intervals)

    # 滑动窗口一致性
    _window = min(8, _n // 2)
    if _window < 3:
        return {"is_beacon": _score > 0.7, "score": _score, "consistency": 0}

    _consist = 0
    _total = 0
    for i in range(_n - _window + 1):
        _win = _intervals[i:i + _window]
        _ws = beacon_score(_win)
        _total += 1
        if _ws > 0.7:
            _consist += 1

    return {
        "is_beacon": _score > 0.7 and _consist > _total * 0.5,
        "score": _score,
        "consistency": _consist / _total if _total > 0 else 0,
    }
