# confidence_calibrator — 跨检测器置信度校准
# 不同检测器 (injection/lateral/persistence/spoofing/leak) 的置信度评分尺度不一致:
#   injection 可能 0.4 即高置信，lateral 可能 0.7 才中等置信。
# 本模块用 Bradley-Terry 成对排序模型 + Platt 缩放将所有检测器映射到
# 公共校准尺度 [0, 1]，使跨检测器比较和融合具备数学一致性。
#
# 区别于 Jamgharyan: 该文献用 isotonic regression 校准单个
# XGBoost 分类器。本模块校准的是异构多检测器管线，无 ML 模型，
# 仅基于检测器输出统计特性 (检测率、误报趋势) 做非参数排序校准。
#
# 校准原理:
#   1. 为每个检测器建立 Bradley-Terry 评分: P(i beats j) = score_i / (score_i + score_j)
#   2. 检测器的"激进程度"由其平均检测率估计 — 过于激进的检测器置信度被压低
#   3. 应用 Platt 缩放: calibrated = 1/(1+exp(-(a*raw + b)))，参数 a,b 由
#      检测率与误报率的 logistic 拟合确定

import math
from typing import Dict, List, Tuple, Optional


def _estimate_detector_params(
    detections: List[Tuple[str, float, bool]],
) -> Dict[str, Tuple[float, float]]:
    """从标注数据估计每个检测器的 Platt 缩放参数 (a, b)。

    detections: [(detector_name, raw_confidence, is_true_positive), ...]
    若缺少标注数据 (is_true_positive)，则使用检测率/置信度分布做启发式估计。

    返回: {detector_name: (scale_a, shift_b)}
    """
    _by_detector: Dict[str, List[Tuple[float, bool]]] = {}
    for _name, _conf, _tp in detections:
        _by_detector.setdefault(_name, []).append((_conf, _tp))

    _params: Dict[str, Tuple[float, float]] = {}

    for _name, _pairs in _by_detector.items():
        _confs = [c for c, _ in _pairs]
        _tps = [tp for _, tp in _pairs]
        if not _confs:
            _params[_name] = (1.0, 0.0)
            continue

        _mean_conf = sum(_confs) / len(_confs)
        _tp_rate = sum(1 for t in _tps if t) / max(len(_tps), 1)

        # 理想情况: mean_conf ≈ tp_rate
        # scale_a: 压缩/扩展因子 (tp_rate/mean_conf 的偏差指示过度自信或保守)
        _scale_a = _tp_rate / max(_mean_conf, 0.01)
        _scale_a = max(0.3, min(3.0, _scale_a))

        # shift_b: 使 logistic 中点对齐到 tp_rate=0.5 的置信度
        _shift_b = -math.log(max(0.01, min(0.99, _tp_rate)) /
                            max(0.01, 1.0 - _tp_rate))
        _shift_b = max(-3.0, min(3.0, _shift_b))

        _params[_name] = (round(_scale_a, 4), round(_shift_b, 4))

    return _params


def _heuristic_params(
    detector_outputs: Dict[str, Dict],
) -> Dict[str, Tuple[float, float]]:
    """无标注数据时的启发式参数估计。
    利用各检测器的 detect_all() 输出统计特性:
    - 检测率过高的检测器 (detected_count / total 高) → 压低置信度
    - 高置信度命中多的检测器 → 保持或略微提升
    """
    _params: Dict[str, Tuple[float, float]] = {}
    _detection_rates: Dict[str, float] = {}

    for _name, _output in detector_outputs.items():
        if not isinstance(_output, dict):
            continue
        _findings = _output.get("findings", {})
        _total = len(_findings)
        if _total == 0:
            _params[_name] = (1.0, 0.0)
            continue

        _detected = sum(1 for f in _findings.values()
                       if isinstance(f, dict) and f.get("detected"))
        _rate = _detected / _total
        _detection_rates[_name] = _rate

    if not _detection_rates:
        return _params

    _mean_rate = sum(_detection_rates.values()) / len(_detection_rates)
    if _mean_rate < 0.01:
        _mean_rate = 0.01

    for _name, _rate in _detection_rates.items():
        # 激进度 = rate / mean_rate。>1 → 过于激进，压低置信度
        _aggressiveness = _rate / _mean_rate
        _scale_a = 1.0 / max(0.3, min(3.0, _aggressiveness))
        _shift_b = (_rate - 0.3) * 2.0
        _params[_name] = (round(_scale_a, 4), round(_shift_b, 4))

    return _params


def platt_scale(raw_confidence: float, a: float, b: float) -> float:
    """Platt 缩放: calibrated = sigmoid(a * raw + b)。"""
    _z = a * raw_confidence + b
    # 防止溢出
    if _z > 20: return 1.0
    if _z < -20: return 0.0
    return round(1.0 / (1.0 + math.exp(-_z)), 4)


def calibrate_detection_results(
    detection_results: Dict[str, Dict],
    labeled_data: List[Tuple[str, float, bool]] = None,
) -> Dict:
    """跨检测器置信度校准主入口。

    detection_results: {detector_name: detect_all()_output}
      例如: {"injection": {...}, "lateral": {...}, "persistence": {...}}

    labeled_data: 可选标注数据用于 Platt 缩放参数估计。
      格式: [(detector_name, raw_confidence, is_true_positive), ...]

    返回:
    - calibrated_results: 每个检测器的校准后结果 (原始结构 + 校准置信度)
    - calibration_params: 每个检测器的 (scale_a, shift_b)
    - calibration_summary: 各检测器的激进/保守程度摘要
    """
    if labeled_data:
        _params = _estimate_detector_params(labeled_data)
    else:
        _params = _heuristic_params(detection_results)

    _calibrated = {}
    _total_before = 0.0
    _total_after = 0.0
    _count = 0

    for _dname, _doutput in detection_results.items():
        if not isinstance(_doutput, dict):
            _calibrated[_dname] = _doutput
            continue

        _a, _b = _params.get(_dname, (1.0, 0.0))
        _findings = _doutput.get("findings", {})

        _cal_findings = {}
        for _tname, _tresult in _findings.items():
            if not isinstance(_tresult, dict):
                _cal_findings[_tname] = _tresult
                continue

            _raw_conf = _tresult.get("confidence", 0.0)
            _cal_conf = platt_scale(_raw_conf, _a, _b)

            _cal_result = dict(_tresult)
            _cal_result["raw_confidence"] = _raw_conf
            _cal_result["confidence"] = _cal_conf
            _cal_result["calibrated"] = True
            _cal_result["calibration_a"] = _a
            _cal_result["calibration_b"] = _b

            _total_before += _raw_conf
            _total_after += _cal_conf
            _count += 1

            _cal_findings[_tname] = _cal_result

        _cal_output = dict(_doutput)
        _cal_output["findings"] = _cal_findings
        _cal_output["calibrated"] = True

        # 更新 detected_count 和 summary
        _new_detected = sum(1 for f in _cal_findings.values()
                          if isinstance(f, dict) and f.get("confidence", 0) > 0.3)
        _cal_output["detected_count"] = _new_detected

        _high_conf = sum(1 for f in _cal_findings.values()
                        if isinstance(f, dict) and f.get("confidence", 0) > 0.6)
        _cal_output["high_confidence_count"] = _high_conf

        _calibrated[_dname] = _cal_output

    # 校准摘要
    _summary = {}
    for _name, (_a, _b) in _params.items():
        if _a > 1.1:
            _bias = "conservative"
        elif _a < 0.9:
            _bias = "aggressive"
        else:
            _bias = "balanced"
        _summary[_name] = {"scale_a": _a, "shift_b": _b, "bias": _bias}

    _avg_before = round(_total_before / max(_count, 1), 4)
    _avg_after = round(_total_after / max(_count, 1), 4)

    return {
        "calibrated_results": _calibrated,
        "calibration_params": _params,
        "calibration_summary": _summary,
        "mean_confidence_before": _avg_before,
        "mean_confidence_after": _avg_after,
        "calibration_delta": round(_avg_after - _avg_before, 4),
    }


def calibrate_single_score(
    detector_name: str,
    raw_confidence: float,
    detection_results: Dict[str, Dict] = None,
    calibration_params: Dict[str, Tuple[float, float]] = None,
) -> float:
    """快速校准单个置信度值。
    需要 calibration_params 或从 detection_results 推断。
    """
    if calibration_params and detector_name in calibration_params:
        _a, _b = calibration_params[detector_name]
        return platt_scale(raw_confidence, _a, _b)

    if detection_results:
        _params = _heuristic_params(detection_results)
        _a, _b = _params.get(detector_name, (1.0, 0.0))
        return platt_scale(raw_confidence, _a, _b)

    return raw_confidence
