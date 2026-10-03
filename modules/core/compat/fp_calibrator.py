# coding: utf-8
"""
误报率统计校准器 — 基于标注样本的反馈调整过滤管线敏感度.

原理: 不在检测阶段引入 ML 黑盒 (避免裁判问题), 而是在过滤管线之后
用标注数据统计各类过滤策略的精确率和召回率, 动态调整阈值以逼近
目标误报率.

校准参数:
  - value_range_threshold: 区间分析的保守度 (越大越保守, 漏报越低但误报越高)
  - taint_distance_max: 污点距离上限 (超过此距离的候选被降权)
  - alloc_constraint_margin: 分配器约束的余量 (usable_size * margin)
  - path_sensitivity_depth: 路径敏感分析的展开深度

方法: 在标注集上用网格搜索找到帕累托最优参数组合,
最大化 F1-score (或给定误报率上限下的最高召回率).

  - "Learning to Find Bugs" — 用 ML 排序静态分析告警
  - "SyFix: Fixing Static Analysis Alarms" — 用历史修复模式校准误报
"""

import json, os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

@dataclass
class CalibrationConfig:
    """可调节的过滤参数."""
    value_range_enabled: bool = True
    value_range_depth: int = 12
    taint_distance_threshold: int = 8
    alloc_constraints_enabled: bool = True
    alloc_margin_factor: float = 1.0
    path_analysis_enabled: bool = True
    path_analysis_max_iter: int = 50
    constraint_solver_enabled: bool = True
    interproc_enabled: bool = True
    interproc_max_depth: int = 12

    def to_dict(self) -> Dict[str, Any]:
        return {
            'value_range_enabled': self.value_range_enabled,
            'value_range_depth': self.value_range_depth,
            'taint_distance_threshold': self.taint_distance_threshold,
            'alloc_constraints_enabled': self.alloc_constraints_enabled,
            'alloc_margin_factor': self.alloc_margin_factor,
            'path_analysis_enabled': self.path_analysis_enabled,
            'path_analysis_max_iter': self.path_analysis_max_iter,
            'constraint_solver_enabled': self.constraint_solver_enabled,
            'interproc_enabled': self.interproc_enabled,
            'interproc_max_depth': self.interproc_max_depth,
        }

@dataclass
class MetricsPoint:
    """一个 (precision, recall, f1) 数据点."""
    config: CalibrationConfig
    tp: int = 0; fp: int = 0; tn: int = 0; fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / max(1, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return self.tp / max(1, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(0.001, p + r)

    @property
    def fp_rate(self) -> float:
        """误报率 = FP / (FP + TN)"""
        return self.fp / max(1, self.fp + self.tn)

class FpCalibrator:
    """误报校准器 — 学习最优过滤参数.

    用法:
      calibrator = FpCalibrator()
      calibrator.load_ground_truth('ground_truth.json')
      best = calibrator.calibrate(detection_fn, param_grid)
      calibrator.save_config(best, 'calibrated_config.json')
    """

    def __init__(self, target_fp_rate: float = 0.15,
                 min_recall: float = 0.85):
        self._target_fp = target_fp_rate
        self._min_recall = min_recall
        self._ground_truth: Dict[str, Dict[str, bool]] = {}
        self._history: List[MetricsPoint] = []

    def load_ground_truth(self, path: str):
        """加载标注数据.

        格式: {
          "sample_001": {
            "0x401234_heap_overflow": true,
            "0x402000_heap_overflow": false,
            ...
          }
        }
        """
        with open(path, 'r') as f:
            self._ground_truth = json.load(f)

    def add_annotation(self, sample_id: str, candidate_key: str,
                       is_tp: bool):
        """手动添加单条标注."""
        if sample_id not in self._ground_truth:
            self._ground_truth[sample_id] = {}
        self._ground_truth[sample_id][candidate_key] = is_tp

    def evaluate(self, config: CalibrationConfig,
                 detection_fn: Callable[[CalibrationConfig, str],
                                       List[Dict]],
                 samples: List[str]) -> MetricsPoint:
        """在标注集上评估一组参数的表现.

        detection_fn: (config, sample_path) → [candidate_dict, ...]
        """
        point = MetricsPoint(config=config)

        for sample_path in samples:
            sample_id = os.path.basename(sample_path).replace('.elf', '')
            candidates = detection_fn(config, sample_path)
            gt = self._ground_truth.get(sample_id, {})

            matched_gt_keys: Set[str] = set()
            for c in candidates:
                key = self._candidate_key(c)
                is_tp = gt.get(key, False)
                if key in gt:
                    matched_gt_keys.add(key)
                    if is_tp:
                        point.tp += 1
                    else:
                        point.fp += 1
                else:
                    point.fp += 1

            for key, is_tp in gt.items():
                if is_tp and key not in matched_gt_keys:
                    point.fn += 1
                elif not is_tp:
                    point.tn += 1

        self._history.append(point)
        return point

    def calibrate(self,
                  detection_fn: Callable,
                  samples: List[str],
                  param_grid: Optional[List[CalibrationConfig]] = None,
                  ) -> Tuple[CalibrationConfig, MetricsPoint]:
        """网格搜索最优参数。

        param_grid 为参数组合列表 (None 时使用默认搜索空间);
        返回 (最优配置, 最优指标)。
        """
        if param_grid is None:
            param_grid = self._default_grid()

        best: Optional[Tuple[CalibrationConfig, MetricsPoint]] = None

        for config in param_grid:
            point = self.evaluate(config, detection_fn, samples)

            if point.recall < self._min_recall:
                continue

            if best is None:
                best = (config, point)
            else:
                if point.fp_rate < best[1].fp_rate:
                    best = (config, point)
                elif (point.fp_rate == best[1].fp_rate and
                      point.recall > best[1].recall):
                    best = (config, point)

        if best is None:
            best_cfg = min(
                self._history,
                key=lambda mp: (mp.fp_rate, -mp.recall),
            )
            return best_cfg.config, best_cfg

        return best

    def _default_grid(self) -> List[CalibrationConfig]:
        """默认参数搜索空间."""
        grid = []
        for td in [4, 6, 8, 10, 14]:
            for amf in [0.8, 1.0, 1.2, 1.5]:
                for vr_depth in [8, 12, 16]:
                    grid.append(CalibrationConfig(
                        taint_distance_threshold=td,
                        alloc_margin_factor=amf,
                        value_range_depth=vr_depth,
                    ))
        return grid

    def _candidate_key(self, candidate: Dict) -> str:
        """从候选生成唯一 key."""
        addr = candidate.get('overflow_site',
                             candidate.get('alloc_site',
                                           candidate.get('write_site', 0)))
        vtype = candidate.get('vuln_type', 'heap_overflow')
        return f'{self._fmt_addr(addr)}_{vtype}'

    @staticmethod
    def _fmt_addr(addr: Any) -> str:
        if isinstance(addr, int):
            return hex(addr)
        if isinstance(addr, str) and addr.startswith('0x'):
            return addr
        return str(addr)

    def save_config(self, config: CalibrationConfig, path: str):
        with open(path, 'w') as f:
            json.dump(config.to_dict(), f, indent=2)

    @staticmethod
    def load_config(path: str) -> CalibrationConfig:
        with open(path, 'r') as f:
            d = json.load(f)
        return CalibrationConfig(**d)

    def report(self) -> Dict[str, Any]:
        """生成校准报告."""
        if not self._history:
            return {'status': 'no evaluations yet'}
        best = min(self._history, key=lambda p: p.fp_rate)
        return {
            'total_evaluations': len(self._history),
            'best_fp_rate': f'{best.fp_rate:.2%}',
            'best_recall': f'{best.recall:.2%}',
            'best_f1': f'{best.f1:.3f}',
            'best_config': best.config.to_dict(),
            'pareto_frontier': self._pareto_frontier(),
        }

    def _pareto_frontier(self) -> List[Dict]:
        """计算帕累托前沿 (误报率 vs 召回率)."""
        points = sorted(self._history, key=lambda p: p.fp_rate)
        frontier = []
        best_recall = 0.0
        for p in points:
            if p.recall > best_recall:
                best_recall = p.recall
                frontier.append({
                    'fp_rate': f'{p.fp_rate:.2%}',
                    'recall': f'{p.recall:.2%}',
                    'f1': f'{p.f1:.3f}',
                    'config': p.config.to_dict(),
                })
        return frontier
