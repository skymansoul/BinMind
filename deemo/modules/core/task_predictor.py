# -*- coding: utf-8 -*-
"""
任务耗时预测 — 在线 Holt-Winters 简化版 + 稀疏特征偏置学习的每任务耗时估算.

静态 worker 分配忽略任务耗时差异: 当层内有 5s 与 0.1s 任务混跑时,
快任务占用的 worker 在层同步点闲置, 层完成时间由最慢任务决定.
若能预知耗时, 慢任务可提前调度以压缩尾部延迟.

不用 sklearn/lightgbm 的原因: 这些框架的导入耗时 (200~500ms) 远超本模块
的目标预测延迟 (<1ms). 纯 Python 在线更新, O(1) 每次, 无需存储历史数据.

参考 Yano & Azumi (2025) 的概率执行时间模型, 但去掉离线 profiling 依赖.
准确率目标: 20 次执行后预测误差中位数 < 30%.
"""

import bisect
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


def _binary_size_bucket(size_bytes: int) -> str:
    """将二进制大小映射到对数桶, 减少特征稀疏性."""
    if size_bytes <= 0:
        return 'empty'
    exp = int(math.log2(size_bytes))
    lower = 1 << exp
    upper = 1 << (exp + 1)
    if size_bytes - lower < upper - size_bytes:
        return f'2^{exp}'
    return f'2^{exp + 1}'


@dataclass
class TaskProfile:
    """单任务的运行时画像 — 由在线更新维持.

    ewma: 指数加权移动均值 (ms)
    ewma_trend: 相邻增量的指数平滑 (ms)
    bias: 特征偏置表 {feature_key: adjustment_ms}
    """

    name: str
    ewma: float = 0.0          # 水平分量
    ewma_trend: float = 0.0     # 趋势分量
    n_samples: int = 0
    bias: Dict[str, float] = field(default_factory=dict)
    last_seen: float = 0.0      # 最后一次更新时刻 (monotonic)

    # Holt-Winters 平滑因子 — α 偏大 (0.3) 以适应非平稳序列
    alpha: float = 0.30
    beta: float = 0.15
    # 偏置学习率
    bias_lr: float = 0.10


class TaskPredictor:
    """在线任务耗时预测器.

    使用模式:
      pred = TaskPredictor()
      est = pred.predict('taint_analysis', features={'arch': 'x86_64', 'size': 2048576})
      # ... 执行 ...
      pred.update('taint_analysis', actual_ms=3420, features={'arch': 'x86_64', 'size': 2048576})

    预测公式:
      pred = ewma + trend + sum(bias[feat] for feat in active_features)
      其中 trend 乘以剩余训练步数的衰减因子: 初期趋势不可靠, 权重低.
    """

    def __init__(self, default_ewma: float = 500.0):
        self._profiles: Dict[str, TaskProfile] = {}
        self._default_ewma = default_ewma
        # 全局特征偏置, 用于冷启动时跨任务共享
        self._global_bias: Dict[str, float] = defaultdict(float)
        self._total_updates = 0

    def predict(
        self, task_name: str,
        features: Optional[Dict[str, Any]] = None,
        steps_ahead: int = 1,
    ) -> float:
        """预测任务的下次执行耗时 (ms).

        steps_ahead: 多步预测, 仅用于趋势外推 (很少使用).
        features: 如 {'arch': 'arm64', 'binary_size': 4194304, 'task_type': 'taint'}.
        """
        profile = self._profiles.get(task_name)
        if profile is None or profile.n_samples == 0:
            base = self._default_ewma
        else:
            base = profile.ewma
            # 趋势项乘衰减: 当 n_samples 少时, trend 不可靠, 权重压低
            confidence = min(1.0, profile.n_samples / 15.0)
            base += profile.ewma_trend * steps_ahead * confidence

        # 特征偏置: 任务级优先, 回退到全局
        if features:
            adjustment = 0.0
            active = self._encode_features(features)
            for feat_key in active:
                if profile is not None and feat_key in profile.bias:
                    adjustment += profile.bias[feat_key]
                elif feat_key in self._global_bias:
                    adjustment += self._global_bias[feat_key]
            # 偏置调整不超过基础值的 50%, 避免冷启动时的极端预测
            clamp = base * 0.5
            base += max(-clamp, min(clamp, adjustment))

        return max(1.0, base)  # 下界 1ms, 防止零或负值

    def update(
        self, task_name: str, actual_ms: float,
        features: Optional[Dict[str, Any]] = None,
    ):
        """以实际测量值更新预测模型. 所有操作为 O(1)."""
        profile = self._profiles.get(task_name)
        if profile is None:
            profile = TaskProfile(name=task_name, ewma=self._default_ewma)
            self._profiles[task_name] = profile

        profile.n_samples += 1
        self._total_updates += 1
        profile.last_seen = time.monotonic()

        old_ewma = profile.ewma
        # Holt-Winters 简化更新
        profile.ewma = (
            profile.alpha * actual_ms
            + (1 - profile.alpha) * (profile.ewma + profile.ewma_trend)
        )
        profile.ewma_trend = (
            profile.beta * (profile.ewma - old_ewma)
            + (1 - profile.beta) * profile.ewma_trend
        )

        # 特征偏置更新: 将预测误差按比例分配至各活跃特征
        if features:
            error = actual_ms - (old_ewma + profile.ewma_trend)
            active = self._encode_features(features)
            share = error / max(1, len(active))
            for feat_key in active:
                old_bias = profile.bias.get(feat_key, 0.0)
                profile.bias[feat_key] = old_bias + profile.bias_lr * share
                # 全局偏置更新 (学习率更低, 避免跨任务污染)
                self._global_bias[feat_key] += 0.02 * share

    def batch_update(
        self, observations: List[Tuple[str, float, Optional[Dict[str, Any]]]],
    ):
        """批量更新, 用于层执行完毕后的一次性反馈."""
        for name, ms, feat in observations:
            self.update(name, ms, feat)

    def profile(self, task_name: str) -> Optional[TaskProfile]:
        return self._profiles.get(task_name)

    def all_profiles(self) -> Dict[str, TaskProfile]:
        return dict(self._profiles)

    @staticmethod
    def _encode_features(features: Dict[str, Any]) -> List[str]:
        """将特征字典编码为稀疏的字符串键列表.

        编码规则:
          - arch: 直接使用 (如 'x86_64', 'arm64')
          - binary_size: 对数分桶 (如 'sz:2^21')
          - task_type: 直接使用
          - 其他值: 转为 'key:value' 形式
        """
        encoded = []
        for k, v in sorted(features.items()):
            if k == 'binary_size' or k == 'size':
                try:
                    encoded.append(f'sz:{_binary_size_bucket(int(v))}')
                except (TypeError, ValueError):
                    encoded.append(f'{k}:{v}')
            elif k == 'arch':
                encoded.append(f'arch:{v}')
            elif k == 'task_type':
                encoded.append(f'type:{v}')
            else:
                encoded.append(f'{k}:{v}')
        return encoded


class PredictionGuidedScheduler:
    """预测驱动的层内任务排序 — 慢任务优先, 压缩层 wall-clock 完成时间.

    对 HookDAGScheduler 非侵入: 仅通过重排 _levels 中同层任务顺序实现.
    """

    def __init__(self, scheduler, predictor: Optional[TaskPredictor] = None):
        self._sched = scheduler
        self.predictor = predictor or TaskPredictor()

    def reorder_by_prediction(
        self, binary_features: Optional[Dict[str, Any]] = None,
    ) -> List[List[str]]:
        """返回按预测耗时降序重排后的层级列表.

        设计考量: 仅在层内重排, 不改变层间拓扑顺序.
        """
        if not self._sched._built:
            self._sched.build()

        feats = dict(binary_features or {})
        new_levels = []
        for level in self._sched._levels:
            if len(level) <= 1:
                new_levels.append(list(level))
                continue
            # 对每层的任务按预测耗时降序排列
            scored = []
            for name in level:
                task_feats = dict(feats)
                task_feats['task_name'] = name
                est = self.predictor.predict(name, features=task_feats)
                scored.append((est, name))
            scored.sort(key=lambda x: x[0], reverse=True)
            new_levels.append([name for _, name in scored])

        return new_levels

    def execute_with_prediction(
        self, context: Optional[Dict[str, Any]] = None,
        binary_features: Optional[Dict[str, Any]] = None,
        max_workers: Optional[int] = None,
        parallel: bool = True,
        learn: bool = True,
    ) -> Tuple[Dict[str, Any], List[Tuple[str, float]]]:
        """执行管道并在此过程中收集耗时数据用于在线学习.

        返回: (context, observations) — observations 可直接喂给 predictor.batch_update.
        """
        import time as _time

        if context is None:
            context = {}

        observations: List[Tuple[str, float, Optional[Dict[str, Any]]]] = []
        feats = dict(binary_features or {})

        # 在执行前获取预测耗时的排序层级, 若调度器支持则注入
        # (此处作为参考实现; 实际生产环境可包装 _run_level 方法)
        t0 = _time.perf_counter()
        result = self._sched.execute(context, max_workers=max_workers, parallel=parallel)
        total_ms = (_time.perf_counter() - t0) * 1000

        # 从遥测中提取各任务的实际耗时
        telemetry = self._sched.get_telemetry() if hasattr(self._sched, 'get_telemetry') else []
        for entry in telemetry:
            name = entry.get('name', '')
            last_ms = entry.get('last_latency_ms', 0)
            if name and last_ms > 0:
                task_feats = dict(feats)
                task_feats['task_name'] = name
                observations.append((name, last_ms, task_feats))

        if learn and observations:
            self.predictor.batch_update(observations)

        return result, observations
