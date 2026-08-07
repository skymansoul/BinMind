# 修改记录:
# 2025-08-07 10:12 - 初始实现：基于二进制复杂度的自适应分析调度

"""复杂度感知调度 — 按二进制复杂度动态分配分析资源的最短剩余时间优先调度。

现有分析管道按FIFO处理二进制——一个5MB的striped binary和一个50MB的
全符号binary获得相同的分析时间和资源。导致小文件等待大文件，整体延迟恶化。

核心机制——复杂度估计 + 最短处理时间优先(SPT)调度：
1. 在分析开始前，用轻量级特征（段数/导入函数数/文件大小/熵）
   估计每个二进制的分析耗时（线性回归）。
2. 按估计耗时升序排列分析队列——短任务优先完成，降低平均等待时间。
3. 对耗时异常超过估计值150%的任务，触发"复杂度再估计"——
   更新模型参数并可能重新排队。
4. 自适应批处理：复杂度相近的二进制归入同批，减少上下文切换。

与既有 adaptive_pool.py 的关系：
- adaptive_pool：线程/进程池的大小自适应（How many workers）。
- 本模块：任务调度顺序自适应（Which task next）。
- 两者正交——分别优化并发度和优先级。

参考：SPT调度理论，应用于二进制分析的新场景。
"""

import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9


@dataclass
class BinaryProfile:
    """二进制的轻量级复杂度画像。"""
    binary_id: str
    file_size: int        # 字节数
    num_sections: int
    num_imports: int
    num_functions: int     # 若已知（有符号表），否则=0
    entropy: float         # 字节级香农熵
    is_stripped: bool = False
    estimated_seconds: float = 0.0
    actual_seconds: float = 0.0  # 分析后填入
    priority: float = 0.0


class ComplexityAwareScheduler:
    """复杂度感知的二进制分析调度器。

    使用范式：
      scheduler = ComplexityAwareScheduler()
      scheduler.enqueue(profiles)
      order = scheduler.schedule()  # 按推荐顺序处理
      for bin_id in order:
          actual_time = analyze(bin_id)
          scheduler.feedback(bin_id, actual_time)
    """

    def __init__(
        self,
        reestimate_threshold: float = 1.5,
        batch_size_hint: int = 8,
    ):
        self.reestimate_threshold = reestimate_threshold
        self.batch_size_hint = batch_size_hint

        # 线性回归模型参数: estimated_time = w·features + b
        # features: [file_size_norm, sections_norm, imports_norm, entropy, stripped_flag]
        self._w: List[float] = [0.3, 0.05, 0.1, 0.15, 0.2]
        self._b: float = 10.0
        # 在线学习率
        self._lr: float = 0.01
        # 反馈历史
        self._feedback: List[Tuple[List[float], float]] = []  # (features, actual_time)

        self._queue: List[BinaryProfile] = []

    def profile_binary(
        self,
        binary_id: str,
        file_size: int,
        num_sections: int = 5,
        num_imports: int = 10,
        num_functions: int = 0,
        entropy: float = 6.0,
        is_stripped: bool = False,
    ) -> BinaryProfile:
        """为二进制构建复杂度画像并估计分析耗时。"""
        _feat = self._extract_features(
            file_size, num_sections, num_imports, num_functions,
            entropy, is_stripped,
        )
        _est = self._predict(_feat)

        return BinaryProfile(
            binary_id=binary_id,
            file_size=file_size,
            num_sections=num_sections,
            num_imports=num_imports,
            num_functions=num_functions,
            entropy=entropy,
            is_stripped=is_stripped,
            estimated_seconds=_est,
        )

    def enqueue(self, profiles: List[BinaryProfile]):
        """将二进制入队。"""
        self._queue.extend(profiles)

    def schedule(self) -> List[str]:
        """返回按SPT排序的二进制ID列表。"""
        self._queue.sort(key=lambda p: p.estimated_seconds)
        return [p.binary_id for p in self._queue]

    def schedule_batches(self) -> List[List[str]]:
        """按复杂度相近原则分组——减少上下文切换。"""
        _sorted = sorted(self._queue, key=lambda p: p.estimated_seconds)
        _batches: List[List[str]] = []
        _current: List[BinaryProfile] = []

        for _p in _sorted:
            if not _current:
                _current.append(_p)
            else:
                _first = _current[0].estimated_seconds
                if (abs(_p.estimated_seconds - _first) < _first * 0.3
                        and len(_current) < self.batch_size_hint):
                    _current.append(_p)
                else:
                    _batches.append([b.binary_id for b in _current])
                    _current = [_p]

        if _current:
            _batches.append([b.binary_id for b in _current])

        return _batches

    def feedback(self, binary_id: str, actual_seconds: float):
        """反馈实际分析耗时——在线更新回归模型。"""
        for _p in self._queue:
            if _p.binary_id == binary_id:
                _p.actual_seconds = actual_seconds

                # 若实际耗时远超估计→触发重新估计+模型更新
                if (_p.estimated_seconds > 0 and
                        actual_seconds > _p.estimated_seconds * self.reestimate_threshold):
                    _feat = self._extract_features(
                        _p.file_size, _p.num_sections, _p.num_imports,
                        _p.num_functions, _p.entropy, _p.is_stripped,
                    )
                    self._online_update(_feat, actual_seconds)
                break

    def estimate_remaining(self, completed: Set[str]) -> float:
        """估计剩余队列的总分析时间。"""
        _total = 0.0
        for _p in self._queue:
            if _p.binary_id not in completed:
                _total += _p.estimated_seconds
        return _total

    # 内部

    @staticmethod
    def _extract_features(
        file_size: int, sections: int, imports: int,
        functions: int, entropy: float, stripped: bool,
    ) -> List[float]:
        return [
            min(1.0, file_size / 100_000_000.0),   # 100MB归一化
            sections / 20.0,
            imports / 500.0,
            functions / 10000.0,
            entropy / 8.0,
            1.0 if stripped else 0.0,
        ]

    def _predict(self, features: List[float]) -> float:
        _z = self._b
        for _i in range(min(len(features), len(self._w))):
            _z += self._w[_i] * features[_i]
        return max(1.0, _z)

    def _online_update(self, features: List[float], actual: float):
        """SGD更新回归权重——最小化(预测-实际)²。"""
        _pred = self._predict(features)
        _error = _pred - actual

        for _i in range(min(len(features), len(self._w))):
            self._w[_i] -= self._lr * _error * features[_i]
        self._b -= self._lr * _error

        self._feedback.append((features, actual))
        if len(self._feedback) > 200:
            self._feedback = self._feedback[-200:]


# 冒烟测试
def _smoke_test():
    _scheduler = ComplexityAwareScheduler()
    _profiles = [
        _scheduler.profile_binary("small_bin", 500_000, 3, 50, 100, 5.5, False),
        _scheduler.profile_binary("large_stripped", 50_000_000, 8, 300, 0, 7.2, True),
        _scheduler.profile_binary("medium_bin", 5_000_000, 5, 150, 500, 6.1, False),
        _scheduler.profile_binary("tiny_bin", 50_000, 2, 10, 20, 4.0, False),
    ]
    _scheduler.enqueue(_profiles)

    _order = _scheduler.schedule()
    print(f"[sched] schedule order: {_order}")
    assert _order[0] == "tiny_bin", f"smallest binary should be first, got {_order[0]}"
    assert _order[-1] == "large_stripped", f"largest should be last, got {_order[-1]}"

    _batches = _scheduler.schedule_batches()
    print(f"[sched] batches: {len(_batches)} batches, sizes={[len(b) for b in _batches]}")

    # 反馈——更新模型
    _scheduler.feedback("tiny_bin", 12.0)
    _remaining = _scheduler.estimate_remaining({"tiny_bin"})
    print(f"[sched] remaining time: {_remaining:.1f}s")

    print("[OK] ComplexityAwareScheduler smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
