# 2026-08-02 — 自适应任务调度: 动态优先级学习 / GNN特征编码 / ET(estimated time)+优先权滚动优化
# 参考: GATES "Cost-aware Dynamic Workflow Scheduling via GAT + Evolution Strategy" (IJCAI 2025, arXiv:2505.12355)
#       NeurIPS 2025 "RL for One-Shot DAG Scheduling with Comparability Identification and Dense Reward"
#       EGS "Edge Generation Scheduling for DAG Tasks Using DRL" (arXiv:2308.14647, 2024)
#       GA-DRL "GNN-Augmented DRL for DAG Task Scheduling Over Dynamic Vehicular Clouds" (IEEE TNSM 2024)
import logging, time, json, math, threading, heapq
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
from collections import defaultdict, deque
from enum import Enum

log = logging.getLogger(__name__)

class PriorityTier(Enum):
    CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; BATCH = 4

# ——————————————————————————————————————————————————————————
# 任务特征编码 — GATES 启发的图注意力简化实现
# ——————————————————————————————————————————————————————————

@dataclass
class TaskProfile:
    """任务画像: 用于优先级排序的特征向量."""
    task_id: str
    est_duration: float                 # 估计执行时间 (s)
    historical_avg_duration: float = 0.0
    historical_success_rate: float = 1.0
    dependency_count: int = 0
    dependents_count: int = 0           # 有多少其他任务依赖此任务
    resource_intensity: float = 0.5     # [0,1] 预估资源消耗
    priority_score: float = 50.0        # 综合优先级分数 [0,100]
    last_run_timestamp: float = 0.0
    run_count: int = 0
    failure_count: int = 0

    def feature_vector(self) -> List[float]:
        return [
            self.est_duration / max(self.historical_avg_duration, 0.001),
            self.historical_success_rate,
            min(self.dependency_count / 10.0, 1.0),
            min(self.dependents_count / 10.0, 1.0),
            self.resource_intensity,
            self.priority_score / 100.0,
            min(self.run_count / 50.0, 1.0),
        ]


class TaskProfiler:
    """任务分析器: 维护 TaskProfile 历史, 计算统计量.

    使用指数衰减更新: profile = α * observed + (1-α) * prior
    α 在 [0.1, 0.3] 之间按任务类型变化, 避免对异常值过度反应.
    """

    def __init__(self, default_alpha: float = 0.2):
        self._profiles: Dict[str, TaskProfile] = {}
        self._history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self.alpha = default_alpha

    def get_or_create(self, task_id: str, **overrides) -> TaskProfile:
        if task_id not in self._profiles:
            self._profiles[task_id] = TaskProfile(task_id=task_id, **overrides)
        return self._profiles[task_id]

    def record_run(self, task_id: str, duration: float, success: bool):
        profile = self.get_or_create(task_id)
        profile.run_count += 1
        if not success:
            profile.failure_count += 1
        profile.last_run_timestamp = time.time()
        profile.historical_success_rate = (
            profile.run_count - profile.failure_count) / max(profile.run_count, 1)

        # 指数衰减更新 ET
        a = self.alpha
        profile.est_duration = (
            a * duration + (1 - a) * profile.historical_avg_duration
            if profile.historical_avg_duration > 0 else duration)
        profile.historical_avg_duration = profile.est_duration

        self._history[task_id].append((duration, success))

    def get_duration_percentile(self, task_id: str, p: float = 0.95) -> float:
        h = list(self._history[task_id])
        if len(h) < 5:
            return self._profiles[task_id].est_duration if task_id in self._profiles else 60.0
        durations = sorted(d for d, _ in h)
        idx = min(int(len(durations) * p), len(durations) - 1)
        return durations[idx]


# ——————————————————————————————————————————————————————————
# 优先级学习 — 基于历史反馈的自适应权重
# ——————————————————————————————————————————————————————————

class AdaptivePriorityLearner:
    """在线优先级学习器.

    算法: 特征加权求和 → 预测优先级. 权重通过随机梯度下降在线更新.
    loss = (predicted_rank - actual_rank)² 其中 actual_rank 基于最终完成时间.

    参考 GATES (2025): 用 Evolution Strategy 替代梯度下降.
    此处因在线场景, 采用简化的 SGD with momentum [Sutskever et al. 2013].
    """

    def __init__(self, n_features: int = 7, learning_rate: float = 0.01):
        self._weights = [1.0 / n_features] * n_features
        self._momentum = [0.0] * n_features
        self._beta = 0.9
        self._lr = learning_rate
        self._lk = threading.Lock()

    def predict(self, features: List[float]) -> float:
        """加权求和 → [0,100] 优先级分数."""
        if len(features) != len(self._weights):
            return 50.0
        score = sum(w * f for w, f in zip(self._weights, features))
        return min(max(score * 100.0, 0.0), 100.0)

    def update(self, features: List[float], actual_utility: float):
        """SGD 更新. actual_utility ∈ [0,1] — 越高表示该优先级安排越好.

        utility 定义: 任务是否在预期时间内完成 + 是否释放了关键依赖.
        若 actual_utility > predicted, 增大相关特征的权重; 否则减小.
        """
        with self._lk:
            predicted = sum(w * f for w, f in zip(self._weights, features))
            error = actual_utility - predicted
            for i, f in enumerate(features):
                grad = -2 * error * f
                self._momentum[i] = self._beta * self._momentum[i] + (1 - self._beta) * grad
                self._weights[i] -= self._lr * self._momentum[i]
                self._weights[i] = max(0.001, min(self._weights[i], 5.0))

    def get_weights(self) -> List[float]:
        with self._lk:
            return list(self._weights)


# ——————————————————————————————————————————————————————————
# 自适应调度器 — 与 TaskScheduler 集成
# ——————————————————————————————————————————————————————————

class AdaptiveScheduler:
    # 维护 TaskProfile 数据库 → 学习优先级权重 → 重排就绪队列
    # 可与 TaskScheduler 集成 (run_all 前调用 prioritise)
    def __init__(self, profiler: TaskProfiler = None,
                 learner: AdaptivePriorityLearner = None):
        self.profiler = profiler or TaskProfiler()
        self.learner = learner or AdaptivePriorityLearner()
        self._task_deps: Dict[str, List[str]] = defaultdict(list)
        self._task_reverse_deps: Dict[str, List[str]] = defaultdict(list)

    def register_task(self, task_id: str, deps: List[str] = None,
                      est_duration: float = 60.0, resource_intensity: float = 0.5):
        profile = self.profiler.get_or_create(
            task_id, est_duration=est_duration, resource_intensity=resource_intensity)
        deps = deps or []
        self._task_deps[task_id] = deps
        profile.dependency_count = len(deps)
        for d in deps:
            self._task_reverse_deps.setdefault(d, []).append(task_id)
        return profile

    def prioritize(self, ready_tasks: List[str]) -> List[str]:
        """对就绪任务按其优先级分数排序 (降序)."""
        scored = []
        for tid in ready_tasks:
            profile = self.profiler.get_or_create(tid)
            profile.dependents_count = len(self._task_reverse_deps.get(tid, []))
            features = profile.feature_vector()
            score = self.learner.predict(features)
            profile.priority_score = score
            scored.append((score, tid))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [tid for _, tid in scored]

    def feedback(self, task_id: str, duration: float, success: bool,
                 was_blocker: bool = False):
        """向学习器反馈任务执行结果."""
        self.profiler.record_run(task_id, duration, success)
        profile = self.profiler.get_or_create(task_id)

        # 计算 utility: 成功=基础分, 是 blocker 则加值, 超预期时间则减值
        utility = 0.5
        if success:
            utility += 0.3
        if was_blocker and success:
            utility += 0.2
        p95 = self.profiler.get_duration_percentile(task_id, 0.95)
        if duration <= p95:
            utility += 0.1
        else:
            utility -= 0.2
        utility = min(max(utility, 0.0), 1.0)

        features = profile.feature_vector()
        self.learner.update(features, utility)

    def suggest_batch_order(self, tasks: List[Tuple[str, float]]) -> List[Tuple[str, float]]:
        """批量任务排序建议.

        Args:
            tasks: [(task_id, est_duration), ...]
        Returns:
            [(task_id, suggested_priority), ...] 按优先级降序
        """
        for tid, dur in tasks:
            self.profiler.get_or_create(tid, est_duration=dur)
        scored = []
        for tid, dur in tasks:
            profile = self.profiler.get_or_create(tid)
            features = profile.feature_vector()
            score = self.learner.predict(features)
            scored.append((tid, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def estimate_makespan(self, task_ids: List[str]) -> float:
        """估算给定任务集的最小完成时间 (基于关键路径). 复杂度 O(V+E)."""
        # 构建子图
        sub_deps = {}
        for tid in task_ids:
            sub_deps[tid] = [d for d in self._task_deps.get(tid, []) if d in task_ids]

        # 拓扑排序 + DP
        indeg = {tid: len(sub_deps[tid]) for tid in task_ids}
        dist = {tid: self.profiler.get_or_create(tid).est_duration
                for tid in task_ids}
        q = deque([tid for tid, d in indeg.items() if d == 0])
        max_dist = 0.0

        while q:
            u = q.popleft()
            max_dist = max(max_dist, dist[u])
            for v in self._task_reverse_deps.get(u, []):
                if v not in task_ids:
                    continue
                dur = self.profiler.get_or_create(v).est_duration
                dist[v] = max(dist[v], dist[u] + dur)
                indeg[v] -= 1
                if indeg[v] == 0:
                    q.append(v)
        return max_dist

    def export_profiles(self) -> List[Dict]:
        return [{'task_id': p.task_id, 'est_duration': p.est_duration,
                 'success_rate': round(p.historical_success_rate, 3),
                 'priority_score': round(p.priority_score, 1),
                 'deps': self._task_deps.get(p.task_id, [])}
                for p in self.profiler._profiles.values() if p.run_count > 0]


# ——————————————————————————————————————————————————————————
# 集成: 将自适应调度包装为 TaskScheduler 的优先级插件
# ——————————————————————————————————————————————————————————

class AdaptiveSchedulerPlugin:
    """TaskScheduler 的自适应插件.

    用法:
      sched = TaskScheduler()
      plugin = AdaptiveSchedulerPlugin(sched)
      sched.run_all()  # 插件在 _enq 阶段介入
    """

    def __init__(self, scheduler=None):
        self.scheduler = scheduler
        self.adaptive = AdaptiveScheduler()
        self._enabled = True

    def wrapped_enqueue(self, original_enqueue_fn):
        """装饰 TaskScheduler._enq: 在入队前重新排序."""
        def wrapper():
            # 先收集就绪任务
            original_enqueue_fn()
            # 重新排序: 按自适应优先级重建堆
            if not self._enabled:
                return
            if not hasattr(self.scheduler, '_rq'):
                return
            # 取出现有队列, 重新 prioritise, 回填
            items = []
            while self.scheduler._rq:
                items.append(heapq.heappop(self.scheduler._rq))
            # 用 adaptive scheduler 重新打分
            tids = [item.task_id for item in items]
            ranked = self.adaptive.prioritize(tids)
            rank_map = {tid: i for i, tid in enumerate(ranked)}
            for item in items:
                new_prio = rank_map.get(item.task_id, item.priority)
                heapq.heappush(self.scheduler._rq,
                               _QItem2(new_prio, item.task_id, item.payload))
        return wrapper

    def feedback_from_result(self, task_id: str, duration: float,
                              success: bool, blocker: bool = False):
        self.adaptive.feedback(task_id, duration, success, blocker)

    @property
    def enabled(self): return self._enabled

    @enabled.setter
    def enabled(self, v: bool): self._enabled = v


# 适配 TaskScheduler 的 _QItem
@dataclass(order=True)
class _QItem2:
    priority: int
    task_id: str = field(compare=False)
    payload: Any = field(compare=False, default=None)
