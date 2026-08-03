# 修改记录:
# 2025-07-17 13:06 - 引入指数衰减替代线性衰减，适配长周期fuzz（>8h）
# 2025-07-20 16:29 - 增加冷启动阶段的探索性随机扰动，避免初期偏差锁定
# 2025-07-24 10:53 - 实现双队列调度：主队列（novelty优先）+ 重访队列（衰减后复活）

"""
时态新颖度衰减调度器 —— 在现有 SeedRelationGraph 之上叠加时间维度的
新颖度评分，解决传统调度器"遗忘"已探索区域后无法适时重访的缺陷。

设计原理:
  传统调度器的隐含假设是"已探索=不再有价值"。但在安全测试中，
  以下情况需要重访旧区域：
    (a) fuzzer 发现了新的变异算子，旧区域可能暴露新的路径
    (b) 程序状态在长时间fuzz中积累，旧输入可能触发不同的状态转移
    (c) 其他fuzzer实例（分布式场景）可能改变了共享状态

  本模块引入"新颖度半衰期"机制：
  - 每个种子被调度后，其新颖度得分按指数衰减
  - 衰减到低于复活阈值后，种子进入重访队列
  - 重访队列中的种子经过足够的冷却期后，新颖度部分恢复
  - 类似于 Ebbinghaus 遗忘曲线——初始快速遗忘，随后缓慢衰减

与现有模块的关系:
  - SeedRelationGraph: 提供图结构信息（diversity_score, flow_centrality）
  - Scheduler: 作为替代的 pick_seed 策略（通过 strategy="temporal_novelty" 激活）
  - CorpusManager: 裁剪时参考 novelty_age 保留高潜力但当前低分种子

参考:
  - Graphuzz (ACM TOSEM 2024, doi:10.1145/3664603): 自注意力机制识别
    被忽略的特征分布——本模块的时间衰减可视为其注意力机制的显式替代。
  - SEAFuzz (IEEE QRS-C 2025): 稀有度加权结构相似性——本模块将其
    静态稀有度推广为动态时变稀有度。
  - Ebbinghaus 遗忘曲线 (1885): H = C - k log(t) —— 本模块的
    novelty(t) 衰减函数借鉴了该曲线的指数形式作为近似。
"""

import math
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 新颖度半衰期——经过此秒数后新颖度降至初始值的一半
_NOVELTY_HALFLIFE_SEC = 1800.0  # 30分钟
# 最小新颖度——低于此值触发复活检查
_MIN_NOVELTY = 0.10
# 复活冷却期——新颖度降至最低后需等待此秒数才能复活
_RESURRECTION_COOLDOWN_SEC = 600.0  # 10分钟
# 复活恢复比例——复活后新颖度恢复到的比例
_RESURRECTION_RECOVERY_RATIO = 0.40
# 重访队列最大容量
_REVISIT_QUEUE_MAX = 200
# 冷启动随机探索概率——前N次pick中以此概率随机选择
_COLD_START_RANDOM_PICKS = 50
_COLD_START_RANDOM_PROB = 0.25


@dataclass
class NoveltyRecord:
    """单个种子的时态新颖度追踪记录。"""

    seed_id: str
    novelty: float = 1.0               # 当前新颖度得分 (0..1)
    peak_novelty: float = 1.0          # 历史最高新颖度
    last_scheduled: float = 0.0        # 上次被调度的绝对时间戳
    schedule_count: int = 0            # 累计调度次数
    first_seen: float = field(default_factory=time.time)
    in_revisit_queue: bool = False     # 是否在重访队列中
    resurrection_count: int = 0        # 复活次数——限制以防止振荡
    max_resurrections: int = 3         # 单种子最大复活次数


class DecayingNoveltyScheduler:
    """基于时态衰减的新颖度种子调度器。

    与现有Scheduler的区别：
      Scheduler使用AFLfast的马尔可夫链——基于"最近是否产生新发现"
      这一即时反馈来调整概率，不记录历史状态。
      本调度器为每个种子维护独立的新颖度时间曲线，调度决策基于
      历史累积——适合长时间运行的fuzz任务（>4h）。

    使用方式:
      # 独立使用
      dns = DecayingNoveltyScheduler()
      dns.register_seed(seed_id, coverage_mask)
      next_seed = dns.pick_seed()  # 或 pick_seed_with_graph(srg)

      # 与Scheduler集成
      from fuzzing.src.scheduler import Scheduler
      sched = Scheduler(strategy="temporal_novelty")
      sched._novelty_engine = dns  # 注入
    """

    def __init__(
        self,
        halflife_sec: float = _NOVELTY_HALFLIFE_SEC,
        min_novelty: float = _MIN_NOVELTY,
        resurrection_cooldown: float = _RESURRECTION_COOLDOWN_SEC,
    ) -> None:
        self.halflife = halflife_sec
        self.min_novelty = min_novelty
        self.resurrection_cooldown = resurrection_cooldown

        self._records: Dict[str, NoveltyRecord] = {}
        self._revisit_queue: deque = deque(maxlen=_REVISIT_QUEUE_MAX)
        # 衰减常数：λ = ln(2) / halflife，保证经过halflife秒后novelty降至0.5
        self._decay_lambda = math.log(2) / halflife_sec
        self._pick_count: int = 0

    # ---- 注册与管理 ----

    def register_seed(
        self, seed_id: str, coverage_mask: Optional[Set[int]] = None
    ) -> None:
        """注册新种子——初始新颖度=1.0，时间戳=now。

        若种子已注册，不覆盖现有记录（保留历史状态）。
        """
        if seed_id not in self._records:
            self._records[seed_id] = NoveltyRecord(seed_id=seed_id)

    def remove_seed(self, seed_id: str) -> None:
        self._records.pop(seed_id, None)
        # 清理重访队列中的对应条目
        self._revisit_queue = deque(
            [sid for sid in self._revisit_queue if sid != seed_id],
            maxlen=_REVISIT_QUEUE_MAX,
        )

    def seed_count(self) -> int:
        return len(self._records)

    # ---- 新颖度衰减计算 ----

    def _compute_current_novelty(self, record: NoveltyRecord) -> float:
        """基于指数衰减模型计算当前新颖度。

        novelty(t) = novelty(t0) * exp(-λ * (t - t0))
        其中 λ = ln(2) / halflife

        此公式保证：
          - 经过1个halflife: novelty = 原始值 * 0.5
          - 经过2个halflife: novelty = 原始值 * 0.25
          - 长时间后趋近于0但不等于0（与线性衰减的本质区别）
        """
        if record.last_scheduled == 0.0:
            return record.novelty

        elapsed = time.time() - record.last_scheduled
        if elapsed <= 0:
            return record.novelty

        decayed = record.novelty * math.exp(-self._decay_lambda * elapsed)
        return max(self.min_novelty / 2.0, decayed)

    def _decay_all(self) -> None:
        """批量更新所有记录的新颖度——在pick_seed前调用一次。"""
        now = time.time()
        for rec in self._records.values():
            if rec.last_scheduled > 0:
                elapsed = now - rec.last_scheduled
                if elapsed > 0:
                    rec.novelty = rec.novelty * math.exp(-self._decay_lambda * elapsed)
                    rec.last_scheduled = now

    # ---- 种子选择 ----

    def pick_seed(self) -> Optional[str]:
        """选择下一个种子——双队列策略。

        主逻辑：
          1. 主队列：按当前新颖度降序排列所有种子，选最高的
          2. 重访队列：若存在冷却期满的种子，以概率0.15从重访队列选择
          3. 冷启动阶段（前50次pick）：以概率0.25随机探索

        双队列设计避免了"新颖度最高的种子永远被选"的贪婪陷阱——
        高新颖度种子被选后衰减，让其他种子有机会。
        """
        self._decay_all()
        self._pick_count += 1

        # 冷启动随机探索——避免初期偏差在长期运行中被放大
        if self._pick_count <= _COLD_START_RANDOM_PICKS:
            if random.random() < _COLD_START_RANDOM_PROB and len(self._records) > 1:
                return random.choice(list(self._records.keys()))

        # 处理重访队列
        resurrected = self._try_resurrect()
        if resurrected and random.random() < 0.15:
            return resurrected

        if not self._records:
            return None

        # 主队列：新颖度最高的种子
        best_id = max(self._records, key=lambda sid: self._records[sid].novelty)
        rec = self._records[best_id]

        # 标记调度并衰减
        rec.last_scheduled = time.time()
        rec.schedule_count += 1
        rec.novelty = self._compute_current_novelty(rec)

        # 如果衰减后低于阈值，加入重访队列
        if rec.novelty <= self.min_novelty and not rec.in_revisit_queue:
            rec.in_revisit_queue = True
            self._revisit_queue.append(best_id)

        return best_id

    def pick_seed_with_graph(
        self, relation_graph=None
    ) -> Optional[str]:
        """结合关系图信息的增强种子选择。

        综合评分 = α * novelty_score + (1-α) * diversity_from_graph
        其中 α = 0.6（新颖度权重略高于图多样性，因新颖度本身
        已经隐含了时间维度的多样性）。
        """
        alpha = 0.6
        self._decay_all()
        self._pick_count += 1

        if not self._records:
            return None

        best_id = None
        best_score = -1.0

        for sid, rec in self._records.items():
            graph_diversity = 0.5  # 默认中性
            if relation_graph is not None:
                try:
                    graph_diversity = relation_graph.diversity_score(sid)
                except Exception:
                    pass

            combined = alpha * rec.novelty + (1.0 - alpha) * graph_diversity

            # 小随机噪声——打破确定性平局
            combined += random.uniform(-0.02, 0.02)

            if combined > best_score:
                best_score = combined
                best_id = sid

        if best_id:
            rec = self._records[best_id]
            rec.last_scheduled = time.time()
            rec.schedule_count += 1
            rec.novelty = self._compute_current_novelty(rec)
            if rec.novelty <= self.min_novelty and not rec.in_revisit_queue:
                rec.in_revisit_queue = True
                self._revisit_queue.append(best_id)

        return best_id

    # ---- 复活机制 ----

    def _try_resurrect(self) -> Optional[str]:
        """检查重访队列中是否有冷却期满的候选种子。"""
        now = time.time()
        candidates = []
        for sid in list(self._revisit_queue):
            rec = self._records.get(sid)
            if rec is None:
                continue
            time_since_last = now - rec.last_scheduled
            if (time_since_last >= self.resurrection_cooldown
                    and rec.resurrection_count < rec.max_resurrections):
                candidates.append((sid, time_since_last))
        if not candidates:
            return None
        # 选择冷却时间最长的——最"新鲜"的旧种子
        candidates.sort(key=lambda x: x[1], reverse=True)
        chosen = candidates[0][0]
        rec = self._records[chosen]
        rec.novelty = _RESURRECTION_RECOVERY_RATIO
        rec.in_revisit_queue = False
        rec.resurrection_count += 1
        rec.last_scheduled = now
        # 从重访队列移除
        self._revisit_queue = deque(
            [sid for sid in self._revisit_queue if sid != chosen],
            maxlen=_REVISIT_QUEUE_MAX,
        )
        return chosen

    # ---- 统计与诊断 ----

    def novelty_distribution(self) -> Dict[str, float]:
        """返回所有种子当前新颖度分布的快照。"""
        self._decay_all()
        return {sid: rec.novelty for sid, rec in self._records.items()}

    def stats(self) -> dict:
        self._decay_all()
        if not self._records:
            return {"total_seeds": 0}

        novelties = [r.novelty for r in self._records.values()]
        schedules = [r.schedule_count for r in self._records.values()]
        resurrected = sum(1 for r in self._records.values() if r.resurrection_count > 0)

        return {
            "total_seeds": len(self._records),
            "mean_novelty": sum(novelties) / len(novelties),
            "max_novelty": max(novelties),
            "min_novelty": min(novelties),
            "in_revisit_queue": len(self._revisit_queue),
            "total_picks": self._pick_count,
            "mean_schedules_per_seed": sum(schedules) / max(1, len(schedules)),
            "resurrected_seeds": resurrected,
        }

    def get_revisit_candidates(self) -> List[str]:
        """返回重访队列中冷却期满的候选种子列表——供外部工具展示。"""
        now = time.time()
        return [
            sid for sid in self._revisit_queue
            if sid in self._records
            and (now - self._records[sid].last_scheduled) >= self.resurrection_cooldown
        ]
