# 将模糊测试的种子调度建模为bandit问题:
#   臂 = 种子, 奖励 = 新覆盖边数 / 触发崩溃 / 执行时间效率
# 在探索（试用新种子）与利用（反复变异高产种子）之间自适应平衡。
#
#   MobFuzz — Multi-Player MAB for multi-objective fuzzing
#   LinFuzz — LinUCB contextual bandit for seed scheduling
#   EcoFuzz — Adversarial MAB for power scheduling
#   Auer et al. 2002 "The Nonstochastic Multiarmed Bandit Problem" — EXP3
import math
import random
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
import time


class UCB1Selector:
    """标准UCB1: 每臂维护(选择次数, 累积奖励)，选上置信界最高者。

    arm_score = mean_reward + sqrt(2 * log(total_trials) / trials_arm)

    奖励值域 [0, inf)，高奖励种子获得更多选择机会。
    新种子（trials=0）优先选出以完成冷启动。
    """

    def __init__(self, exploration_bonus: float = 2.0):
        """
        exploration_bonus: UCB探索系数。>1偏向探索，<1偏向利用。默认2.0。
        """
        self._c = exploration_bonus
        self._arms: Dict[str, Dict[str, float]] = {}  # name -> {trials, reward, last_seen}
        self._total = 0

    def add_arm(self, name: str) -> None:
        if name not in self._arms:
            self._arms[name] = {"trials": 0.0, "reward": 0.0,
                               "last_seen": time.time()}

    def select(self) -> str:
        """选择一个臂。trials==0的臂优先选出（冷启动）。"""
        self._total += 1
        best_arm = None
        best_score = float('-inf')

        for name, stats in self._arms.items():
            if stats["trials"] < 1:
                return name  # 冷启动优先
            mean = stats["reward"] / stats["trials"]
            exploration = self._c * math.sqrt(
                math.log(self._total) / stats["trials"])
            score = mean + exploration
            if score > best_score:
                best_score = score
                best_arm = name

        return best_arm or next(iter(self._arms))

    def reward(self, name: str, value: float) -> None:
        """给予奖励。value建议归一化到[0, 10]。"""
        if name in self._arms:
            self._arms[name]["trials"] += 1
            self._arms[name]["reward"] += value
            self._arms[name]["last_seen"] = time.time()

    def prune_stale(self, max_age_s: float = 3600.0) -> int:
        """移除超时未使用的臂，释放内存。返回移除数。"""
        now = time.time()
        stale = [n for n, s in self._arms.items()
                 if now - s["last_seen"] > max_age_s]
        for name in stale:
            del self._arms[name]
        return len(stale)

    def arm_stats(self) -> Dict[str, Dict[str, float]]:
        return {
            name: {
                "trials": int(s["trials"]),
                "avg_reward": round(s["reward"] / s["trials"], 3)
                if s["trials"] > 0 else 0.0,
            }
            for name, s in self._arms.items()
        }

    def size(self) -> int:
        return len(self._arms)


class ThompsonSelector:
    """Thompson采样: 每臂维护Beta(alpha, beta)后验分布。

    奖励建模为二项结果(成功/失败)，由外部报告new_edges > 0为成功。
    每次选臂时从Beta分布采样，选采样值最高者。
    与UCB1不同，Thompson天然具备随机探索性（后验方差大的臂也有机会
    被选中），不需要显式探索项。

    参考Chapelle & Li 2011 "An Empirical Evaluation of Thompson Sampling"
    """

    def __init__(self):
        self._arms: Dict[str, Dict[str, float]] = {}  # name -> {alpha, beta}

    def add_arm(self, name: str, alpha: float = 1.0,
                beta: float = 1.0) -> None:
        if name not in self._arms:
            self._arms[name] = {"alpha": alpha, "beta": beta}

    def select(self) -> str:
        best_name = ""
        best_sample = -1.0
        for name, params in self._arms.items():
            sample = random.betavariate(
                max(0.1, params["alpha"]),
                max(0.1, params["beta"]))
            if sample > best_sample:
                best_sample = sample
                best_name = name
        return best_name or next(iter(self._arms), "")

    def reward(self, name: str, success: bool) -> None:
        """success=True -> alpha += 1, success=False -> beta += 1"""
        if name in self._arms:
            if success:
                self._arms[name]["alpha"] += 1.0
            else:
                self._arms[name]["beta"] += 1.0

    def expected_reward(self, name: str) -> float:
        params = self._arms.get(name)
        if params is None:
            return 0.0
        return params["alpha"] / (params["alpha"] + params["beta"])

    def stats(self) -> Dict[str, Dict[str, float]]:
        return {
            name: {
                "alpha": round(p["alpha"], 2),
                "beta": round(p["beta"], 2),
                "expected": round(
                    p["alpha"] / (p["alpha"] + p["beta"]), 3),
            }
            for name, p in self._arms.items()
        }


class EXP3Selector:
    """EXP3 (Exponential-weight for Exploration and Exploitation):
    对抗性bandit算法，不对奖励分布做任何假设。适用于非稳态奖励
    （如fuzzing过程中某种子突然发现大量新覆盖）。
    每臂维护权重w_i，选择概率p_i = (1-gamma)*(w_i/SUM(w_j)) + gamma/N。
    收到奖励后做重要性加权更新: w_i *= exp(gamma * reward_i / (N * p_i))。

    参考Auer et al. 2002, "The Nonstochastic Multiarmed Bandit Problem"
    及EcoFuzz的对抗性MAB应用。
    """

    def __init__(self, exploration_rate: float = 0.1):
        """
        exploration_rate (gamma): 均匀探索比例 [0, 1]。0.1=10%时间做均匀探索。
        较大值适合高度非稳态奖励流。
        """
        self._gamma = max(0.01, min(0.5, exploration_rate))
        self._weights: Dict[str, float] = {}
        self._names: List[str] = []

    def add_arm(self, name: str) -> None:
        if name not in self._weights:
            self._weights[name] = 1.0
            self._names.append(name)

    def select(self) -> str:
        if not self._names:
            return ""
        n = len(self._names)
        total_w = sum(self._weights[nm] for nm in self._names) or 1.0

        # 计算概率分布
        probs = []
        for nm in self._names:
            p = (1.0 - self._gamma) * (self._weights[nm] / total_w)
            p += self._gamma / n
            probs.append(p)

        # 轮盘赌选择
        r = random.random()
        acc = 0.0
        for i, p in enumerate(probs):
            acc += p
            if r <= acc:
                return self._names[i]
        return self._names[-1]

    def reward(self, name: str, value: float) -> None:
        """value in [0, 1]，做重要性加权更新权重。"""
        if name not in self._weights or not self._names:
            return
        n = len(self._names)
        total_w = sum(self._weights[nm] for nm in self._names) or 1.0
        prob = ((1.0 - self._gamma) * (self._weights[name] / total_w)
                + self._gamma / n)
        if prob <= 0:
            return
        # 重要性加权: 除以选择概率以纠正采样偏差
        scaled_reward = value / prob
        self._weights[name] *= math.exp(
            self._gamma * scaled_reward / n)
        # 权重截断防溢出
        self._weights[name] = min(
            self._weights[name], 1e6)

    def stats(self) -> Dict[str, Dict[str, float]]:
        total_w = sum(self._weights.values()) or 1.0
        return {
            name: {
                "weight": round(w, 2),
                "prob": round(w / total_w, 4),
            }
            for name, w in self._weights.items()
        }


class CompositeSeedSelector:
    """组合多种bandit策略的种子选择器。

    三种策略各有优势:
      UCB1: 确定性探索，适合稳定奖励
      Thompson: 贝叶斯探索，适合二项奖励
      EXP3: 对抗性探索，适合非稳态奖励
    最终选择通过加权投票决定。
    """

    def __init__(self):
        self._ucb1 = UCB1Selector()
        self._thompson = ThompsonSelector()
        self._exp3 = EXP3Selector()
        # 各策略的全局表现权重
        self._strategy_weights = {"ucb1": 1.0, "thompson": 1.0, "exp3": 1.0}
        self._strategy_success: Dict[str, List[float]] = defaultdict(list)

    def add_arm(self, name: str) -> None:
        self._ucb1.add_arm(name)
        self._thompson.add_arm(name)
        self._exp3.add_arm(name)

    def select(self) -> str:
        """三个选择器各提名一个种子，按策略历史成功率加权投票。"""
        candidates = {
            "ucb1": self._ucb1.select(),
            "thompson": self._thompson.select(),
            "exp3": self._exp3.select(),
        }
        # 统计票数（去重）
        votes: Dict[str, float] = defaultdict(float)
        for strategy, seed_id in candidates.items():
            if seed_id:
                votes[seed_id] += self._strategy_weights.get(strategy, 1.0)

        if not votes:
            return ""
        return max(votes, key=votes.get)

    def reward(self, name: str, new_edges: int) -> None:
        self._ucb1.reward(name, float(new_edges))
        self._thompson.reward(name, new_edges > 0)
        self._exp3.reward(name, min(1.0, new_edges / 10.0))

    def update_strategy_performance(self, strategy: str,
                                    was_successful: bool) -> None:
        """跟踪各策略长期成功率，用于加权投票。"""
        self._strategy_success[strategy].append(1.0 if was_successful else 0.0)
        recent = self._strategy_success[strategy][-32:]
        avg = sum(recent) / len(recent)
        self._strategy_weights[strategy] = 0.3 + avg * 2.0  # [0.3, 2.3]

    def prune_all(self, max_age_s: float = 3600.0) -> int:
        return self._ucb1.prune_stale(max_age_s)

    def global_stats(self) -> Dict[str, Any]:
        return {
            "ucb1_arms": self._ucb1.size(),
            "ucb1_stats": self._ucb1.arm_stats(),
            "thompson_stats": self._thompson.stats(),
            "exp3_stats": self._exp3.stats(),
            "strategy_weights": dict(self._strategy_weights),
        }
