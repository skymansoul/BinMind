# 汤普森采样弹性伸缩器算法验证
# 汤普森采样是探索-利用权衡的贝叶斯方法。
# 每个动作 (scale_up/scale_down/maintain) 有一个 Beta(alpha, beta) 后验。
# 采样器选择采样值最高的动作 — 自然平衡了
# 探索 (不确定的动作分布更宽) 和利用 (已证明有效的动作)。
# 关键属性: (1) Beta 更新正确, (2) 决策遵守 min/max 边界,
# (3) 奖励观察正确反馈到所选动作。
"""
汤普森采样弹性伸缩器测试：Beta 更新、决策边界、奖励反馈。
"""
import math
import pytest
from ..src.thompson_autoscaler import ThompsonAutoscaler, ScaleAction


class TestScaleAction:
    """单个动作的 Beta 后验更新。"""

    def test_initial_beta_is_uniform(self):
        action = ScaleAction("test", alpha=1.0, beta=1.0)
        mean = action.alpha / (action.alpha + action.beta)
        assert mean == 0.5  # Beta(1,1) = Uniform(0,1)

    def test_positive_reward_increases_alpha(self):
        action = ScaleAction("test", alpha=1.0, beta=1.0)
        action.update(0.8)  # 好奖励
        assert action.alpha > 1.0
        assert action.beta == 1.0

    def test_negative_reward_increases_beta(self):
        action = ScaleAction("test", alpha=1.0, beta=1.0)
        action.update(0.2)  # 差奖励
        assert action.alpha == 1.0
        assert action.beta > 1.0

    def test_sample_in_range(self):
        action = ScaleAction("test", alpha=5.0, beta=2.0)
        for _ in range(100):
            s = action.sample()
            assert 0.0 < s < 1.0

    def test_sample_converges_with_many_observations(self):
        """大量正向奖励后均值应变高。"""
        action = ScaleAction("test", alpha=1.0, beta=1.0)
        for _ in range(100):
            action.update(0.9)
        mean = action.alpha / (action.alpha + action.beta)
        assert mean > 0.7


class TestThompsonAutoscaler:
    """完整弹性伸缩器：决策逻辑、边界强制、奖励闭环。"""

    def test_initial_worker_count(self):
        scaler = ThompsonAutoscaler(min_workers=2, max_workers=8)
        assert scaler.current_workers == (2 + 8) // 2  # 中间值

    def test_scale_up_never_exceeds_max(self):
        scaler = ThompsonAutoscaler(min_workers=1, max_workers=4)
        # 人工设置当前值为 max 并偏向 scale_up
        scaler._current = 4
        scaler._actions["scale_up"].alpha = 100.0
        scaler._actions["scale_up"].beta = 1.0
        result = scaler.decide(queue_depth=1000, avg_task_time_ms=5000, cpu_util=0.99)
        assert result <= 4

    def test_scale_down_never_below_min(self):
        scaler = ThompsonAutoscaler(min_workers=1, max_workers=4)
        scaler._current = 1
        scaler._actions["scale_down"].alpha = 100.0
        scaler._actions["scale_down"].beta = 1.0
        result = scaler.decide(queue_depth=0, avg_task_time_ms=1, cpu_util=0.01)
        assert result >= 1

    def test_observe_reward_updates_last_action(self):
        scaler = ThompsonAutoscaler(min_workers=1, max_workers=8)
        # 做一次决策以记录最后一个动作
        scaler.decide(queue_depth=10, avg_task_time_ms=100, cpu_util=0.5)
        last_action = scaler._history[-1][2]
        old_alpha = scaler._actions[last_action].alpha
        old_beta = scaler._actions[last_action].beta

        # 观察一个正向奖励
        scaler.observe_reward(throughput_delta=0.5, latency_delta=-0.3)
        # reward = 0.6*0.5 + 0.4*0.3 = 0.3 + 0.12 = 0.42
        # reward < 0.5 → beta 增加
        new_beta = scaler._actions[last_action].beta
        # reward=0.42 (< 0.5), beta 应增加 (1.0-0.42)=0.58
        expected_beta = old_beta + 0.58
        assert abs(new_beta - expected_beta) < 0.01

    def test_observe_high_reward_updates_alpha(self):
        scaler = ThompsonAutoscaler(min_workers=1, max_workers=8)
        scaler.decide(queue_depth=10, avg_task_time_ms=100, cpu_util=0.5)
        last_action = scaler._history[-1][2]
        old_alpha = scaler._actions[last_action].alpha

        # 观察一个很高的正向奖励
        scaler.observe_reward(throughput_delta=2.0, latency_delta=-2.0)
        # reward = min(1.0, max(0.0, 0.6*2.0 + 0.4*2.0)) = min(1.0, 2.0) = 1.0
        # reward >= 0.5 → alpha 增加 reward = 1.0
        expected_alpha = old_alpha + 1.0
        assert abs(scaler._actions[last_action].alpha - expected_alpha) < 0.01

    def test_history_grows_with_decisions(self):
        scaler = ThompsonAutoscaler()
        for i in range(5):
            scaler.decide(queue_depth=i * 3, avg_task_time_ms=50, cpu_util=0.3)
        assert len(scaler._history) == 5

    def test_stats_contains_all_actions(self):
        scaler = ThompsonAutoscaler()
        stats = scaler.get_stats()
        assert "current" in stats
        assert "actions" in stats
        for name in ["scale_up", "scale_down", "maintain"]:
            assert name in stats["actions"]
            assert "alpha" in stats["actions"][name]
            assert "beta" in stats["actions"][name]
            assert "mean" in stats["actions"][name]

    def test_maintain_action_is_default_safe_choice(self):
        """均匀先验下 maintain 动作应有时被选择。"""
        scaler = ThompsonAutoscaler(min_workers=2, max_workers=4)
        choices = set()
        for _ in range(50):
            scaler.decide(queue_depth=5, avg_task_time_ms=100, cpu_util=0.4)
            choices.add(scaler._history[-1][2])
        assert "maintain" in choices  # 均匀先验下所有动作都可能被选
