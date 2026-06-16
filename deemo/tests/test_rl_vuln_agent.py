#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试强化学习自主漏洞挖掘代理模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.rl_vuln_agent import (
    RLVulnAgent, QLearningAgent, DQNAgent, InputMutator, MutateAction,
    RLTrainingResult, VulnerabilityType, simulate_fuzzing
)


class TestRLVulnAgent:
    """测试强化学习漏洞挖掘代理"""

    def test_initialization(self):
        """测试初始化"""
        agent = RLVulnAgent(agent_type="qlearning")
        assert agent is not None
        assert agent.agent_type == "qlearning"
        
        agent_dqn = RLVulnAgent(agent_type="dqn")
        assert agent_dqn is not None
        assert agent_dqn.agent_type == "dqn"

    def test_input_mutator(self):
        """测试输入突变器"""
        mutator = InputMutator()
        
        original = b"AAAA"
        mutated = mutator.mutate(original, MutateAction.APPEND_BYTE)
        assert len(mutated) == len(original) + 1
        
        mutated = mutator.mutate(original, MutateAction.FLIP_BIT)
        assert len(mutated) == len(original)
        # 至少有一位被翻转
        assert mutated != original or original == b"\x00\x00\x00\x00"
        
        mutated = mutator.mutate(original, MutateAction.REPEAT_PAYLOAD)
        assert len(mutated) >= len(original)
        
        mutated = mutator.mutate(original, MutateAction.SET_MAX_VALUE)
        assert len(mutated) == len(original)
        
        # 测试随机突变
        mutated = mutator.random_mutate(original)
        assert mutated is not None

    def test_qlearning_agent(self):
        """测试Q-Learning代理"""
        actions = [action for action in MutateAction]
        agent = QLearningAgent(actions, alpha=0.1, gamma=0.9, epsilon=0.1)
        
        # 测试选择动作
        state = (0.5, 0.3, 0, 0)
        action = agent.select_action(state)
        assert action in actions
        
        # 测试学习
        agent.learn(state, action, 1.0, (0.6, 0.4, 1, 0))
        
        # 测试保存和加载
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        agent.save_q_table(temp_path)
        new_agent = QLearningAgent(actions)
        new_agent.load_q_table(temp_path)
        
        os.unlink(temp_path)

    def test_dqn_agent(self):
        """测试DQN代理"""
        actions = [action for action in MutateAction]
        agent = DQNAgent(actions)
        
        # 测试选择动作
        state = (0.5, 0.3, 0, 0)
        action = agent.select_action(state)
        assert action in actions
        
        # 测试学习（使用模拟数据）
        for _ in range(10):
            agent.learn(state, action, 0.5, (0.6, 0.4, 0, 0))

    def test_train_short(self):
        """测试短期训练"""
        agent = RLVulnAgent(agent_type="qlearning")
        
        result = agent.train(episodes=10, max_steps=5, verbose=False)
        
        assert isinstance(result, RLTrainingResult)
        assert result.total_episodes == 10
        assert result.total_crashes >= 0
        assert result.total_unique_crashes >= 0
        assert result.coverage >= 0
        
        # 验证奖励曲线不为空
        assert len(result.reward_history) > 0

    def test_run(self):
        """测试运行代理"""
        agent = RLVulnAgent(agent_type="qlearning")
        
        result = agent.run(max_iterations=10)
        
        assert isinstance(result, RLTrainingResult)
        assert result.total_episodes == 10

    def test_collect_statistics(self):
        """测试收集统计信息"""
        agent = RLVulnAgent(agent_type="qlearning")
        
        stats = agent.collect_statistics()
        
        assert 'total_inputs_tested' in stats
        assert 'crash_count' in stats
        assert 'unique_crash_count' in stats
        assert 'coverage' in stats
        assert 'average_reward' in stats

    def test_simulate_fuzzing(self):
        """测试模拟模糊测试便捷函数"""
        result = simulate_fuzzing(
            episodes=5,
            agent_type="qlearning",
            initial_input=b"test"
        )
        
        assert isinstance(result, RLTrainingResult)
        assert result.total_episodes == 5

    def test_save_and_load_agent(self):
        """测试保存和加载代理"""
        import tempfile
        
        agent = RLVulnAgent(agent_type="qlearning")
        agent.train(episodes=5, max_steps=3, verbose=False)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            agent.save(tmpdir)
            
            loaded_agent = RLVulnAgent.load(tmpdir)
            assert loaded_agent is not None
            assert loaded_agent.agent_type == "qlearning"

    def test_mutation_actions(self):
        """测试所有突变动作"""
        mutator = InputMutator()
        original = b"TEST_INPUT_123"
        
        for action in MutateAction:
            mutated = mutator.mutate(original, action)
            assert mutated is not None
            assert isinstance(mutated, bytes)

    def test_reward_calculation(self):
        """测试奖励计算"""
        agent = RLVulnAgent(agent_type="qlearning")
        
        # 测试崩溃奖励
        reward = agent._calculate_reward(
            crash=True,
            new_crash=True,
            coverage=0.5,
            prev_coverage=0.3,
            input_entropy=1.0
        )
        assert reward > 0
        
        # 测试无崩溃奖励
        reward = agent._calculate_reward(
            crash=False,
            new_crash=False,
            coverage=0.3,
            prev_coverage=0.3,
            input_entropy=0.5
        )
        assert reward >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])