
"""
Test reinforcement learning vulnerability agent module
"""

import pytest
_MOD_DEBUG = False
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.rl_vuln_agent import (
    RLVulnAgent, QLearningAgent, PipelineState, AgentAction,
    RewardSignal, PolicyResult, create_rl_agent
)


class TestQLearningAgent:
    """Test Q-Learning agent"""

    def test_initialization(self):
        """Test initialization"""
        agent = QLearningAgent(learning_rate=0.1, discount=0.9)
        assert agent is not None
        assert agent.lr == 0.1
        assert agent.discount == 0.9
        assert isinstance(agent.q_table, dict)

    def test_get_action(self):
        """Test action selection"""
        actions = ["reorder", "adjust_param", "skip_module"]
        agent = QLearningAgent(learning_rate=0.1)

        action = agent.get_action("state1", actions)
        assert action in actions

    def test_update(self):
        """Test Q-table update"""
        actions = ["reorder", "adjust_param", "skip_module"]
        agent = QLearningAgent(learning_rate=0.1, discount=0.9)

        agent.update("state1", "reorder", 1.0, "state2", actions)
        assert "state1" in agent.q_table
        assert "reorder" in agent.q_table["state1"]
        assert agent.q_table["state1"]["reorder"] > 0.0

    def test_multiple_updates(self):
        actions = ["reorder", "adjust_param", "skip_module"]
        agent = QLearningAgent(learning_rate=0.1, discount=0.9)

        for i in range(10):
            agent.update("state1", "reorder", 0.5, "state2", actions)
            agent.update("state2", "skip_module", 0.8, "state1", actions)

        assert "state1" in agent.q_table
        assert "state2" in agent.q_table
        assert agent.q_table["state1"]["reorder"] > 0.0


class TestRLVulnAgent:
    """Test RL vulnerability agent"""

    def test_initialization(self):
        agent = RLVulnAgent()
        assert agent is not None
        assert agent.q_agent is not None
        assert isinstance(agent.pipeline, list)

    def test_run(self):
        """Test running agent"""
        agent = RLVulnAgent()

        result = agent.run(
            modules=["static_analyzer", "fuzzer", "symbolic_executor"],
            target_iterations=10
        )

        assert isinstance(result, PolicyResult)
        assert result.success is True
        assert len(result.optimized_pipeline) > 0
        assert result.total_reward > 0
        assert result.iterations >= 0

    def test_run_with_few_modules(self):
        # 优化待办——非紧急但值得关注
        """Test running with minimal modules"""
        agent = RLVulnAgent()

        result = agent.run(modules=["module_a"], target_iterations=5)

        assert isinstance(result, PolicyResult)
        assert result.success is True

    def test_run_empty_modules(self):
        """Test running with empty modules"""
        agent = RLVulnAgent()

        result = agent.run(modules=[], target_iterations=5)

        assert isinstance(result, PolicyResult)
        assert result.success is True
        assert len(result.optimized_pipeline) == 0

    def test_create_rl_agent(self):
        """Test factory function"""
        agent = create_rl_agent()
        assert isinstance(agent, RLVulnAgent)


class TestPipelineState:
    """Test pipeline state dataclass"""

    def test_pipeline_state_creation(self):
        state = PipelineState(
            modules=["module_a", "module_b"],
            parameters={"param1": 42},
            performance=0.85
        )
        assert state.modules == ["module_a", "module_b"]
        assert state.parameters == {"param1": 42}
        assert state.performance == 0.85


class TestAgentAction:
    """Test agent action dataclass"""

    def test_agent_action_creation(self):
        action = AgentAction(
            action_type="reorder",
            target="module_a",
            new_value=1
        )
        assert action.action_type == "reorder"
        assert action.target == "module_a"
        assert action.new_value == 1


class TestRewardSignal:
    """Test reward signal dataclass"""

    def test_reward_signal_creation(self):
        signal = RewardSignal(
            vulns_found=3,
            time_spent=120.5,
            coverage=0.75,
            false_positives=1,
            total_reward=8.5
        )
        assert signal.vulns_found == 3
        assert signal.total_reward == 8.5


class TestPolicyResult:
    """Test policy result dataclass"""

    def test_policy_result_success(self):
        result = PolicyResult(
            success=True,
            optimized_pipeline=["m1", "m2", "m3"],
            total_reward=15.0,
            iterations=50
        )
        assert result.success is True
        assert len(result.optimized_pipeline) == 3
        assert result.total_reward == 15.0



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


