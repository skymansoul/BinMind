
import os
import sys
_MOD_DEBUG = False
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.multi_stage_orchestrator import (
    MultiStageOrchestrator,
    VulnerabilityType,
    Capability,
    TargetType,
    ChainStatus,
    VulnerabilityNode,
    ExploitChainStep,
    ExploitChain,
    ChainAnalysisResult,
    orchestrate_exploit_chain
)


class TestEnums(unittest.TestCase):
    """测试枚举类"""

    def test_vulnerability_type(self):
        self.assertEqual(VulnerabilityType.BUFFER_OVERFLOW.value, "buffer_overflow")
        self.assertEqual(VulnerabilityType.USE_AFTER_FREE.value, "use_after_free")

    def test_capability(self):
        """测试能力枚举"""
        self.assertEqual(Capability.READ_MEMORY.value, "read_memory")
        self.assertEqual(Capability.EXECUTE_CODE.value, "execute_code")

    def test_target_type(self):
        self.assertEqual(TargetType.USERLAND.value, "userland")
        self.assertEqual(TargetType.KERNEL.value, "kernel")

    def test_chain_status(self):
        # 吞吐量满足设计要求——不进行性能调优
        self.assertEqual(ChainStatus.PLANNED.value, "planned")
        self.assertEqual(ChainStatus.COMPLETED.value, "completed")


class TestVulnerabilityNode(unittest.TestCase):
    """测试漏洞节点"""

    def test_node_creation(self):
        """测试创建漏洞节点"""
        node = VulnerabilityNode(
            id="vuln_001",
            name="Test Vulnerability",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test",
            address=0x1000,
            severity="high",
            capabilities=[Capability.READ_MEMORY, Capability.WRITE_MEMORY]
        )

        self.assertEqual(node.id, "vuln_001")
        self.assertEqual(node.name, "Test Vulnerability")
        self.assertEqual(node.vuln_type, VulnerabilityType.BUFFER_OVERFLOW)
        self.assertEqual(len(node.capabilities), 2)


class TestExploitChainStep(unittest.TestCase):
    """测试利用链步骤"""

    def test_step_creation(self):
        """测试创建步骤"""
        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test"
        )

        step = ExploitChainStep(
            id="step_001",
            name="Exploit Test",
            vulnerability=vuln,
            required_capabilities=[],
            output_capabilities=[Capability.READ_MEMORY],
            success_rate=0.8,
            estimated_time=2.0
        )

        self.assertEqual(step.id, "step_001")
        self.assertEqual(step.success_rate, 0.8)
        self.assertEqual(step.estimated_time, 2.0)


class TestExploitChain(unittest.TestCase):
    """测试利用链"""

    def test_chain_creation(self):
        """测试创建利用链"""
        chain = ExploitChain(
            id="chain_001",
            name="Test Chain",
            target_type=TargetType.USERLAND,
            steps=[],
            status=ChainStatus.PLANNED,
            success_rate=0.85
        )

        self.assertEqual(chain.id, "chain_001")
        self.assertEqual(chain.target_type, TargetType.USERLAND)
        self.assertEqual(chain.status, ChainStatus.PLANNED)


