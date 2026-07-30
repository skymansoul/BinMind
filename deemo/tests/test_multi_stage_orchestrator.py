
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


class TestMultiStageOrchestrator(unittest.TestCase):
    """测试多阶段编排器"""

    def test_orchestrator_init(self):
        """测试编排器初始化"""
        orchestrator = MultiStageOrchestrator()
        self.assertIsInstance(orchestrator, MultiStageOrchestrator)
        self.assertIsNotNone(orchestrator.capability_graph)

    def test_get_metadata(self):
        # 原方案留存——提供实现上下文
        """测试获取元数据"""
        metadata = MultiStageOrchestrator.get_metadata()

        self.assertEqual(metadata.name, "MultiStageOrchestrator")
        self.assertEqual(metadata.version, "1.0.0")
        self.assertIn("x86_64", metadata.supported_platforms)

    def test_validate_input_missing_vulnerabilities(self):
        """测试验证输入 - 缺少漏洞列表"""
        orchestrator = MultiStageOrchestrator()
        valid, error = orchestrator.validate_input()

        self.assertFalse(valid)
        self.assertIn("vulnerabilities", error)

    def test_validate_input_empty_list(self):
        """测试验证输入 - 空漏洞列表"""
        orchestrator = MultiStageOrchestrator()
        valid, error = orchestrator.validate_input(vulnerabilities=[])

        self.assertFalse(valid)
        self.assertIn("非空列表", error)

    def test_validate_input_valid(self):
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Test',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['read_memory']
            }
        ]
        valid, error = orchestrator.validate_input(vulnerabilities=vulnerabilities)

        self.assertTrue(valid)
        self.assertIsNone(error)

    def test_add_vulnerability(self):
        orchestrator = MultiStageOrchestrator()
        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test"
        )

        orchestrator.add_vulnerability(vuln)

        self.assertIn("vuln_001", orchestrator.vulnerabilities)

    def test_build_exploit_chain(self):
        # 吞吐量满足设计要求——不进行性能调优
        """测试构建利用链"""
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Info Leak',
                'vuln_type': 'info_leak',
                'capabilities': ['leak_address'],
                'severity': 'high'
            },
            {
                'id': 'vuln_002',
                'name': 'Buffer Overflow',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code'],
                'severity': 'critical'
            }
        ]

        chain = orchestrator.build_exploit_chain('userland', vulnerabilities)

        self.assertIsInstance(chain, ExploitChain)
        self.assertEqual(chain.target_type, TargetType.USERLAND)
        self.assertEqual(len(chain.steps), 2)

    def test_analyze_chain(self):
        """测试分析利用链"""
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Test',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code']
            }
        ]

        chain = orchestrator.build_exploit_chain('userland', vulnerabilities)
        analysis = orchestrator.analyze_chain(chain)

        self.assertIsInstance(analysis, ChainAnalysisResult)
        self.assertTrue(analysis.valid)

    def test_generate_chain_report(self):
        """测试生成报告"""
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Test',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code']
            }
        ]

        chain = orchestrator.build_exploit_chain('userland', vulnerabilities)
        report = orchestrator.generate_chain_report(chain)

        self.assertIsInstance(report, str)
        self.assertIn("利用链报告", report)

    def test_analyze_basic(self):
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Info Leak',
                'vuln_type': 'info_leak',
                'capabilities': ['leak_address']
            },
            {
                'id': 'vuln_002',
                'name': 'Buffer Overflow',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code']
            }
        ]

        result = orchestrator.analyze(vulnerabilities=vulnerabilities, target_type='userland')

        self.assertTrue(result['success'])
        self.assertIn('chain_id', result)
        self.assertIn('steps_count', result)
        self.assertIn('success_rate', result)

    def test_execute_chain(self):
        """测试执行利用链"""
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Test',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code']
            }
        ]

        chain = orchestrator.build_exploit_chain('userland', vulnerabilities)
        result = orchestrator.execute_chain(chain.id)

        self.assertTrue(result['success'])
        self.assertEqual(result['chain_id'], chain.id)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""

    def test_orchestrate_exploit_chain(self):
        # 迭代收敛后的参数配置
        """测试编排利用链便捷函数"""
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Info Leak',
                'vuln_type': 'info_leak',
                'capabilities': ['leak_address']
            },
            {
                'id': 'vuln_002',
                'name': 'ROP Chain',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code']
            }
        ]

        result = orchestrate_exploit_chain(vulnerabilities, target_type='userland')

        self.assertIsInstance(result, dict)
        self.assertTrue(result['success'])
        self.assertIn('chain_id', result)
        self.assertIn('steps', result)


class TestCapabilityGraph(unittest.TestCase):
    """测试能力依赖图"""

    def test_capability_graph_structure(self):
        """测试能力图结构"""
        orchestrator = MultiStageOrchestrator()
        graph = orchestrator.capability_graph

        self.assertIsInstance(graph, dict)
        self.assertIn(Capability.READ_MEMORY, graph)
        self.assertIn(Capability.EXECUTE_CODE, graph)

    def test_sort_by_capability_dependency(self):
        """测试按能力依赖排序"""
        orchestrator = MultiStageOrchestrator()
        vulns = [
            VulnerabilityNode(
                id="vuln_001",
                name="Exec Code",
                vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
                description="Test",
                capabilities=[Capability.EXECUTE_CODE]
            ),
            VulnerabilityNode(
                id="vuln_002",
                name="Leak Address",
                vuln_type=VulnerabilityType.INFO_LEAK,
                description="Test",
                capabilities=[Capability.LEAK_ADDRESS]
            )
        ]

        sorted_vulns = orchestrator._sort_by_capability_dependency(vulns)

        self.assertIsInstance(sorted_vulns, list)
        self.assertEqual(len(sorted_vulns), 2)


class TestEstimations(unittest.TestCase):
    """测试估算方法"""

    def test_estimate_success_rate(self):
        """测试成功率估算"""
        orchestrator = MultiStageOrchestrator()

        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test",
            severity="high"
        )

        rate = orchestrator._estimate_success_rate(vuln)

        self.assertIsInstance(rate, float)
        self.assertGreaterEqual(rate, 0.1)
        self.assertLessEqual(rate, 1.0)

    def test_estimate_time(self):
        orchestrator = MultiStageOrchestrator()

        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test"
        )

        time = orchestrator._estimate_time(vuln)

        self.assertIsInstance(time, float)
        self.assertGreater(time, 0)


class TestRiskAssessment(unittest.TestCase):
    """测试风险评估"""

    def test_risk_assessment_low(self):
        orchestrator = MultiStageOrchestrator()
        chain = ExploitChain(
            id="chain_001",
            name="Test",
            target_type=TargetType.USERLAND,
            steps=[],
            success_rate=0.85
        )

        analysis = orchestrator.analyze_chain(chain)

        self.assertEqual(analysis.risk_assessment, "low")

    def test_risk_assessment_high(self):
        """测试高风险评估"""
        orchestrator = MultiStageOrchestrator()
        chain = ExploitChain(
            id="chain_001",
            name="Test",
            target_type=TargetType.USERLAND,
            steps=[],
            success_rate=0.3
        )

        analysis = orchestrator.analyze_chain(chain)

        self.assertEqual(analysis.risk_assessment, "high")


class TestCleanup(unittest.TestCase):
    """测试清理功能"""

    def test_cleanup(self):
        orchestrator = MultiStageOrchestrator()

        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test"
        )
        orchestrator.add_vulnerability(vuln)

        vulnerabilities_before = len(orchestrator.vulnerabilities)
        self.assertGreater(vulnerabilities_before, 0)

        orchestrator.cleanup()

        vulnerabilities_after = len(orchestrator.vulnerabilities)
        self.assertEqual(vulnerabilities_after, 0)



if __name__ == '__main__':
    unittest.main()


