# -*- coding: utf-8 -*-

import os
import sys
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
    orchestrate_exploit_chain,
)


class TestEnums(unittest.TestCase):

    def test_vulnerability_type(self):
        self.assertEqual(VulnerabilityType.BUFFER_OVERFLOW.value, "buffer_overflow")
        self.assertEqual(VulnerabilityType.USE_AFTER_FREE.value, "use_after_free")

    def test_capability(self):
        self.assertEqual(Capability.READ_MEMORY.value, "read_memory")
        self.assertEqual(Capability.EXECUTE_CODE.value, "execute_code")

    def test_target_type(self):
        self.assertEqual(TargetType.USERLAND.value, "userland")
        self.assertEqual(TargetType.KERNEL.value, "kernel")

    def test_chain_status(self):
        self.assertEqual(ChainStatus.PLANNED.value, "planned")
        self.assertEqual(ChainStatus.COMPLETED.value, "completed")


class TestVulnerabilityNode(unittest.TestCase):

    def test_creation(self):
        node = VulnerabilityNode(
            id="vuln_001",
            name="Test Vulnerability",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test",
            address=0x1000,
            severity="high",
            capabilities=[Capability.READ_MEMORY, Capability.WRITE_MEMORY],
        )
        self.assertEqual(node.id, "vuln_001")
        self.assertEqual(node.name, "Test Vulnerability")
        self.assertEqual(node.vuln_type, VulnerabilityType.BUFFER_OVERFLOW)
        self.assertEqual(len(node.capabilities), 2)


class TestExploitChainStep(unittest.TestCase):

    def test_creation(self):
        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test",
        )
        step = ExploitChainStep(
            id="step_001",
            name="Exploit Test",
            vulnerability=vuln,
            required_capabilities=[],
            output_capabilities=[Capability.READ_MEMORY],
            success_rate=0.8,
            estimated_time=2.0,
        )
        self.assertEqual(step.id, "step_001")
        self.assertEqual(step.success_rate, 0.8)
        self.assertEqual(step.estimated_time, 2.0)


class TestExploitChain(unittest.TestCase):

    def test_creation(self):
        chain = ExploitChain(
            id="chain_001",
            name="Test Chain",
            target_type=TargetType.USERLAND,
            steps=[],
            status=ChainStatus.PLANNED,
            success_rate=0.85,
        )
        self.assertEqual(chain.id, "chain_001")
        self.assertEqual(chain.target_type, TargetType.USERLAND)
        self.assertEqual(chain.status, ChainStatus.PLANNED)


class TestMultiStageOrchestrator(unittest.TestCase):

    def test_init(self):
        orchestrator = MultiStageOrchestrator()
        self.assertIsInstance(orchestrator, MultiStageOrchestrator)
        self.assertIsNotNone(orchestrator.capability_graph)

    def test_get_metadata(self):
        metadata = MultiStageOrchestrator.get_metadata()
        self.assertEqual(metadata.name, "MultiStageOrchestrator")
        self.assertEqual(metadata.version, "1.0.0")
        self.assertIn("x86_64", metadata.supported_platforms)

    def test_validate_missing_vulnerabilities(self):
        orchestrator = MultiStageOrchestrator()
        valid, error = orchestrator.validate_input()
        self.assertFalse(valid)
        self.assertIn("vulnerabilities", error)

    def test_validate_empty_list(self):
        orchestrator = MultiStageOrchestrator()
        valid, error = orchestrator.validate_input(vulnerabilities=[])
        self.assertFalse(valid)
        self.assertIn("非空list", error)

    def test_validate_valid(self):
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [{
            'id': 'vuln_001',
            'name': 'Test',
            'vuln_type': 'buffer_overflow',
            'capabilities': ['read_memory'],
        }]
        valid, error = orchestrator.validate_input(vulnerabilities=vulnerabilities)
        self.assertTrue(valid)
        self.assertIsNone(error)

    def test_add_vulnerability(self):
        orchestrator = MultiStageOrchestrator()
        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test",
        )
        orchestrator.add_vulnerability(vuln)
        self.assertIn("vuln_001", orchestrator.vulnerabilities)

    def test_build_exploit_chain(self):
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Info Leak',
                'vuln_type': 'info_leak',
                'capabilities': ['leak_address'],
                'severity': 'high',
            },
            {
                'id': 'vuln_002',
                'name': 'Buffer Overflow',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code'],
                'severity': 'critical',
            },
        ]
        chain = orchestrator.build_exploit_chain('userland', vulnerabilities)
        self.assertIsInstance(chain, ExploitChain)
        self.assertEqual(chain.target_type, TargetType.USERLAND)
        self.assertEqual(len(chain.steps), 2)

    def test_analyze_chain(self):
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [{
            'id': 'vuln_001',
            'name': 'Test',
            'vuln_type': 'buffer_overflow',
            'capabilities': ['execute_code'],
        }]
        chain = orchestrator.build_exploit_chain('userland', vulnerabilities)
        analysis = orchestrator.analyze_chain(chain)
        self.assertIsInstance(analysis, ChainAnalysisResult)
        self.assertTrue(analysis.valid)

    def test_generate_chain_report(self):
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [{
            'id': 'vuln_001',
            'name': 'Test',
            'vuln_type': 'buffer_overflow',
            'capabilities': ['execute_code'],
        }]
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
                'capabilities': ['leak_address'],
            },
            {
                'id': 'vuln_002',
                'name': 'Buffer Overflow',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code'],
            },
        ]
        result = orchestrator.analyze(
            vulnerabilities=vulnerabilities, target_type='userland'
        )
        self.assertTrue(result['success'])
        self.assertIn('chain_id', result)
        self.assertIn('steps_count', result)
        self.assertIn('success_rate', result)

    def test_execute_chain(self):
        orchestrator = MultiStageOrchestrator()
        vulnerabilities = [{
            'id': 'vuln_001',
            'name': 'Test',
            'vuln_type': 'buffer_overflow',
            'capabilities': ['execute_code'],
        }]
        chain = orchestrator.build_exploit_chain('userland', vulnerabilities)
        result = orchestrator.execute_chain(chain.id)
        self.assertTrue(result['success'])
        self.assertEqual(result['chain_id'], chain.id)


class TestConvenienceFunctions(unittest.TestCase):

    def test_orchestrate_exploit_chain(self):
        vulnerabilities = [
            {
                'id': 'vuln_001',
                'name': 'Info Leak',
                'vuln_type': 'info_leak',
                'capabilities': ['leak_address'],
            },
            {
                'id': 'vuln_002',
                'name': 'ROP Chain',
                'vuln_type': 'buffer_overflow',
                'capabilities': ['execute_code'],
            },
        ]
        result = orchestrate_exploit_chain(vulnerabilities, target_type='userland')
        self.assertIsInstance(result, dict)
        self.assertTrue(result['success'])
        self.assertIn('chain_id', result)
        self.assertIn('steps', result)


class TestCapabilityGraph(unittest.TestCase):

    def test_graph_structure(self):
        orchestrator = MultiStageOrchestrator()
        graph = orchestrator.capability_graph
        self.assertIsInstance(graph, dict)
        self.assertIn(Capability.READ_MEMORY, graph)
        self.assertIn(Capability.EXECUTE_CODE, graph)

    def test_sort_by_capability_dependency(self):
        orchestrator = MultiStageOrchestrator()
        vulns = [
            VulnerabilityNode(
                id="vuln_001",
                name="Exec Code",
                vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
                description="Test",
                capabilities=[Capability.EXECUTE_CODE],
            ),
            VulnerabilityNode(
                id="vuln_002",
                name="Leak Address",
                vuln_type=VulnerabilityType.INFO_LEAK,
                description="Test",
                capabilities=[Capability.LEAK_ADDRESS],
            ),
        ]
        sorted_vulns = orchestrator._sort_by_capability_dependency(vulns)
        self.assertIsInstance(sorted_vulns, list)
        self.assertEqual(len(sorted_vulns), 2)


class TestEstimations(unittest.TestCase):

    def test_estimate_success_rate(self):
        orchestrator = MultiStageOrchestrator()
        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test",
            severity="high",
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
            description="Test",
        )
        time = orchestrator._estimate_time(vuln)
        self.assertIsInstance(time, float)
        self.assertGreater(time, 0)


class TestRiskAssessment(unittest.TestCase):

    def test_risk_low(self):
        orchestrator = MultiStageOrchestrator()
        chain = ExploitChain(
            id="chain_001",
            name="Test",
            target_type=TargetType.USERLAND,
            steps=[],
            success_rate=0.85,
        )
        analysis = orchestrator.analyze_chain(chain)
        self.assertEqual(analysis.risk_assessment, "low")

    def test_risk_high(self):
        orchestrator = MultiStageOrchestrator()
        chain = ExploitChain(
            id="chain_001",
            name="Test",
            target_type=TargetType.USERLAND,
            steps=[],
            success_rate=0.3,
        )
        analysis = orchestrator.analyze_chain(chain)
        self.assertEqual(analysis.risk_assessment, "high")


class TestCleanup(unittest.TestCase):

    def test_cleanup(self):
        orchestrator = MultiStageOrchestrator()
        vuln = VulnerabilityNode(
            id="vuln_001",
            name="Test",
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            description="Test",
        )
        orchestrator.add_vulnerability(vuln)
        self.assertGreater(len(orchestrator.vulnerabilities), 0)
        orchestrator.cleanup()
        self.assertEqual(len(orchestrator.vulnerabilities), 0)


if __name__ == '__main__':
    unittest.main()
