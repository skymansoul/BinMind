import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.vuln_propagation import (
    VulnPropagationAnalyzer,
    VulnerabilityNode,
    analyze_vuln_propagation,
    build_program_dependency_graph,
    find_affected_functions
)


class TestVulnPropagationAnalyzer(unittest.TestCase):
    def test_analyzer_init(self):
        analyzer = VulnPropagationAnalyzer('/path/to/binary')
        self.assertEqual(analyzer.binary_path, '/path/to/binary')
    
    def test_build_dependency_graph(self):
        analyzer = VulnPropagationAnalyzer()
        binary_analysis = {
            'functions': {
                'func1': {'calls': ['func2', 'func3']},
                'func2': {'calls': ['func4']},
                'func3': {'calls': []},
                'func4': {'calls': []}
            },
            'data_flows': [
                {'source': 'func1', 'target': 'func2', 'confidence': 0.9}
            ]
        }
        analyzer.build_dependency_graph(binary_analysis)
        self.assertGreater(analyzer.propagation_graph.number_of_nodes(), 0)
    
    def test_add_vulnerability_source(self):
        analyzer = VulnPropagationAnalyzer()
        vuln_info = {
            'id': 'CVE-2024-1234',
            'name': 'Test Vulnerability',
            'description': 'A test vulnerability',
            'severity': 'high',
            'location': 'func1'
        }
        node_id = analyzer.add_vulnerability_source(vuln_info)
        self.assertIn(node_id, analyzer.vulnerability_nodes)
    
    def test_propagate_vulnerability(self):
        analyzer = VulnPropagationAnalyzer()
        binary_analysis = {
            'functions': {
                'func1': {'calls': ['func2']},
                'func2': {'calls': ['func3']},
                'func3': {'calls': []}
            },
            'data_flows': [
                {'source': 'func1', 'target': 'func2'},
                {'source': 'func2', 'target': 'func3'}
            ]
        }
        analyzer.build_dependency_graph(binary_analysis)
        analyzer.add_vulnerability_source({'id': 'test', 'location': 'func1'})
        paths = analyzer.propagate_vulnerability('vuln_test')
        self.assertIsInstance(paths, list)
    
    def test_analyze_vuln_propagation(self):
        vuln_info = {
            'id': 'CVE-2024-1234',
            'name': 'Test Vulnerability',
            'severity': 'high'
        }
        binary_analysis = {
            'functions': {
                'func1': {'calls': ['func2']},
                'func2': {'calls': []}
            },
            'data_flows': []
        }
        result = analyze_vuln_propagation(vuln_info, binary_analysis)
        self.assertEqual(result.vulnerability_id, 'CVE-2024-1234')
        self.assertIsInstance(result.propagation_graph, object)
    
    def test_generate_report(self):
        analyzer = VulnPropagationAnalyzer()
        vuln_info = {'id': 'test', 'name': 'Test', 'severity': 'medium'}
        binary_analysis = {
            'functions': {'func1': {'calls': []}},
            'data_flows': []
        }
        result = analyzer.analyze(vuln_info, binary_analysis)
        report = analyzer.generate_report(result)
        self.assertIsInstance(report, str)
        self.assertIn('漏洞传播路径分析报告', report)


if __name__ == '__main__':
    unittest.main()
