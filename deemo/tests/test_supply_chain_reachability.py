"""
供应链漏洞可达性分析模块测试
"""

import pytest
from modules.supply_chain_reachability import SupplyChainReachability, ReachabilityStatus


class TestSupplyChainReachability:
    """供应链可达性分析器测试类"""
    
    def test_analyze_basic(self):
        """测试基本分析功能"""
        analyzer = SupplyChainReachability()
        
        result = analyzer.analyze(
            binary_path='/path/to/binary',
            call_graph={
                'main': {'parse_input', 'process_data'},
                'parse_input': {'strcpy', 'malloc'},
                'process_data': {'openssl_encrypt'}
            },
            entry_points=['main']
        )
        
        assert result['success'] is True
        assert 'report' in result
        assert 'summary' in result
    
    def test_check_function_reachability(self):
        """测试函数可达性检查"""
        analyzer = SupplyChainReachability()
        
        analyzer.call_graph = {
            'main': {'func_a', 'func_b'},
            'func_a': {'target_func'},
            'func_b': {'other_func'}
        }
        analyzer.entry_points = {'main'}
        
        result = analyzer._check_function_reachability('target_func')
        
        assert result['status'] == ReachabilityStatus.REACHABLE
        assert result['score'] > 0.0
    
    def test_find_paths(self):
        """测试路径查找"""
        analyzer = SupplyChainReachability()
        
        analyzer.call_graph = {
            'start': {'a', 'b'},
            'a': {'c'},
            'b': {'c'},
            'c': {'target'}
        }
        
        paths = analyzer._find_paths('start', 'target', max_depth=5)
        
        assert isinstance(paths, list)
        assert len(paths) > 0
    
    def test_load_sbom(self):
        """测试SBOM加载"""
        analyzer = SupplyChainReachability()
        
        # 创建临时测试SBOM文件
        import json
        import tempfile
        import os
        
        sbom_data = {
            'binary_path': '/test/binary',
            'components': [
                {'name': 'openssl', 'version': '1.1.1', 'version_parts': (1, 1, 1), 'purl': ''}
            ],
            'vulnerabilities': {
                'openssl': [
                    {'cve_id': 'CVE-2023-0001', 'severity': 'HIGH', 'description': 'Test vulnerability'}
                ]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sbom_data, f)
            temp_path = f.name
        
        try:
            sbom = analyzer._load_sbom(temp_path)
            assert sbom is not None
        finally:
            os.unlink(temp_path)
    
    def test_metadata(self):
        """测试元数据获取"""
        metadata = SupplyChainReachability.get_metadata()
        
        assert metadata.name == "SupplyChainReachability"
        assert metadata.type.value == "vulnerability_detector"


class TestReachabilityStatus:
    """可达性状态测试类"""
    
    def test_status_values(self):
        """测试状态值"""
        assert ReachabilityStatus.REACHABLE.value == "reachable"
        assert ReachabilityStatus.UNREACHABLE.value == "unreachable"
        assert ReachabilityStatus.PARTIALLY_REACHABLE.value == "partially_reachable"
        assert ReachabilityStatus.UNKNOWN.value == "unknown"